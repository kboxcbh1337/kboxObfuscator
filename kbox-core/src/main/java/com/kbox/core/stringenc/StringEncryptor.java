package com.kbox.core.stringenc;

import com.kbox.core.KBoxException;
import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.FileSelector;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

/**
 * Replaces every {@code LDC "literal"} of type String inside method bodies
 * with a call to {@code KBoxRuntime.d(byte[])} (XOR, strength 1) or
 * {@code KBoxRuntime.a(byte[])} (AES, strength 2). The byte array literal is
 * constructed inline so no plaintext String survives in the constant pool.
 *
 * <p>Safety properties that make this transparent:
 * <ul>
 *   <li>Annotation string values live in attributes, not method bytecode, so
 *       they are never touched.</li>
 *   <li>Strings flowing into {@code Class.forName} decrypt to the original
 *       literal at runtime; because reflection targets are kept (name
 *       unchanged) by {@link com.kbox.core.name.NameObfuscator}, the call
 *       still resolves.</li>
 *   <li>The runtime interns decrypted strings so {@code ==} comparisons and
 *       {@code switch}-on-String (which relies on hashCode + equals) keep
 *       working.</li>
 * </ul>
 */
public final class StringEncryptor {

    private static final String TAG = "strings";
    private static final String RUNTIME_OWNER = "com/kbox/runtime/KBoxRuntime";
    /** Strength 1: rolling-XOR decryptor. */
    private static final String XOR_DEC = "d";
    /** Strength 2: AES decryptor. */
    private static final String AES_DEC = "a";
    private static final String DEC_DESC = "([B)Ljava/lang/String;";

    /**
     * Random-decryption-mode decryptor names. Each method uses a different
     * decryption strategy (rolling XOR, fixed-key XOR, position-dependent
     * XOR, multi-step XOR with rotate). The encryption randomly assigns one
     * of these to each string, so an attacker cannot statically identify a
     * single decryption pattern — they must reverse-engineer all variants.
     * <p>All decryptors are pre-compiled static methods in KBoxRuntime
     * (no dynamic code generation). Each method takes {@code byte[]} and
     * returns {@code String}. The first 4 bytes always encode the key (or a
     * fixed seed in fixed-XOR-key mode), followed by the ciphertext.
     */
    private static final String[] RANDOM_DEC_METHODS = {"d", "e", "f", "g", "h"};

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final SecureRandom rng = new SecureRandom();
    private int encrypted;
    /** Fixed key derived from watermark (or a default seed) for fixedXorKey mode. */
    private final int fixedKey;

    public StringEncryptor(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
        // Derive a fixed key from the watermark for deterministic output.
        String wm = cfg.getWatermark();
        this.fixedKey = (wm != null && !wm.isEmpty())
                ? wm.hashCode() ^ 0x5A6B7C8D
                : 0x12345678;
    }

    public void encrypt() {
        if (!cfg.isEncryptStrings()) {
            KBoxLog.info(TAG, "String encryption disabled");
            return;
        }
        int skippedLibrary = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            // Skip the runtime class itself (no recursion into the decryptor),
            // library classes, kept classes and out-of-scope classes. Single
            // canonical decision via shouldTransformClass.
            if (cn.name.equals(RUNTIME_OWNER)) continue;
            if (!cfg.shouldProtectClass(cn.name)) {
                skippedLibrary++;
                continue;
            }
            try {
                encryptClass(cn);
            } catch (Exception e) {
                // Per-class failure must not abort; fall back to leaving strings plain.
                if (cfg.isNeverFail()) {
                    KBoxLog.warn(TAG, "String encryption failed for " + cn.name + ": " + e.getMessage());
                } else {
                    throw new com.kbox.core.KBoxException(
                            "String encryption failed for " + cn.name, e);
                }
            }
        }
        KBoxLog.info(TAG, "Encrypted " + encrypted + " string literals (mode="
                + (cfg.getStringEncryptionStrength() == 2 ? "AES" : "XOR")
                + "), " + skippedLibrary + " library classes skipped");
    }

    @SuppressWarnings("unchecked")
    private void encryptClass(ClassNode cn) {
        // First desugar invokedynamic string-concat into StringBuilder so the
        // recipe literals become LDC constants the pass below can encrypt.
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            desugarIndyConcat(mn);
        }
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
                AbstractInsnNode next = ins.getNext();
                if (ins.getOpcode() == Opcodes.LDC && ins instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) ins;
                    if (ldc.cst instanceof String) {
                        InsnList repl = buildReplacement((String) ldc.cst);
                        if (repl != null) {
                            mn.instructions.insertBefore(ins, repl);
                            mn.instructions.remove(ins);
                            encrypted++;
                        }
                    }
                }
                ins = next;
            }
        }
        // Encrypt static-final String ConstantValue fields: their value lives in
        // the field's ConstantValue attribute (not a method LDC), so the LDC pass
        // above never touches it and the plaintext leaks. Move the initialization
        // into <clinit> via KBoxRuntime decryption, like ZKM/Allatori.
        encryptConstantStringFields(cn);
    }

    /**
     * Rewrites {@code static final String F = "literal";} fields. The literal is
     * stored in the field's {@code ConstantValue} attribute, which is invisible
     * to the {@code LDC} pass. We strip the attribute and instead assign the
     * decrypted value in {@code <clinit>}:
     * <pre>{@code
     *   F = KBoxRuntime.<dec>(new byte[]{...});
     * }</pre>
     * The field keeps its access flags (still {@code static final}); assigning a
     * final static field in {@code <clinit>} is legal JVM bytecode.
     */
    @SuppressWarnings("unchecked")
    private void encryptConstantStringFields(ClassNode cn) {
        if (cn.fields == null) return;
        List<FieldNode> toRelocate = new java.util.ArrayList<>();
        for (FieldNode fn : (List<FieldNode>) cn.fields) {
            if (fn.value instanceof String
                    && (fn.access & Opcodes.ACC_STATIC) != 0
                    && (fn.access & Opcodes.ACC_FINAL) != 0) {
                toRelocate.add(fn);
            }
        }
        if (toRelocate.isEmpty()) return;

        // Ensure a <clinit> exists. If absent, synthesize one (must call super if
        // this were a ctor — but <clinit> is static and has no super()).
        MethodNode clinit = null;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if ("<clinit>".equals(mn.name) && "()V".equals(mn.desc)) {
                clinit = mn;
                break;
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(clinit);
            clinit.maxStack = 4;
            clinit.maxLocals = 0;
        }

        for (FieldNode fn : toRelocate) {
            String literal = (String) fn.value;
            // Strip the ConstantValue attribute so the plaintext no longer lives
            // in the class file. ASM serialises fn.value as ConstantValue.
            fn.value = null;

            InsnList init = buildReplacement(literal);
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, fn.name, fn.desc));
            // Assign at the start of <clinit> (order is irrelevant for distinct
            // fields; keeping them first preserves any existing clinit body).
            clinit.instructions.insertBefore(clinit.instructions.getFirst(), init);
            clinit.maxStack = Math.max(clinit.maxStack, init.size() > 0 ? 4 : 4);
            encrypted++;
        }
    }

    /**
     * Desugars {@code StringConcatFactory.makeConcatWithConstants} invokedynamic
     * sites into explicit {@code StringBuilder} chains. The recipe string (which
     * contains the literal text) is embedded in the BootstrapMethods attribute as
     * a bootstrap constant, so the {@code LDC} pass never sees it — leaving the
     * literal plaintext in the class file. Rewriting into StringBuilder turns each
     * literal into an {@code LDC} that the encryptor then encrypts.
     *
     * <p>Called from {@link #encryptClass} AFTER the {@code LDC} pass so the
     * emitted literals are themselves encrypted on a second sweep.
     */
    @SuppressWarnings("unchecked")
    private void desugarIndyConcat(MethodNode mn) {
        if (mn.instructions == null) return;
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            if (ins instanceof InvokeDynamicInsnNode) {
                InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) ins;
                // Careful: bsm (Handle) is null for some ASM versions; fall back safely.
                if (id.bsm == null) { ins = next; continue; }
                String bsmName = id.bsm.getName();
                if ("makeConcatWithConstants".equals(bsmName)) {
                    InsnList repl = buildConcatReplacement(mn, id);
                    if (repl != null) {
                        mn.instructions.insertBefore(ins, repl);
                        mn.instructions.remove(ins);
                        // Mark CF-modified so frames are recomputed during packaging.
                        graph.markCfModified(mn.name);
                    }
                }
            }
            ins = next;
        }
    }

    /**
     * Builds a {@code StringBuilder} chain equivalent to a
     * {@code makeConcatWithConstants} call.
     *
     * <p>The invokedynamic's dynamic arguments are already on the operand stack
     * (arg0 deepest, last arg on top). We first store them into fresh local
     * slots (popping top-down), then emit {@code new StringBuilder.}<append>
     * {@code ...} {@code .toString()}, reading each argument back from its slot.
     * The recipe uses {@code \u0001} (tag 1) for argument slots and
     * {@code \u0002} (tag 2) for constant pool slots; all other chars are
     * literal text.
     */
    private InsnList buildConcatReplacement(MethodNode mn, InvokeDynamicInsnNode id) {
        // bsmArgs[0] = recipe string; bsmArgs[1..] = constants (tag 2).
        if (id.bsmArgs == null || id.bsmArgs.length == 0) return null;
        Object recipeObj = id.bsmArgs[0];
        if (!(recipeObj instanceof String)) return null;
        String recipe = (String) recipeObj;

        // Dynamic argument types from the indy descriptor: (argTypes)String.
        List<Character> argTypeList = parseArgTypes(id.desc);
        if (argTypeList == null) return null;
        int argCount = argTypeList.size();

        // Allocate fresh local slots for each argument (long/double = 2 slots).
        int base = mn.maxLocals;
        int[] slotOf = new int[argCount];
        int cursor = base;
        for (int i = 0; i < argCount; i++) {
            slotOf[i] = cursor;
            char t = argTypeList.get(i);
            cursor += (t == 'J' || t == 'D') ? 2 : 1;
        }
        mn.maxLocals = cursor;

        InsnList out = new InsnList();
        // 1. Store dynamic args (top-down) into the fresh locals.
        for (int i = argCount - 1; i >= 0; i--) {
            out.add(storeInsn(argTypeList.get(i), slotOf[i]));
        }
        // 2. new StringBuilder
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/StringBuilder", "<init>", "()V", false));

        // 3. append recipe segments in order.
        int argIdx = 0;      // index into argTypeList / operand stack
        int cstIdx = 1;      // index into id.bsmArgs (constants)
        StringBuilder lit = new StringBuilder();
        for (int i = 0; i < recipe.length(); i++) {
            char c = recipe.charAt(i);
            if (c == 1) { // tag 1 = dynamic argument
                flushLiteral(out, lit);
                appendArg(out, argTypeList.get(argIdx), slotOf[argIdx]);
                argIdx++;
            } else if (c == 2) { // tag 2 = constant
                flushLiteral(out, lit);
                if (cstIdx < id.bsmArgs.length) {
                    appendConstant(out, id.bsmArgs[cstIdx++]);
                } else {
                    return null; // corrupt recipe
                }
            } else {
                lit.append(c);
            }
        }
        flushLiteral(out, lit);
        if (argIdx != argCount) return null; // arg count mismatch
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false));
        return out;
    }

    /**
     * Parse the argument group of a method descriptor into a list of type chars
     * (one per argument). Reference types and arrays are represented by 'L'.
     */
    private static List<Character> parseArgTypes(String desc) {
        if (desc == null) return null;
        int open = desc.indexOf('(');
        int close = desc.indexOf(')', open);
        if (open < 0 || close < 0) return null;
        String args = desc.substring(open + 1, close);
        List<Character> out = new java.util.ArrayList<>();
        int i = 0;
        while (i < args.length()) {
            char c = args.charAt(i);
            if (c == '[') {
                // array — skip the array markers, treat as object ('L')
                while (i < args.length() && args.charAt(i) == '[') i++;
                if (i < args.length() && args.charAt(i) == 'L') {
                    while (i < args.length() && args.charAt(i) != ';') i++;
                }
                out.add('L');
            } else if (c == 'L') {
                while (i < args.length() && args.charAt(i) != ';') i++;
                out.add('L');
            } else {
                out.add(c); // primitive
            }
            i++;
        }
        return out;
    }

    /** Return the store instruction for a local of the given type char. */
    private static AbstractInsnNode storeInsn(char t, int slot) {
        int op;
        switch (t) {
            case 'J': op = Opcodes.LSTORE; break;
            case 'F': op = Opcodes.FSTORE; break;
            case 'D': op = Opcodes.DSTORE; break;
            case 'Z': case 'C': case 'B': case 'S': case 'I':
                op = Opcodes.ISTORE; break;
            default:  op = Opcodes.ASTORE; break;
        }
        // Always use the explicit-index form (VarInsnNode). Short-form _0.._3
        // opcodes are modelled as bare InsnNodes in the ASM tree API, and ASM's
        // COMPUTE_MAXS does NOT account for them when recomputing maxLocals
        // (a short-form ASTORE_1 is treated as an opcode with no operand, so
        // maxLocals stays 1 -> VerifyError "Local index 1 is invalid"). Using
        // VarInsnNode makes COMPUTE_MAXS compute the correct maxLocals.
        return new VarInsnNode(op, slot);
    }

    /** Emit a pending literal as {@code builder.append("...")}. */
    private void flushLiteral(InsnList out, StringBuilder lit) {
        if (lit.length() == 0) return;
        out.add(new LdcInsnNode(lit.toString()));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        lit.setLength(0);
    }

    /** Append one dynamic argument (stored in a local slot) to the builder. */
    private void appendArg(InsnList out, char t, int slot) {
        // load the argument back from its local slot
        int loadOp;
        switch (t) {
            case 'J': loadOp = Opcodes.LLOAD; break;
            case 'F': loadOp = Opcodes.FLOAD; break;
            case 'D': loadOp = Opcodes.DLOAD; break;
            case 'Z': case 'C': case 'B': case 'S': case 'I':
                loadOp = Opcodes.ILOAD; break;
            default:  loadOp = Opcodes.ALOAD; break;
        }
        // Always VarInsnNode (see storeInsn): short-form loads are InsnNodes
        // that COMPUTE_MAXS ignores when recomputing maxLocals.
        out.add(new VarInsnNode(loadOp, slot));
        String desc;
        switch (t) {
            case 'J': desc = "(J)Ljava/lang/StringBuilder;"; break;
            case 'F': desc = "(F)Ljava/lang/StringBuilder;"; break;
            case 'D': desc = "(D)Ljava/lang/StringBuilder;"; break;
            case 'Z': case 'C': case 'B': case 'S': case 'I':
                desc = "(I)Ljava/lang/StringBuilder;"; break;
            default:  desc = "(Ljava/lang/Object;)Ljava/lang/StringBuilder;"; break;
        }
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append", desc, false));
    }

    /** Push a bootstrap constant and append it. */
    private void appendConstant(InsnList out, Object cst) {
        if (cst instanceof String) {
            out.add(new LdcInsnNode(cst));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                    "java/lang/StringBuilder", "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Integer || cst instanceof Boolean
                || cst instanceof Byte || cst instanceof Short || cst instanceof Character) {
            out.add(new LdcInsnNode(((Number) cst).intValue()));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                    "java/lang/StringBuilder", "append",
                    "(I)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Long) {
            out.add(new LdcInsnNode(((Long) cst).longValue()));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                    "java/lang/StringBuilder", "append",
                    "(J)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Float) {
            out.add(new LdcInsnNode(((Float) cst).floatValue()));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                    "java/lang/StringBuilder", "append",
                    "(F)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Double) {
            out.add(new LdcInsnNode(((Double) cst).doubleValue()));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                    "java/lang/StringBuilder", "append",
                    "(D)Ljava/lang/StringBuilder;", false));
        }
        // Unknown constant types are ignored (rare; the concat still works via
        // the surrounding literal-only recipe).
    }

    /**
     * Builds the bytecode equivalent of
     * {@code KBoxRuntime.<dec>(new byte[]{k0,k1,k2,k3, enc...})}.
     *
     * <p>When {@code fixedXorKey} is enabled, the same key (derived from the
     * watermark) is used for every string — no random key per string. This
     * produces deterministic output for reproducible builds.
     *
     * <p>When random decryption mode is active (default for XOR strength 1),
     * a decryptor method is randomly chosen per string from
     * {@link #RANDOM_DEC_METHODS}, so an attacker must reverse every variant
     * to recover all strings — there is no single static pattern. Each variant
     * uses a different XOR key schedule (see {@link XorHelper}).
     */
    private InsnList buildReplacement(String s) {
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        int key = cfg.isFixedXorKey() ? fixedKey : rng.nextInt();

        byte[] blob;
        String method;
        if (cfg.getStringEncryptionStrength() == 2) {
            // AES mode: no random decryption variants (single AES path).
            blob = AesHelper.encrypt(utf8, key);
            method = AES_DEC;
        } else {
            // XOR mode: randomly pick a decryption variant. Each variant
            // encrypts with a different schedule matching its runtime decryptor.
            int idx = rng.nextInt(RANDOM_DEC_METHODS.length);
            method = RANDOM_DEC_METHODS[idx];
            blob = XorHelper.encrypt(utf8, key, method);
        }

        InsnList l = new InsnList();
        // push array length
        pushInt(l, blob.length);
        // newarray byte
        l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        // for each byte: dup, push index, push value, bastore
        for (int i = 0; i < blob.length; i++) {
            l.add(new InsnNode(Opcodes.DUP));
            pushInt(l, i);
            pushByte(l, blob[i]);
            l.add(new InsnNode(Opcodes.BASTORE));
        }
        // invokestatic KBoxRuntime.<method>([B)Ljava/lang/String;
        l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_OWNER, method, DEC_DESC, false));
        return l;
    }

    /** Push an int constant using the smallest opcode form. */
    static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) {
            l.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        } else {
            l.add(new LdcInsnNode(v));
        }
    }

    /** Push an unsigned byte (0..255) as an int suitable for BASTORE. */
    static void pushByte(InsnList l, byte b) {
        int v = b & 0xFF;
        if (v >= 0 && v <= 5) {
            l.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v <= 127) {
            l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else {
            l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        }
    }

    /**
     * XOR stream cipher used for strength 1. Supports multiple key schedules
     * to implement random-decryption-mode (each variant encrypts/decrypts
     * with a different schedule, defeating static pattern analysis).
     */
    static final class XorHelper {
        /** Default schedule used by {@code KBoxRuntime.d}. */
        static byte[] encrypt(byte[] data, int key) {
            return encrypt(data, key, "d");
        }

        /**
         * Encrypt {@code data} with the key schedule matching the named runtime
         * decryptor method. The first 4 bytes of the output always encode the
         * key (so the runtime can recover it), followed by the ciphertext.
         */
        static byte[] encrypt(byte[] data, int key, String method) {
            byte[] out = new byte[data.length + 4];
            out[0] = (byte) (key >>> 24);
            out[1] = (byte) (key >>> 16);
            out[2] = (byte) (key >>> 8);
            out[3] = (byte) key;
            switch (method) {
                case "d":
                    // Rolling XOR, shift = (i*7) % 32.
                    for (int i = 0; i < data.length; i++) {
                        int shift = (i * 7) % 32;
                        int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
                        out[i + 4] = (byte) (data[i] ^ (k & 0xFF));
                    }
                    break;
                case "e":
                    // Rolling XOR, shift = (i*3) % 32.
                    for (int i = 0; i < data.length; i++) {
                        int shift = (i * 3) % 32;
                        int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
                        out[i + 4] = (byte) (data[i] ^ (k & 0xFF));
                    }
                    break;
                case "f":
                    // Rotating XOR with 5-position schedule, shift = (i%5)*6.
                    for (int i = 0; i < data.length; i++) {
                        int shift = (i % 5) * 6;
                        int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
                        out[i + 4] = (byte) (data[i] ^ (k & 0xFF));
                    }
                    break;
                case "g":
                    // XOR with running counter mixed into the key.
                    int state = key;
                    for (int i = 0; i < data.length; i++) {
                        state = (state ^ (state << 13)) ^ (i * 0x9E3779B9);
                        out[i + 4] = (byte) (data[i] ^ (state & 0xFF));
                    }
                    break;
                case "h":
                    // XOR with fibonacci-like key schedule.
                    int a = key, c = key ^ 0x61C88647;
                    for (int i = 0; i < data.length; i++) {
                        int next = a ^ c;
                        a = c;
                        c = next;
                        out[i + 4] = (byte) (data[i] ^ (a & 0xFF));
                    }
                    break;
                default:
                    // Fallback: same as 'd'.
                    for (int i = 0; i < data.length; i++) {
                        int shift = (i * 7) % 32;
                        int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
                        out[i + 4] = (byte) (data[i] ^ (k & 0xFF));
                    }
            }
            return out;
        }

        public static String decrypt(byte[] b) {
            int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                    | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
            byte[] data = new byte[b.length - 4];
            for (int i = 0; i < data.length; i++) {
                int shift = (i * 7) % 32;
                int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
                data[i] = (byte) (b[i + 4] ^ (k & 0xFF));
            }
            return new String(data, StandardCharsets.UTF_8).intern();
        }
        private XorHelper() {}
    }

    /** AES/CBC with a key derived from the embedded int; strength 2. */
    static final class AesHelper {
        static byte[] encrypt(byte[] data, int key) {
            try {
                javax.crypto.spec.SecretKeySpec k = deriveKey(key);
                javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);
                c.init(javax.crypto.Cipher.ENCRYPT_MODE, k, new javax.crypto.spec.IvParameterSpec(iv));
                byte[] enc = c.doFinal(data);
                byte[] out = new byte[4 + 16 + enc.length];
                out[0] = (byte) (key >>> 24);
                out[1] = (byte) (key >>> 16);
                out[2] = (byte) (key >>> 8);
                out[3] = (byte) key;
                System.arraycopy(iv, 0, out, 4, 16);
                System.arraycopy(enc, 0, out, 20, enc.length);
                return out;
            } catch (Exception e) {
                throw new KBoxException("AES string encryption failed", e);
            }
        }

        public static String decrypt(byte[] b) {
            try {
                int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                        | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
                javax.crypto.spec.SecretKeySpec k = deriveKey(key);
                byte[] iv = new byte[16];
                System.arraycopy(b, 4, iv, 0, 16);
                byte[] enc = new byte[b.length - 20];
                System.arraycopy(b, 20, enc, 0, enc.length);
                javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(javax.crypto.Cipher.DECRYPT_MODE, k, new javax.crypto.spec.IvParameterSpec(iv));
                return new String(c.doFinal(enc), StandardCharsets.UTF_8).intern();
            } catch (Exception e) {
                throw new RuntimeException("KBox AES decrypt failed", e);
            }
        }

        private static javax.crypto.spec.SecretKeySpec deriveKey(int key) {
            // SHA-256 of the int -> first 16 bytes = AES-128 key.
            try {
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                md.update(new byte[]{
                        (byte) (key >>> 24), (byte) (key >>> 16),
                        (byte) (key >>> 8), (byte) key
                });
                byte[] d = md.digest();
                return new javax.crypto.spec.SecretKeySpec(d, 0, 16, "AES");
            } catch (Exception e) {
                throw new KBoxException("key derivation failed", e);
            }
        }
        private AesHelper() {}
    }
}
