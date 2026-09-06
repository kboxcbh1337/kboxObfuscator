package com.kbox.core.vmp;

import com.kbox.core.KBoxException;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;

/**
 * Rewrites a class so that each VMP-eligible method body is:
 * <ol>
 *   <li>Translated to a {@code byte[]} VMP program (via {@link VmpTranslator}).</li>
 *   <li>Stored in a synthetic {@code static byte[]} field named {@code $vmp_<n>}.
 *       plus a sibling {@code Object[]} field holding the constant-pool spec.</li>
 *   <li>The original method body is replaced with a stub that builds a
 *       {@link com.kbox.runtime.VmpInterpreter.VmpMethod} on first call (cached in a
 *       static {@code $vmpmethod_<n>} field), wraps primitive args in their
 *       boxed types, then calls {@code VmpInterpreter.execute(...)}.</li>
 * </ol>
 *
 * Methods that fail translation fall back to obfuscation (logged).
 */
public final class VmpMethodInjector {

    private static final String TAG = "vmp";
    private static final String INTERPRETER = "com/kbox/runtime/VmpInterpreter";
    private static final String INTERPRETER_METHOD = "com/kbox/runtime/VmpInterpreter$VmpMethod";
    private static final SecureRandom VMP_RNG = new SecureRandom();

    /** BrainfuckShield 强度（0=off）。>0 时每个 VMP 方法的密文流被重编码成磁带程序。 */
    private final int bfLevel;
    /** 每构建随机 buildSalt（与每方法 K 共同派生私有方言）。 */
    private final int bfBuildSalt;

    public VmpMethodInjector() {
        this(0, 0);
    }

    public VmpMethodInjector(int bfLevel, int bfBuildSalt) {
        this.bfLevel = Math.max(0, Math.min(3, bfLevel));
        this.bfBuildSalt = bfBuildSalt;
    }

    /**
     * Per-method opcode twin (double-state dispatch mask). Derived from the
     * method's 32-byte key K so both the build (masking) and the runtime
     * (VmpInterpreter dispatch) agree WITHOUT extra fields. Nonzero.
     */
    static int opcodeTwin(byte[] key) {
        int t = (key != null && key.length > 0) ? (key[0] & 0xFF) : 0;
        if (t == 0 && key != null && key.length > 1) t = key[key.length - 1] & 0xFF;
        return (t == 0) ? 0xB1 : t;
    }

    /**
     * Deterministic slot permutation derived from K. Both the build and the runtime
     * derive the SAME permutation (no field emitted). The constant-pool is stored
     * with {@code encCp[perm[i]] = encrypt(logical[i])}, so the VM's natural slot
     * index i maps to physical slot perm[i] — a static dump cannot tell which slot
     * holds which constant.
     */
    static int[] slotPerm(byte[] K, int n) {
        int[] p = new int[n];
        for (int i = 0; i < n; i++) p[i] = i;
        if (n <= 1) return p;
        long s = 0x6A09E667F3BCC909L;
        byte[] kb = (K == null) ? new byte[0] : K;
        for (byte b : kb) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
        for (int i = n - 1; i > 0; i--) {
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27; s *= 0x2545F4914F6CDD1DL;
            int j = (int) (Long.remainderUnsigned(s, i + 1L));
            int t = p[i]; p[i] = p[j]; p[j] = t;
        }
        return p;
    }

    /**
     * Deterministic per-method 256-entry opcode permutation derived from K. Maps
     * the REAL opcode to the STORED opcode: {@code stored = perm[real] ^ twin}.
     * The interpreter inverts it at dispatch time with {@code invPerm[stored ^ twin]}
     * (= {@code real}). Because K is randomly generated per method per build, every
     * KBox build gets a different virtual opcode mapping — no two builds share a
     * byte-identical VMP instruction stream. MUST match VmpInterpreter.opcodePerm.
     */
    static int[] opcodePerm(byte[] K) {
        int[] p = new int[256];
        for (int i = 0; i < 256; i++) p[i] = i;
        long s = 0x243F6A8885A308D3L;   // distinct domain constant from slotPerm
        byte[] kb = (K == null) ? new byte[0] : K;
        for (byte b : kb) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
        for (int i = 255; i > 0; i--) {
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27; s *= 0x2545F4914F6CDD1DL;
            int j = (int) (Long.remainderUnsigned(s, i + 1L));
            int t = p[i]; p[i] = p[j]; p[j] = t;
        }
        return p;
    }

    /**
     * Deterministic per-method 256-entry micro-operation permutation derived from
     * K. Independent domain from {@link #opcodePerm} (different seed constant).
     *
     * <p>The VMP interpreter's DISPATCH is data-driven: after the twin-mask
     * collapse the stored opcode byte is mapped straight to a micro-operation
     * slot {@code mo} in a per-method handler table via the composite permutation
     * ({@code microPerm ∘ invPerm}) — the real VmpOp is NEVER materialized in a
     * register, and every method/build lays its handler table out differently.
     * Because K is random per method per build, no two builds share a byte-identical
     * dispatch layout. MUST match VmpInterpreter.VmpMethod.microPerm.
     */
    static int[] microPerm(byte[] K) {
        int[] p = new int[256];
        for (int i = 0; i < 256; i++) p[i] = i;
        long s = 0xA4093822299F31D0L;   // distinct domain constant from slotPerm/opcodePerm
        byte[] kb = (K == null) ? new byte[0] : K;
        for (byte b : kb) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
        for (int i = 255; i > 0; i--) {
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27; s *= 0x2545F4914F6CDD1DL;
            int j = (int) (Long.remainderUnsigned(s, i + 1L));
            int t = p[i]; p[i] = p[j]; p[j] = t;
        }
        return p;
    }

    /** Inverse of a permutation array. */
    static int[] inversePerm(int[] perm) {
        int[] inv = new int[perm.length];
        for (int i = 0; i < perm.length; i++) inv[perm[i]] = i;
        return inv;
    }

    /**
     * Composite dispatch permutation: {@code composite[t] = microPerm[invPerm[t]]}.
     * At runtime {@code mo = composite[storedOpcode ^ twin]} yields the handler slot
     * without ever revealing the real VmpOp. The build logs its fingerprint for
     * cross-build ISA-polymorphism verification (see {@code kbox.vmp.permDump}).
     */
    static int[] compositePerm(int[] opcodePerm, int[] microPerm) {
        int[] inv = inversePerm(opcodePerm);
        int[] c = new int[256];
        for (int t = 0; t < 256; t++) c[t] = microPerm[inv[t]];
        return c;
    }

    /** FNV-1a 32-bit fingerprint of a permutation array (for permDump logging). */
    static String fnvHex(int[] a) {
        int h = 0x811c9dc5;
        for (int v : a) {
            h ^= (v & 0xFF); h *= 0x01000193;
            h ^= (v >>> 8) & 0xFF; h *= 0x01000193;
        }
        return String.format("%08x", h);
    }

    /*
     * VMP operand length (bytes after the opcode) for the interpreter's current
     * instruction set. MUST match VmpInterpreter's per-opcode pc advance. Used by
     * {@link #applyOpcodeMask} to locate every opcode byte so the per-method twin
     * can be XORed into them (delivering per-method opcode disorder).
     */
    static final int[] OP_LEN = new int[256];
    static {
        opLen(0x01, 0);              // ACONST_NULL
        opLen(0x02, 4); opLen(0x03, 8); opLen(0x04, 4); opLen(0x05, 8); // consts
        opLen(0x06, 4); opLen(0x07, 4);                                 // STRING/CLASS
        opLen(0x10, 2); opLen(0x11, 2); opLen(0x12, 2); opLen(0x13, 2); opLen(0x14, 2); // loads
        opLen(0x18, 2); opLen(0x19, 2); opLen(0x1A, 2); opLen(0x1B, 2); opLen(0x1C, 2); // stores
        for (int op = 0x2C; op <= 0x2C; op++) opLen(op, 6);             // IINC
        for (int op = 0x30; op <= 0x3F; op++) opLen(op, 4);             // IF*/GOTO (incl 0x3E)
        opLen(0x50, 4); opLen(0x51, 4); opLen(0x52, 4); opLen(0x53, 4); // GET/PUT STATIC/FIELD
        opLen(0x60, 4); opLen(0x61, 4); opLen(0x62, 4); opLen(0x63, 4); // invoke
        opLen(0x70, 4); opLen(0x71, 4); opLen(0x72, 4);                 // NEW/NEWARRAY/ANEWARRAY
        opLen(0x78, 4); opLen(0x79, 4);                                 // CHECKCAST/INSTANCEOF
        opLen(0xC9, 4);                                                 // IF_ACMPNE
    }
    private static void opLen(int op, int len) { OP_LEN[op] = len; }
    private static int operandLen(int op) { return (op >= 0 && op < 256) ? OP_LEN[op] : 0; }

    /**
     * Applies the per-method opcode permutation + twin mask to the program:
     * each opcode byte becomes {@code perm[real] ^ twin}. The interpreter recovers
     * the real opcode via its two-state dispatch {@code (st1 ^ st2) == twin}
     * followed by {@code invPerm[stored ^ twin]}. Only opcode bytes are touched;
     * operands are untouched. {@code perm} maps the ORIGINAL opcode to the stored
     * value; the walker uses the original opcode to advance, so the permutation
     * never perturbs the layout.
     */
    static void applyOpcodeMask(byte[] code, int[] perm, int twin) {
        int n = code.length;
        int pc = 0;
        while (pc < n) {
            int op = code[pc] & 0xFF;
            code[pc] = (byte) ((perm[op] ^ twin) & 0xFF);
            if (op == 0xFF) break; // END
            pc += 1 + operandLen(op);
        }
    }

    /** Encrypts a VMP program byte array with a random key. Returns encrypted bytes + wrapped key. */
    static class EncryptedProgram {
        final byte[] code;
        final Object[] cpRaw;
        final byte[] wrappedK;   // K wrapped (AES-GCM) under the hardware master — NEVER bare
        final int maxLocals;
        final int maxStack;
        final int argCount;
        final int retSort;
        final int[][] exceptions;
        EncryptedProgram(byte[] code, Object[] cpRaw, byte[] wrappedK,
                         int maxLocals, int maxStack, int argCount, int retSort, int[][] exceptions) {
            this.code = code; this.cpRaw = cpRaw; this.wrappedK = wrappedK;
            this.maxLocals = maxLocals; this.maxStack = maxStack;
            this.argCount = argCount; this.retSort = retSort; this.exceptions = exceptions;
        }
    }

    static EncryptedProgram encrypt(VmpTranslator.Result r) {
        return encrypt(r, 0, 0, "");
    }

    static EncryptedProgram encrypt(VmpTranslator.Result r, int bfLevel, int bfBuildSalt) {
        return encrypt(r, bfLevel, bfBuildSalt, "");
    }

    static EncryptedProgram encrypt(VmpTranslator.Result r, int bfLevel, int bfBuildSalt, String key) {
        // Per-method random 32-byte key K (stream seed, NOT stored bare).
        byte[] K = new byte[32];
        VMP_RNG.nextBytes(K);
        int twin = opcodeTwin(K);
        int[] perm = opcodePerm(K);
        int[] micro = microPerm(K);
        // Per-method opcode disorder: permute each opcode through a K-derived
        // bijection, then XOR with the twin. Because K is random per method per
        // build, no two builds share a byte-identical VMP instruction stream.
        byte[] pc2 = r.code.clone();
        applyOpcodeMask(pc2, perm, twin);
        // ISA-polymorphism fingerprint: the interpreter's data-driven dispatch layout
        // (micro-permutation composed over the twin-collapse) recorded here proves —
        // without decrypting classes.bf.rle — that the L2 ISA is re-keyed per method
        // per build. Log each method's invPerm/microPerm/composite digest so two builds
        // can be compared byte-for-byte.
        if (System.getProperty("kbox.vmp.permDump") != null) {
            int[] inv = inversePerm(perm);
            int[] comp = compositePerm(perm, micro);
            StringBuilder hex = new StringBuilder();
            for (byte b : K) hex.append(String.format("%02x", b & 0xFF));
            KBoxLog.info(TAG, "ISA permDump K=" + hex
                    + " twin=0x" + String.format("%02X", twin)
                    + " invPerm=" + fnvHex(inv)
                    + " microPerm=" + fnvHex(micro)
                    + " composite=" + fnvHex(comp));
        }
        // Encrypt bytecode with a ChaCha20 keystream derived from K (byte[] secret).
        com.kbox.runtime.ChaCha20.Keystream ks =
                new com.kbox.runtime.ChaCha20.Keystream(K);
        byte[] encCode = new byte[r.code.length];
        for (int i = 0; i < r.code.length; i++) {
            encCode[i] = (byte)((pc2[i] & 0xFF) ^ ks.at(i));
        }
        // BrainfuckShield（二次虚拟化）: 把 VMP 密文流重编码成每方法私有方言磁带程序。
        // 运行期 VmpMethod 构造时由 BfInterpreter.decodeIfTape 先回放解码回 encCode。
        if (bfLevel > 0) {
            byte[] rawEnc = encCode;
            encCode = com.kbox.core.brainfuckshield.BfMethodInjector.shield(
                    rawEnc, K, bfBuildSalt, bfLevel);
            if (System.getProperty("kbox.bf.verify") != null) {
                if (!com.kbox.core.brainfuckshield.BfMethodInjector.verifyRoundTrip(
                        rawEnc, K, bfBuildSalt, bfLevel)) {
                    throw new KBoxException("BrainfuckShield round-trip verify failed");
                }
            }
            if (System.getProperty("kbox.bf.dump") != null) {
                com.kbox.core.brainfuckshield.BfMethodInjector.log(
                        -1, rawEnc, encCode, key);
            }
        }
        // Encrypt CP strings (Object[] → XOR each String entry in the same stream)
        // and STORE them in PERMUTED physical order so the VM's logical slot i lives
        // at physical slot perm[i]. The keystream offset uses the PHYSICAL index so
        // the runtime (which also computes perm) recovers each slot exactly.
        int[] slotP = slotPerm(K, r.cpRaw.length);
        Object[] encCp = new Object[r.cpRaw.length];
        for (int i = 0; i < r.cpRaw.length; i++) {
            int phys = slotP[i];   // logical i placed at physical phys
            if (r.cpRaw[i] instanceof String) {
                String s = (String) r.cpRaw[i];
                byte[] sb = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] enc = new byte[sb.length];
                for (int j = 0; j < sb.length; j++) {
                    enc[j] = (byte)((sb[j] & 0xFF) ^ ks.at(j + r.code.length + phys * 256));
                }
                encCp[phys] = new String(enc, java.nio.charset.StandardCharsets.ISO_8859_1);
            } else {
                encCp[phys] = r.cpRaw[i];
            }
        }
        // Wrap K under the hardware-bound master so it is unusable off-device.
        byte[] wrappedK = com.kbox.runtime.HardwareKeyRing.aesGcmEncrypt(
                com.kbox.runtime.HardwareKeyRing.vmpMaster(), K);
        if (wrappedK == null) {
            // AES-GCM is universally available on the JVM; a null here is a hard
            // environment fault — fail cleanly so the build falls back.
            throw new KBoxException("Key wrapping failed (AES-GCM unavailable)");
        }
        return new EncryptedProgram(encCode, encCp, wrappedK, r.maxLocals, r.maxStack, r.argCount, r.retSort, r.exceptions);
    }

    public void rewrite(ClassNode cn, Map<String, VmpTranslator.Result> perMethod) {
        @SuppressWarnings("unchecked")
        java.util.List<MethodNode> snapshot = new java.util.ArrayList<>(cn.methods);
        int idx = 0;
        for (MethodNode mn : snapshot) {
            String key = cn.name + "#" + mn.name + "#" + mn.desc;
            VmpTranslator.Result r = perMethod.get(key);
            if (r == null) continue;
            // Hard invariant: never re-wrap a native/abstract method — a native
            // method carrying a Code attribute is rejected by the JVM at load time.
            if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) {
                perMethod.remove(key);
                continue;
            }
            try {
                // Encrypt the VMP program before storing in class fields.
                EncryptedProgram ep = encrypt(r, bfLevel, bfBuildSalt, key);
                inject(cn, mn, ep, idx);
                idx++;
            } catch (Exception e) {
                KBoxLog.warn(TAG, "VMP inject failed for " + key + ": " + e.getMessage()
                        + " (falling back to obfuscation)");
                perMethod.remove(key);
            }
        }
    }

    private void inject(ClassNode cn, MethodNode mn, EncryptedProgram ep, int idx) throws IOException {
        String fieldName = "$vmp_" + idx;
        String cpFieldName = "$vmpcp_" + idx;
        String methodFieldName = "$vmpm_" + idx;
        String keyFieldName = "$vmpkey_" + idx;
        cn.fields.add(field(cn, fieldName, "[B", true));
        cn.fields.add(field(cn, cpFieldName, "[Ljava/lang/Object;", true));
        cn.fields.add(field(cn, methodFieldName, "L" + INTERPRETER_METHOD + ";", true));
        // Store the WRAPPED key (K under AES-GCM hardware master) — never the bare key.
        cn.fields.add(field(cn, keyFieldName, "[B", true));

        // Add initialization code to <clinit>. The VmpMethod construction is
        // built into a scratch buffer and PREPENDED to the start of <clinit>
        // (NOT appended at the end): javac emits enum <clinit> that calls the
        // virtualized private $values() to build the $VALUES field, so every
        // $vmpm_* field must be initialized before ANY of the original
        // <clinit> body runs — otherwise $values() executes with a null
        // VmpMethod and the native interpreter crashes on GetIntField(NULL).
        MethodNode clinit = findOrCreateClinit(cn);
        MethodNode initBuf = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        emitByteArrayInit(initBuf, cn.name, fieldName, ep.code);
        emitObjectArrayInit(initBuf, cn.name, cpFieldName, ep.cpRaw);
        // Store the wrapped key in a byte[] field for runtime unwrapping.
        emitByteArrayInit(initBuf, cn.name, keyFieldName, ep.wrappedK);
        // Construct the VmpMethod object eagerly in <clinit> and cache it.
        // NEW + DUP create the uninitialized object reference that <init> consumes.
        initBuf.visitTypeInsn(Opcodes.NEW, INTERPRETER_METHOD);
        initBuf.visitInsn(Opcodes.DUP);
        initBuf.visitFieldInsn(Opcodes.GETSTATIC, cn.name, fieldName, "[B");
        initBuf.visitFieldInsn(Opcodes.GETSTATIC, cn.name, cpFieldName, "[Ljava/lang/Object;");
        initBuf.visitFieldInsn(Opcodes.GETSTATIC, cn.name, keyFieldName, "[B");
        pushInt(initBuf, ep.maxLocals);
        pushInt(initBuf, ep.maxStack);
        pushInt(initBuf, ep.argCount);
        pushInt(initBuf, ep.retSort);
        if (ep.exceptions == null) {
            initBuf.visitInsn(Opcodes.ACONST_NULL);
        } else {
            pushInt(initBuf, ep.exceptions.length);
            initBuf.visitTypeInsn(Opcodes.ANEWARRAY, "[I");
            for (int i = 0; i < ep.exceptions.length; i++) {
                initBuf.visitInsn(Opcodes.DUP);
                pushInt(initBuf, i);
                pushInt(initBuf, ep.exceptions[i].length);
                initBuf.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT);
                for (int j = 0; j < ep.exceptions[i].length; j++) {
                    initBuf.visitInsn(Opcodes.DUP);
                    pushInt(initBuf, j);
                    pushInt(initBuf, ep.exceptions[i][j]);
                    initBuf.visitInsn(Opcodes.IASTORE);
                }
                initBuf.visitInsn(Opcodes.AASTORE);
            }
        }
        initBuf.visitMethodInsn(Opcodes.INVOKESPECIAL, INTERPRETER_METHOD, "<init>",
                "([B[Ljava/lang/Object;[BIIII[[I)V", false);
        initBuf.visitFieldInsn(Opcodes.PUTSTATIC, cn.name, methodFieldName, "L" + INTERPRETER_METHOD + ";");
        clinit.instructions.insert(initBuf.instructions);
        // maxStack must cover: 5 args (byte[], Object[], 3 ints) + exceptions-array
        // construction which peaks at ~6 deeper, so 16 is a safe lower bound.
        clinit.maxStack = Math.max(clinit.maxStack, 16);

        // Replace the original method body with a thin stub.
        Type[] argTypes = Type.getArgumentTypes(mn.desc);
        Type retType = Type.getReturnType(mn.desc);
        boolean isStatic = (mn.access & Opcodes.ACC_STATIC) != 0;

        mn.instructions.clear();
        if (mn.tryCatchBlocks != null) mn.tryCatchBlocks.clear();
        mn.localVariables = null;

        // Load VmpMethod + receiver + args array.
        mn.visitFieldInsn(Opcodes.GETSTATIC, cn.name, methodFieldName, "L" + INTERPRETER_METHOD + ";");
        if (isStatic) {
            mn.visitInsn(Opcodes.ACONST_NULL);
        } else {
            mn.visitVarInsn(Opcodes.ALOAD, 0);
        }
        pushInt(mn, argTypes.length);
        mn.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        int localIdx = isStatic ? 0 : 1;
        for (int i = 0; i < argTypes.length; i++) {
            mn.visitInsn(Opcodes.DUP);
            pushInt(mn, i);
            loadAndBox(mn, argTypes[i], localIdx);
            localIdx += argTypes[i].getSize();
            mn.visitInsn(Opcodes.AASTORE);
        }
        mn.visitMethodInsn(Opcodes.INVOKESTATIC, INTERPRETER, "execute",
                "(L" + INTERPRETER_METHOD + ";Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        // Wrap the result in a try/catch for Throwable -> re-throw as the actual exception.
        // VmpInterpreter.execute returns Object; if it threw, the Throwable propagated.
        unboxReturn(mn, retType);
        mn.maxStack = 8 + argTypes.length;
        mn.maxLocals = Math.max(mn.maxLocals, localIdx + 2);
    }

    /** Finds the class's {@code <clinit>} or creates an empty one. */
    @SuppressWarnings("unchecked")
    private MethodNode findOrCreateClinit(ClassNode cn) {
        for (MethodNode m : (java.util.List<MethodNode>) cn.methods) {
            if (m.name.equals("<clinit>") && m.desc.equals("()V")) return m;
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
        clinit.maxStack = 1;
        clinit.maxLocals = 0;
        cn.methods.add(clinit);
        return clinit;
    }

    /** Emits code to initialize a {@code static byte[]} field with literal bytes. */
    private void emitByteArrayInit(MethodNode clinit, String owner, String fieldName, byte[] data) {
        pushInt(clinit, data.length);
        clinit.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        for (int i = 0; i < data.length; i++) {
            clinit.visitInsn(Opcodes.DUP);
            pushInt(clinit, i);
            int v = data[i] & 0xFF;
            if (v >= 0 && v <= 5) clinit.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_0 + v));
            else if (v <= 127) clinit.instructions.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, v));
            else clinit.instructions.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, v));
            clinit.visitInsn(Opcodes.BASTORE);
        }
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, owner, fieldName, "[B");
    }

    /** Emits code to initialize a {@code static Object[]} field of String literals. */
    private void emitObjectArrayInit(MethodNode clinit, String owner, String fieldName, Object[] items) {
        pushInt(clinit, items.length);
        clinit.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        for (int i = 0; i < items.length; i++) {
            clinit.visitInsn(Opcodes.DUP);
            pushInt(clinit, i);
            clinit.visitLdcInsn(items[i]);
            clinit.visitInsn(Opcodes.AASTORE);
        }
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, owner, fieldName, "[Ljava/lang/Object;");
    }

    private org.objectweb.asm.tree.FieldNode field(ClassNode cn, String name, String desc, boolean isStatic) {
        int acc = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC;
        return new org.objectweb.asm.tree.FieldNode(acc, name, desc, null, null);
    }

    private void pushInt(MethodNode mn, int v) {
        if (v >= -1 && v <= 5) mn.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE)
            mn.instructions.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, v));
        else mn.instructions.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, v));
    }

    private void loadAndBox(MethodNode mn, Type t, int localIdx) {
        switch (t.getSort()) {
            case Type.BOOLEAN: mn.visitVarInsn(Opcodes.ILOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false); break;
            case Type.BYTE: mn.visitVarInsn(Opcodes.ILOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false); break;
            case Type.CHAR: mn.visitVarInsn(Opcodes.ILOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false); break;
            case Type.SHORT: mn.visitVarInsn(Opcodes.ILOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false); break;
            case Type.INT: mn.visitVarInsn(Opcodes.ILOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false); break;
            case Type.LONG: mn.visitVarInsn(Opcodes.LLOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false); break;
            case Type.FLOAT: mn.visitVarInsn(Opcodes.FLOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false); break;
            case Type.DOUBLE: mn.visitVarInsn(Opcodes.DLOAD, localIdx);
                mn.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false); break;
            default: mn.visitVarInsn(Opcodes.ALOAD, localIdx);
        }
    }

    private void unboxReturn(MethodNode mn, Type t) {
        switch (t.getSort()) {
            case Type.VOID: mn.visitInsn(Opcodes.POP); mn.visitInsn(Opcodes.RETURN); break;
            case Type.BOOLEAN:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Boolean");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false);
                mn.visitInsn(Opcodes.IRETURN); break;
            case Type.BYTE:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Byte");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Byte", "byteValue", "()B", false);
                mn.visitInsn(Opcodes.IRETURN); break;
            case Type.CHAR:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Character");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false);
                mn.visitInsn(Opcodes.IRETURN); break;
            case Type.SHORT:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Short");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Short", "shortValue", "()S", false);
                mn.visitInsn(Opcodes.IRETURN); break;
            case Type.INT:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Integer");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false);
                mn.visitInsn(Opcodes.IRETURN); break;
            case Type.LONG:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Long");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false);
                mn.visitInsn(Opcodes.LRETURN); break;
            case Type.FLOAT:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Float");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false);
                mn.visitInsn(Opcodes.FRETURN); break;
            case Type.DOUBLE:
                mn.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Double");
                mn.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false);
                mn.visitInsn(Opcodes.DRETURN); break;
            default:
                mn.visitTypeInsn(Opcodes.CHECKCAST, t.getInternalName());
                mn.visitInsn(Opcodes.ARETURN);
        }
    }

    /** Serializes a {@link VmpTranslator.Result} into {@code byte[]} for the field initializer. */
    public static byte[] serializeProgram(VmpTranslator.Result r) {
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            DataOutputStream d = new DataOutputStream(bo);
            d.write(r.code);
            d.flush();
            return bo.toByteArray();
        } catch (IOException e) {
            throw new KBoxException("VMP serialize failed", e);
        }
    }

    /** Serializes the constant-pool spec as Object[]: members are all Strings. */
    public static Object[] serializeCp(VmpTranslator.Result r) {
        return r.cpRaw;
    }
}
