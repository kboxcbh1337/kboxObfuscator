package com.kbox.core.stringenc;

import com.kbox.core.KBoxException;
import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import com.kbox.runtime.KbnlKey;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * AES-256-CTR string encryption. Replaces the weaker XOR-based encryptors with
 * a proper authenticated stream cipher.
 *
 * <p>Each string literal is encrypted with AES-256-CTR under a per-build key
 * derived from a random 256-byte permutation table {@code T}: the AES key is
 * {@code SHA-256(T)} (32 bytes &rarr; AES-256). The table is embedded in a
 * synthetic runtime holder; the key is recomputed in that class's
 * {@code <clinit>} so the key never appears as a plain constant in the output.
 *
 * <p>Encryption scheme (per string {@code s}):
 * <pre>
 *   key  = SHA-256(T)           // 32-byte AES-256 key
 *   iv   = random 12 bytes      // unique nonce per string
 *   ct   = AES-256-CTR(key, iv, UTF-8 bytes of s)
 *   enc  = iv || ct             // 12-byte nonce prepended to ciphertext
 * </pre>
 * Decryption at runtime extracts the 12-byte IV, re-derives the key from
 * {@code T}, and runs AES-256-CTR in decrypt mode.
 *
 * <p><b>Anti-tamper linkage.</b> When {@code AntiDebug.isTampered()} is true
 * the decryptor returns deterministic garbage (the leading bytes of the
 * ciphertext decoded as UTF-8) instead of the real plaintext, so a debugger
 * sees mojibake rather than a clean failure.
 *
 * <p><b>Lazy cache.</b> Every encrypted string is assigned an integer id. The
 * holder keeps a {@code String[] _cache} array sized to the total string
 * count (known after a pre-scan). The decryptor checks {@code _cache[id]}
 * first, so each string is decrypted at most once. The call site becomes:
 * <pre>
 *   pushByteArray(enc); pushInt(id);
 *   INVOKESTATIC holder.&lt;dec&gt;([BI)Ljava/lang/String;
 * </pre>
 *
 * <p><b>Multiple decryptor variants.</b> 2-3 decryptor methods with randomized
 * names are emitted; one is chosen at random per site, so there is no single
 * stable decryption symbol to grep or mock. A fresh table + IVs are generated
 * per build, so ciphertext changes between runs.
 *
 * <p><b>Full coverage.</b> Every {@code LDC "literal"} of type String in every
 * method (exception messages, log strings, paths, etc.) is replaced, and
 * {@code static final String} fields whose value lives in the
 * {@code ConstantValue} attribute are relocated into {@code <clinit>} via
 * decryption, so no plaintext survives in the class file.
 */
public final class AesStringEncryptor {

    private static final String TAG = "aes-strings";
    /** Decryptor signature: (byte[] enc, int id) -> String. */
    private static final String DEC_DESC = "([BI)Ljava/lang/String;";
    private static final String ANTIDEBUG_OWNER = "com/kbox/runtime/AntiDebug";
    private static final String CIPHER_SPEC = "AES/CTR/NoPadding";
    private static final String KEY_ALGO = "AES";
    private static final String DIGEST_ALGO = "SHA-256";
    /** Length of the per-string IV (nonce) prepended to the ciphertext.
     *  AES/CTR requires the IV to equal the AES block size (16 bytes). */
    private static final int IV_LEN = 16;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    /** Per-thread SecureRandom for thread-safe IV generation in parallel mode. */
    private final ThreadLocal<SecureRandom> rng = ThreadLocal.withInitial(SecureRandom::new);

    /** 256-byte permutation table T embedded in the holder (the "key material"). */
    private byte[] table;
    /** Build-time AES-256 key = SHA-256(T); identical to the runtime derivation. */
    private SecretKeySpec buildKey;
    /** Internal name of the synthetic holder class. */
    private String holder;
    /** Randomized decryptor method names (2..3 variants). */
    private String[] decMethods;
    /** Upper bound on the number of encrypted strings (sizes {@code _cache}). */
    private int cacheSize;
    /** Global per-string id counter; assigned in parallel, so atomic. */
    private final AtomicInteger nextId = new AtomicInteger();
    private final AtomicInteger encrypted = new AtomicInteger();

    // ---- S7: 字符串密钥 KBNL 会话绑定 ----
    // 现状：256 字节表 T 以 static final byte[] 明文落 holder 的 <clinit>，
    // 反编译器/静态扫描可直接读出密钥材料。
    // 修复：构建期用 KbnlKey.derive(D, S)（硬件指纹绑定的确定性派生，与 KBNL
    // blob 密钥同源、同机部署模型）把 T 盲化为 T'(i)=T(i)^K(i mod 32) 落 holder；
    // 运行期 holder <clinit> 先 derive(D,S) 重建 K，再 XOR 还原 T。静态拿到 holder
    // 只看到盲化字节和常数，无法不经 KbnlKey 直接恢复密钥。
    //
    // 硬约束遵守：不混入 sessionEpoch/perRun 因子（那些只进 ephemeralKey），
    // derive() 是确定性稳定键（build↔run 同机一致）；一处独立 domain tag 只
    // 消耗 A8 K_USE_CAP(16) 中的 1 次，合法进程不越线。
    /** Dedicated KbnlKey domain tag for the string-key material (gorge from blobs). */
    private int strDomainTag;
    /** Random 16-byte salt bound with the string-key domain tag. */
    private byte[] strSalt;

    public AesStringEncryptor(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /**
     * Generates the holder class, then encrypts every string literal in every
     * eligible class in parallel. The holder is added to the graph before the
     * parallel pass; it is never itself encrypted because
     * {@code shouldProtectClass} returns {@code false} for any
     * {@code com/kbox/runtime/} class (see {@code LibraryClassifier}).
     */
    public void apply() {
        holder = "com/kbox/runtime/_" + randomName(14);
        int variants = 2 + rng.get().nextInt(2);   // 2..3 variants per build
        decMethods = new String[variants];
        for (int i = 0; i < variants; i++) decMethods[i] = "z" + randomName(9);
        table = randomPermutation();
        // S7: allocate a dedicated KBNL domain tag + salt for the string-key
        // material, so the holder blinds T behind KbnlKey.derive(D,S) instead of
        // embedding the 256-byte table in plaintext.
        strDomainTag = KbnlKey.newDomainTag();
        strSalt = new byte[16];
        rng.get().nextBytes(strSalt);
        // Derive the build-time AES key = SHA-256(T); matches the holder <clinit>.
        buildKey = new SecretKeySpec(sha256(table), KEY_ALGO);
        // Pre-scan to size the per-string cache (upper bound: empty strings are
        // counted but skipped at encryption time, so the array is always large
        // enough and no ArrayIndexOutOfBoundsException can occur).
        cacheSize = countStrings();
        if (cacheSize == 0) {
            KBoxLog.info(TAG, "No strings to encrypt");
            return;
        }
        ensureHolder();
        nextId.set(0);
        encrypted.set(0);
        // Parallel per-class encryption (no shared mutable state between classes
        // other than the atomic id counter, which is safe).
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, this::encryptClass,
                cfg.getParallelThreads());
        KBoxLog.info(TAG, "AES-256-CTR encrypted " + encrypted.get() + " strings ("
                + cacheSize + " cache slots, " + variants + " decryptors, holder=" + holder + ")");
    }

    // ------------------------------------------------------------------
    //  Pre-scan: count candidate strings to size _cache (upper bound).
    // ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private int countStrings() {
        int total = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
                    if (ins.getOpcode() == Opcodes.LDC && ins instanceof LdcInsnNode) {
                        if (((LdcInsnNode) ins).cst instanceof String) total++;
                    } else if (isStringConcatIndy(ins)) {
                        // StringConcat literal fragments must be counted so the
                        // shared _cache is sized for the ids they consume.
                        total += countConcatFragments((InvokeDynamicInsnNode) ins);
                    }
                }
            }
            // Count static-final String ConstantValue fields too.
            if (cn.fields != null) {
                for (FieldNode fn : (List<FieldNode>) cn.fields) {
                    if (fn.value instanceof String
                            && (fn.access & Opcodes.ACC_STATIC) != 0
                            && (fn.access & Opcodes.ACC_FINAL) != 0) {
                        total++;
                    }
                }
            }
        }
        return total;
    }

    // ------------------------------------------------------------------
    //  Per-class encryption (called in parallel).
    // ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private void encryptClass(ClassNode cn) {
        // 1. Replace every LDC "..." with: pushByteArray(enc) + pushInt(id) + dec.
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
                AbstractInsnNode next = ins.getNext();
                if (ins.getOpcode() == Opcodes.LDC && ins instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) ins;
                    if (ldc.cst instanceof String) {
                        String s = (String) ldc.cst;
                        if (s.isEmpty()) { ins = next; continue; }   // skip empty
                        try {
                            int id = nextId.getAndIncrement();
                            String decName = decMethods[rng.get().nextInt(decMethods.length)];
                            byte[] enc = encrypt(s);
                            InsnList repl = new InsnList();
                            pushByteArray(repl, enc);
                            pushInt(repl, id);
                            repl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holder, decName, DEC_DESC, false));
                            mn.instructions.insertBefore(ins, repl);
                            mn.instructions.remove(ins);
                            encrypted.incrementAndGet();
                        } catch (Exception e) {
                            KBoxLog.warn(TAG, "Failed to encrypt string in " + cn.name + "." + mn.name + ": " + e.getMessage()
                                    + (e.getCause() != null ? " cause=" + e.getCause().getMessage() : ""));
                        }
                    }
                } else if (isStringConcatIndy(ins)) {
                    // Rewrite javac 9+ invokedynamic StringConcat so every literal
                    // fragment is AES-encrypted (closes the coverage gap that LDC
                    // rewriting cannot reach). Non-safe forms are left untouched.
                    try {
                        rewriteConcat(mn, (InvokeDynamicInsnNode) ins);
                    } catch (Exception e) {
                        KBoxLog.warn(TAG, "StringConcat rewrite skipped in " + cn.name + "." + mn.name + ": " + e.getMessage());
                    }
                }
                ins = next;
            }
        }
        // 2. Relocate static-final String ConstantValue fields into <clinit>.
        encryptConstantStringFields(cn);
    }

    /**
     * Rewrites {@code static final String F = "literal";} fields. The literal
     * lives in the field's {@code ConstantValue} attribute, which is invisible
     * to the {@code LDC} pass and leaks plaintext. We strip the attribute and
     * instead assign the decrypted value in {@code <clinit>}. Assigning a final
     * static field in {@code <clinit>} is legal JVM bytecode.
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

        // Ensure a <clinit> exists.
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
            // in the class file (ASM serialises fn.value as ConstantValue).
            fn.value = null;
            int id = nextId.getAndIncrement();
            String decName = decMethods[rng.get().nextInt(decMethods.length)];
            byte[] enc = encrypt(literal);
            InsnList init = new InsnList();
            pushByteArray(init, enc);
            pushInt(init, id);
            init.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holder, decName, DEC_DESC, false));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, fn.name, fn.desc));
            // Assign at the start of <clinit> (order is irrelevant for distinct
            // fields; keeping them first preserves any existing clinit body).
            clinit.instructions.insertBefore(clinit.instructions.getFirst(), init);
            clinit.maxStack = Math.max(clinit.maxStack, 4);
            encrypted.incrementAndGet();
        }
    }

    // ------------------------------------------------------------------
    //  invokedynamic StringConcat (javac 9+) rewrite -> encrypted StringBuilder.
    //  Closes the coverage gap: the recipe's literal fragments live in the
    //  constant pool as CONSTANT_String reachable only via the bootstrap
    //  method, never via LDC, so the plain LDC pass cannot touch them.
    //  We rewrite the call site into an explicit StringBuilder chain in which
    //  every literal fragment is decrypted through the same AES decryptor and
    //  every argument is appended with exact StringConcat semantics.
    // ------------------------------------------------------------------

    private static final String BS_OWNER = "java/lang/invoke/StringConcatFactory";

    private static boolean isStringConcatIndy(AbstractInsnNode ins) {
        if (!(ins instanceof InvokeDynamicInsnNode)) return false;
        Handle h = ((InvokeDynamicInsnNode) ins).bsm;
        if (h == null || !BS_OWNER.equals(h.getOwner())) return false;
        String n = h.getName();
        return "makeConcat".equals(n) || "makeConcatWithConstants".equals(n);
    }

    /** Returns {@code {List<Object[]> parts, Type[] argTypes}}, or null when unsafe.
     *  parts: each Object[]{0, String literal} or Object[]{1, Integer argIndex}. */
    private static Object[] parseConcat(InvokeDynamicInsnNode indy) {
        Type[] at = Type.getArgumentTypes(indy.desc);
        int argc = at.length;
        java.util.List<Object[]> parts = new java.util.ArrayList<>();
        if ("makeConcatWithConstants".equals(indy.bsm.getName())) {
            // Only the common form is supported: recipe + NO trailing constants,
            // tags all == 0x01 (consumed in argument order), tag count == argc.
            if (indy.bsmArgs == null || indy.bsmArgs.length != 1) return null;
            if (!(indy.bsmArgs[0] instanceof String)) return null;
            String recipe = (String) indy.bsmArgs[0];
            StringBuilder lit = new StringBuilder();
            int argIdx = 0;
            for (int i = 0; i < recipe.length(); i++) {
                char c = recipe.charAt(i);
                if (c >= 1 && c <= 0x10) {
                    if (c != 0x01) return null;          // only \u0001 form supported
                    if (lit.length() > 0) { parts.add(new Object[]{0, lit.toString()}); lit.setLength(0); }
                    if (argIdx >= argc) return null;
                    parts.add(new Object[]{1, argIdx++});
                } else {
                    lit.append(c);
                }
            }
            if (lit.length() > 0) parts.add(new Object[]{0, lit.toString()});
            if (argIdx != argc) return null;
        } else {
            // makeConcat: no recipe; ingredients are all method args in order.
            for (int i = 0; i < argc; i++) parts.add(new Object[]{1, i});
        }
        return new Object[]{parts, at};
    }

    @SuppressWarnings("unchecked")
    private static int countConcatFragments(InvokeDynamicInsnNode indy) {
        Object[] parsed = parseConcat(indy);
        if (parsed == null) return 0;
        int n = 0;
        for (Object[] part : (java.util.List<Object[]>) parsed[0]) {
            if ((Integer) part[0] == 0 && ((String) part[1]).length() > 0) n++;
        }
        return n;
    }

    /** Rewrites a StringConcat indy into an encrypted StringBuilder sequence.
     *  Returns true when rewritten; false (or throws) when left untouched. */
    @SuppressWarnings("unchecked")
    private boolean rewriteConcat(MethodNode mn, InvokeDynamicInsnNode indy) {
        Object[] parsed = parseConcat(indy);
        if (parsed == null) return false;
        java.util.List<Object[]> parts = (java.util.List<Object[]>) parsed[0];
        Type[] at = (Type[]) parsed[1];
        int argc = at.length;

        // Allocate fresh locals for the method args and the StringBuilder.
        int slot = mn.maxLocals;
        int[] argSlot = new int[argc];
        for (int i = 0; i < argc; i++) { argSlot[i] = slot; slot += at[i].getSize(); }
        int sbSlot = slot++;
        mn.maxLocals = Math.max(mn.maxLocals, slot);

        // Pop the args into fresh locals (top of stack is the LAST arg).
        InsnList pre = new InsnList();
        for (int i = argc - 1; i >= 0; i--) store(pre, at[i], argSlot[i]);
        mn.instructions.insertBefore(indy, pre);

        // Builder sequence (replaces the indy).
        InsnList b = new InsnList();
        b.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        b.add(new InsnNode(Opcodes.DUP));
        b.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
        b.add(new VarInsnNode(Opcodes.ASTORE, sbSlot));

        for (Object[] part : parts) {
            if ((Integer) part[0] == 0) {
                String plain = (String) part[1];
                if (plain.isEmpty()) continue;
                // sb.append(dec(enc, id))
                String decName = decMethods[rng.get().nextInt(decMethods.length)];
                byte[] enc = encrypt(plain);
                int id = nextId.getAndIncrement();
                InsnList seg = new InsnList();
                pushByteArray(seg, enc);
                pushInt(seg, id);
                seg.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holder, decName, DEC_DESC, false));
                seg.add(new VarInsnNode(Opcodes.ALOAD, sbSlot));
                seg.add(new InsnNode(Opcodes.SWAP));   // String -> underneath, sb on top? see below
                // We used ALOAD sb AFTER pushing String; correct order for
                // StringBuilder.append(String): [sb, String].
                seg.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
                seg.add(new InsnNode(Opcodes.POP));
                b.add(seg);
                encrypted.incrementAndGet();
            } else {
                int ai = (Integer) part[1];
                emitAppendArg(b, sbSlot, at[ai], argSlot[ai]);
            }
        }
        b.add(new VarInsnNode(Opcodes.ALOAD, sbSlot));
        b.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false));
        mn.instructions.insertBefore(indy, b);
        mn.instructions.remove(indy);
        mn.maxStack = Math.max(mn.maxStack, 12);
        return true;
    }

    /** Appends one method argument to the StringBuilder with StringConcat semantics. */
    private void emitAppendArg(InsnList b, int sbSlot, Type t, int local) {
        b.add(new VarInsnNode(Opcodes.ALOAD, sbSlot));
        switch (t.getSort()) {
            case Type.BOOLEAN:
                b.add(new VarInsnNode(Opcodes.ILOAD, local));
                b.add(append("(Z)")); break;
            case Type.CHAR:
                b.add(new VarInsnNode(Opcodes.ILOAD, local));
                b.add(append("(C)")); break;
            case Type.INT: case Type.BYTE: case Type.SHORT:
                b.add(new VarInsnNode(Opcodes.ILOAD, local));
                b.add(append("(I)")); break;
            case Type.LONG:
                b.add(new VarInsnNode(Opcodes.LLOAD, local));
                b.add(append("(J)")); break;
            case Type.FLOAT:
                b.add(new VarInsnNode(Opcodes.FLOAD, local));
                b.add(append("(F)")); break;
            case Type.DOUBLE:
                b.add(new VarInsnNode(Opcodes.DLOAD, local));
                b.add(append("(D)")); break;
            default: {
                // Reference/array (incl char[]): javac's StringConcatFactory
                // stringifies via String.valueOf(Object) -> null => "null",
                // char[]/arrays => identity toString. Match exactly; never use
                // append(char[]) or valueOf(char[]).
                b.add(new VarInsnNode(Opcodes.ALOAD, local));
                b.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/String", "valueOf",
                        "(Ljava/lang/Object;)Ljava/lang/String;", false));
                b.add(append("(Ljava/lang/String;)"));
                break;
            }
        }
        b.add(new InsnNode(Opcodes.POP));
    }

    /** StringBuilder.append(desc) instruction (returns StringBuilder; caller POPs).
     *  param is a full descriptor like "(Z)", "(I)" or "(Ljava/lang/String;)". */
    private static MethodInsnNode append(String desc) {
        String params = desc.substring(1, desc.length() - 1);
        return new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                "(" + params + ")Ljava/lang/StringBuilder;", false);
    }

    private static void store(InsnList l, Type t, int local) {
        switch (t.getSort()) {
            case Type.LONG: l.add(new VarInsnNode(Opcodes.LSTORE, local)); break;
            case Type.FLOAT: l.add(new VarInsnNode(Opcodes.FSTORE, local)); break;
            case Type.DOUBLE: l.add(new VarInsnNode(Opcodes.DSTORE, local)); break;
            case Type.INT: case Type.BOOLEAN: case Type.CHAR: case Type.BYTE: case Type.SHORT:
                l.add(new VarInsnNode(Opcodes.ISTORE, local)); break;
            default: l.add(new VarInsnNode(Opcodes.ASTORE, local)); break;
        }
    }

    // ------------------------------------------------------------------
    //  Build-time AES-256-CTR encryption.
    // ------------------------------------------------------------------

    /** enc = IV(12) || AES-256-CTR(key, IV, UTF-8 bytes of s). */
    private byte[] encrypt(String s) {
        try {
            byte[] iv = new byte[IV_LEN];
            rng.get().nextBytes(iv);
            Cipher c = Cipher.getInstance(CIPHER_SPEC);
            c.init(Cipher.ENCRYPT_MODE, buildKey, new IvParameterSpec(iv));
            byte[] ct = c.doFinal(s.getBytes(StandardCharsets.UTF_8));
            byte[] enc = new byte[IV_LEN + ct.length];
            System.arraycopy(iv, 0, enc, 0, IV_LEN);
            System.arraycopy(ct, 0, enc, IV_LEN, ct.length);
            return enc;
        } catch (Exception e) {
            throw new KBoxException("AES-CTR string encryption failed", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(DIGEST_ALGO);
            return md.digest(data);
        } catch (Exception e) {
            throw new KBoxException("SHA-256 key derivation failed", e);
        }
    }

    // ------------------------------------------------------------------
    //  Holder class generation.
    // ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private void ensureHolder() {
        if (graph.getClasses().containsKey(holder)) return;
        // S7 fix: derive the build-side blinding key ONCE here. The holder's
        // <clinit> re-derives the SAME KbnlKey.derive(D,S) at run time and XORs
        // it back out, so the embedded table must be ALREADY blinded
        // (T'(i)=table[i]^K[i%32]). Writing the raw table here and XOR-ing at
        // <clinit> would yield table^K at run time — never equal to the build
        // key SHA-256(table) — and every decrypted string would be garbage.
        byte[] kbuild = KbnlKey.derive(strDomainTag, strSalt);
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = holder;
        cn.superName = "java/lang/Object";

        // --- trivial <init> ---
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);

        // --- fields ---
        // static final byte[] T  — 256-byte permutation, BLINDED by KbnlKey.derive(D,S)
        //   (T'(i)=T(i)^K(i%32)). Not recoverable statically without KbnlKey.
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "T", "[B", null, null));
        // S7 domain tag + salt for KbnlKey.derive(,) unblinding.
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "D", "I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "S", "[B", null, null));
        // static SecretKeySpec _key — derived in <clinit>.
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_key", "Ljavax/crypto/spec/SecretKeySpec;", null, null));
        // static volatile boolean _init — set true once <clinit> completes.
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE,
                "_init", "Z", null, null));
        // static WeakReference<String>[] _cache — per-string-id lazy decrypt cache.
        // Weak references + in-decryptor plaintext wipe (L6): a decrypted string is
        // only weakly held, so it does NOT reside strongly in memory once the caller
        // drops it; the GC reclaims it, and the intermediate plaintext byte[] is
        // zeroed before returning. No full plaintext set persists.
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_cache", "[Ljava/lang/ref/WeakReference;", null, null));

        // --- <clinit>: D=tag; S=salt; K=KbnlKey.derive(D,S); T(i)=T'(i)^K(i%32);
        //               derive _key=SecretKeySpec(SHA-256(T)); alloc _cache ---
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList cl = clinit.instructions;
        // D = strDomainTag
        pushInt(cl, strDomainTag);
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "D", "I"));
        // S = strSalt
        pushInt(cl, strSalt.length);
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < strSalt.length; i++) {
            cl.add(new InsnNode(Opcodes.DUP));
            pushInt(cl, i);
            pushByte(cl, strSalt[i]);
            cl.add(new InsnNode(Opcodes.BASTORE));
        }
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "S", "[B"));
        // K = KbnlKey.derive(D, S)   -> local0 (byte[32], deterministic hardware-bound)
        cl.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "D", "I"));
        cl.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "S", "[B"));
        cl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "com/kbox/runtime/KbnlKey",
                "derive", "(I[B)[B", false));
        cl.add(new VarInsnNode(Opcodes.ASTORE, 0));
        // T = new byte[256]; T[i] = table[i] ^ K[i % 32]   (data already blinded)
        pushInt(cl, 256);
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < 256; i++) {
            cl.add(new InsnNode(Opcodes.DUP));
            pushInt(cl, i);
            pushByte(cl, (byte) (table[i] ^ kbuild[i % 32]));   // blinded at build time
            // K[i % 32]
            cl.add(new VarInsnNode(Opcodes.ALOAD, 0));
            pushInt(cl, i % 32);
            cl.add(new InsnNode(Opcodes.BALOAD));
            cl.add(new InsnNode(Opcodes.IXOR));
            cl.add(new InsnNode(Opcodes.BASTORE));
        }
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "T", "[B"));
        // digest = MessageDigest.getInstance("SHA-256").digest(T)
        cl.add(new LdcInsnNode(DIGEST_ALGO));
        cl.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/security/MessageDigest", "getInstance",
                "(Ljava/lang/String;)Ljava/security/MessageDigest;", false));
        cl.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "T", "[B"));
        cl.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/security/MessageDigest", "digest", "([B)[B", false));
        cl.add(new VarInsnNode(Opcodes.ASTORE, 0));     // local 0 = digest
        // _key = new SecretKeySpec(digest, "AES")
        cl.add(new TypeInsnNode(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec"));
        cl.add(new InsnNode(Opcodes.DUP));
        cl.add(new VarInsnNode(Opcodes.ALOAD, 0));
        cl.add(new LdcInsnNode(KEY_ALGO));
        cl.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "javax/crypto/spec/SecretKeySpec", "<init>", "([BLjava/lang/String;)V", false));
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "_key", "Ljavax/crypto/spec/SecretKeySpec;"));
        // _cache = new WeakReference[cacheSize]
        pushInt(cl, cacheSize);
        cl.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/ref/WeakReference"));
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "_cache", "[Ljava/lang/ref/WeakReference;"));
        // _init = true
        cl.add(new InsnNode(Opcodes.ICONST_1));
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "_init", "Z"));
        cl.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 6;
        clinit.maxLocals = 2;
        cn.methods.add(clinit);

        // --- decryptor variants ---
        for (String decName : decMethods) {
            cn.methods.add(buildDecryptor(decName));
        }

        graph.getClasses().put(holder, cn);
    }

    /**
     * Builds one decryptor method: {@code static String dec(byte[] enc, int id)}.
     *
     * <p>Logic:
     * <ol>
     *   <li>If {@code _cache[id] != null} return it (lazy cache hit).</li>
     *   <li>If {@code AntiDebug.isTampered()} return deterministic noise
     *       (leading ciphertext bytes decoded as UTF-8).</li>
     *   <li>Extract IV (first 16 bytes), run AES-256-CTR decrypt on the rest,
     *       wrap in {@code new String(pt, UTF_8)}, cache and return.</li>
     * </ol>
     * The whole decrypt body is wrapped in a catch-all handler that falls
     * through to the noise path, so a malformed blob never crashes the app.
     */
    private MethodNode buildDecryptor(String decName) {
        MethodNode dec = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                decName, DEC_DESC, null, null);
        InsnList d = new InsnList();
        // locals: 0=enc, 1=id, 2=wr, 3=iv, 4=cipher, 5=pt, 6=result, 7=exc, 8=cached
        String CACHE = "[Ljava/lang/ref/WeakReference;";

        // === cache check (weak): wr = _cache[id]; if (wr != null) { cached=(String)wr.get();
        //       if (cached != null) return cached; }  — a reclaimed entry simply re-decrypts ===
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "_cache", CACHE));
        d.add(new VarInsnNode(Opcodes.ILOAD, 1));
        d.add(new InsnNode(Opcodes.AALOAD));
        d.add(new VarInsnNode(Opcodes.ASTORE, 2));       // wr = _cache[id]
        LabelNode notCached = new LabelNode();
        d.add(new VarInsnNode(Opcodes.ALOAD, 2));
        d.add(new JumpInsnNode(Opcodes.IFNULL, notCached));
        d.add(new VarInsnNode(Opcodes.ALOAD, 2));
        d.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/ref/WeakReference", "get",
                "()Ljava/lang/Object;", false));
        d.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        d.add(new VarInsnNode(Opcodes.ASTORE, 8));       // cached
        d.add(new VarInsnNode(Opcodes.ALOAD, 8));
        d.add(new JumpInsnNode(Opcodes.IFNULL, notCached));
        d.add(new VarInsnNode(Opcodes.ALOAD, 8));
        d.add(new InsnNode(Opcodes.ARETURN));            // return cached

        d.add(notCached);

        // === anti-tamper: if (AntiDebug.isTampered()) goto noise ===
        d.add(new MethodInsnNode(Opcodes.INVOKESTATIC, ANTIDEBUG_OWNER, "isTampered", "()Z", false));
        LabelNode noise = new LabelNode();
        d.add(new JumpInsnNode(Opcodes.IFNE, noise));

        // === try: decrypt body ===
        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        d.add(tryStart);

        // iv = new byte[12]; System.arraycopy(enc, 0, iv, 0, 12)
        pushInt(d, IV_LEN);
        d.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        d.add(new VarInsnNode(Opcodes.ASTORE, 3));
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));       // enc
        d.add(new InsnNode(Opcodes.ICONST_0));
        d.add(new VarInsnNode(Opcodes.ALOAD, 3));       // iv
        d.add(new InsnNode(Opcodes.ICONST_0));
        pushInt(d, IV_LEN);
        d.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "arraycopy",
                "(Ljava/lang/Object;ILjava/lang/Object;II)V", false));

        // cipher = Cipher.getInstance("AES/CTR/NoPadding")
        d.add(new LdcInsnNode(CIPHER_SPEC));
        d.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "javax/crypto/Cipher", "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;", false));
        d.add(new VarInsnNode(Opcodes.ASTORE, 4));

        // cipher.init(DECRYPT_MODE, _key, new IvParameterSpec(iv))
        d.add(new VarInsnNode(Opcodes.ALOAD, 4));        // cipher
        d.add(new InsnNode(Opcodes.ICONST_2));           // Cipher.DECRYPT_MODE = 2
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "_key", "Ljavax/crypto/spec/SecretKeySpec;"));
        d.add(new TypeInsnNode(Opcodes.NEW, "javax/crypto/spec/IvParameterSpec"));
        d.add(new InsnNode(Opcodes.DUP));
        d.add(new VarInsnNode(Opcodes.ALOAD, 3));         // iv
        d.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "javax/crypto/spec/IvParameterSpec",
                "<init>", "([B)V", false));
        d.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "javax/crypto/Cipher", "init",
                "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V", false));

        // pt = cipher.doFinal(enc, 12, enc.length - 12)
        d.add(new VarInsnNode(Opcodes.ALOAD, 4));         // cipher
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));         // enc
        pushInt(d, IV_LEN);
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));         // enc
        d.add(new InsnNode(Opcodes.ARRAYLENGTH));
        pushInt(d, IV_LEN);
        d.add(new InsnNode(Opcodes.ISUB));                // enc.length - 12
        d.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "javax/crypto/Cipher", "doFinal",
                "([BII)[B", false));
        d.add(new VarInsnNode(Opcodes.ASTORE, 5));         // pt

        // result = new String(pt, UTF_8)
        d.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        d.add(new InsnNode(Opcodes.DUP));
        d.add(new VarInsnNode(Opcodes.ALOAD, 5));
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets",
                "UTF_8", "Ljava/nio/charset/Charset;"));
        d.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String",
                "<init>", "([BLjava/nio/charset/Charset;)V", false));
        d.add(new VarInsnNode(Opcodes.ASTORE, 6));         // result

        // _cache[id] = new WeakReference(result)
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "_cache", CACHE));
        d.add(new VarInsnNode(Opcodes.ILOAD, 1));
        d.add(new TypeInsnNode(Opcodes.NEW, "java/lang/ref/WeakReference"));
        d.add(new InsnNode(Opcodes.DUP));
        d.add(new VarInsnNode(Opcodes.ALOAD, 6));
        d.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/ref/WeakReference",
                "<init>", "(Ljava/lang/Object;)V", false));
        d.add(new InsnNode(Opcodes.AASTORE));

        // === L6 wipe: Arrays.fill(pt, (byte)0) — zero the plaintext source BEFORE the
        //     String escapes, so the byte-level plaintext never persists after use. ===
        d.add(new VarInsnNode(Opcodes.ALOAD, 5));
        d.add(new InsnNode(Opcodes.ICONST_0));
        d.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Arrays", "fill",
                "([BB)V", false));

        // return result
        d.add(new VarInsnNode(Opcodes.ALOAD, 6));
        d.add(new InsnNode(Opcodes.ARETURN));

        d.add(tryEnd);

        // === catch (Throwable): discard and fall through to noise ===
        d.add(handler);
        d.add(new VarInsnNode(Opcodes.ASTORE, 7));

        // === noise: return new String(enc, 0, Math.min(enc.length, 8), UTF_8) ===
        d.add(noise);
        d.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        d.add(new InsnNode(Opcodes.DUP));
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));         // enc
        d.add(new InsnNode(Opcodes.ICONST_0));
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));         // enc
        d.add(new InsnNode(Opcodes.ARRAYLENGTH));
        pushInt(d, 8);
        d.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "min", "(II)I", false));
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets",
                "UTF_8", "Ljava/nio/charset/Charset;"));
        d.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String",
                "<init>", "([BIILjava/nio/charset/Charset;)V", false));
        d.add(new InsnNode(Opcodes.ARETURN));

        dec.instructions = d;
        dec.maxStack = 6;
        // locals 0..8 (incl. weak-ref cached slot); 9 total.
        dec.maxLocals = 9;
        // Catch-all handler covering the decrypt body: any Throwable -> noise.
        dec.tryCatchBlocks.add(new TryCatchBlockNode(tryStart, tryEnd, handler, null));
        return dec;
    }

    // ------------------------------------------------------------------
    //  Bytecode helpers (mirrors WhiteboxStringEncryptor).
    // ------------------------------------------------------------------

    private void pushByteArray(InsnList l, byte[] data) {
        pushInt(l, data.length);
        l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < data.length; i++) {
            l.add(new InsnNode(Opcodes.DUP));
            pushInt(l, i);
            pushByte(l, data[i]);
            l.add(new InsnNode(Opcodes.BASTORE));
        }
    }

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

    private static String randomName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        java.util.concurrent.ThreadLocalRandom r = java.util.concurrent.ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(cs.charAt(r.nextInt(cs.length())));
        return sb.toString();
    }

    private byte[] randomPermutation() {
        byte[] t = new byte[256];
        for (int i = 0; i < 256; i++) t[i] = (byte) i;
        for (int i = 255; i > 0; i--) {
            int j = rng.get().nextInt(i + 1);
            byte tmp = t[i];
            t[i] = t[j];
            t[j] = tmp;
        }
        return t;
    }
}
