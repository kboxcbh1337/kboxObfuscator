package com.kbox.core.stringenc;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

/**
 * Table-substitution string encryption ("whitebox" mode).
 *
 * <p><b>KBX-STR-04 (honesty note):</b> this is NOT a white-box construction in
 * the academic sense (Chow et al.) — there is no encoded-table algebra, no
 * external encodings, no mask binding. The lookup table <em>is</em> the key and
 * it ships inside the artifact next to the ciphertext, so an attacker who
 * extracts the table can decrypt everything offline. The name is kept for
 * config/API compatibility only; treat this as an obfuscated substitution
 * cipher with per-build keys, roughly comparable to the AES scheme in
 * {@link AesStringEncryptor} in terms of the static-extraction ceiling.
 *
 * <p>Encrypts each string literal into a byte array via a random 256-entry
 * permutation lookup table {@code T} (the "key"). The table is embedded in a
 * synthetic runtime holder; the inverse table {@code invT} is computed in that
 * class's {@code <clinit>}. At the use site, inline bytecode calls a decryptor
 * that reconstructs the original string by table lookup.
 *
 * <p>Encryption scheme (per byte index {@code i}, per-string salt {@code salt}):
 * <pre>
 *   enc[i] = T[(p[i] + i + salt) &amp; 0xFF]
 *   dec: y = invT[enc[i] &amp; 0xFF]; p[i] = (y - i - salt) &amp; 0xFF
 * </pre>
 * Every literal carries its own random {@code salt}, so hooking a single
 * decryptor is not enough to bulk-recover every string (each needs its salt).
 * Multiple decryptor variants (randomised names) are emitted and one is chosen
 * per site, so there is no single stable decryption symbol to grep or mock.
 * The key is distributed across the whole permutation table rather than
 * appearing as a standalone constant, and a fresh table + salts are generated
 * per build, so ciphertext changes between runs.
 */
public final class WhiteboxStringEncryptor {

    private static final String TAG = "whitebox";
    /** Decryptor signature: (byte[] enc, int salt) -> String. */
    private static final String DEC_DESC = "([BI)Ljava/lang/String;";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final SecureRandom rng = new SecureRandom();
    private byte[] table;
    private final java.util.concurrent.atomic.AtomicInteger encrypted =
            new java.util.concurrent.atomic.AtomicInteger();

    // Randomized per-build symbols (holder class + several decryptor variants).
    private String holder;
    private String[] decMethods;

    public WhiteboxStringEncryptor(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    private static String randomName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        java.util.concurrent.ThreadLocalRandom r = java.util.concurrent.ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(cs.charAt(r.nextInt(cs.length())));
        return sb.toString();
    }

    public void apply() {
        if (!cfg.isWhiteboxStrings()) return;
        holder = "com/kbox/runtime/_" + randomName(14);
        int variants = 2 + rng.nextInt(2);   // 2..3 variants per build
        decMethods = new String[variants];
        for (int i = 0; i < variants; i++) decMethods[i] = "z" + randomName(9);
        table = randomPermutation();
        ensureHolder();
        encrypted.set(0);
        // Parallel per-class encryption (no shared mutable state between classes).
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, this::encryptClass,
                cfg.getParallelThreads());
        KBoxLog.info(TAG, "White-box encrypted " + encrypted.get() + " strings (256-entry table, "
                + variants + " decryptors, holder=" + holder + ")");
    }

    private byte[] randomPermutation() {
        byte[] t = new byte[256];
        for (int i = 0; i < 256; i++) t[i] = (byte) i;
        for (int i = 255; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            byte tmp = t[i];
            t[i] = t[j];
            t[j] = tmp;
        }
        return t;
    }

    @SuppressWarnings("unchecked")
    private void encryptClass(ClassNode cn) {
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
                AbstractInsnNode next = ins.getNext();
                if (ins.getOpcode() == Opcodes.LDC && ins instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) ins;
                    if (ldc.cst instanceof String) {
                        String s = (String) ldc.cst;
                        if (s.isEmpty()) { ins = next; continue; }
                        // Each literal gets its own random salt and a random
                        // decryptor variant — no single API to hook.
                        int salt = rng.nextInt(256);
                        String decName = decMethods[rng.nextInt(decMethods.length)];
                        byte[] enc = encrypt(s, salt);
                        InsnList repl = new InsnList();
                        pushByteArray(repl, enc);
                        pushInt(repl, salt);
                        repl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holder, decName, DEC_DESC, false));
                        mn.instructions.insertBefore(ins, repl);
                        mn.instructions.remove(ins);
                        encrypted.incrementAndGet();
                    }
                }
                ins = next;
            }
        }
    }

    /** enc[i] = T[(p[i] + i + salt) & 0xFF]. */
    private byte[] encrypt(String s, int salt) {
        byte[] p = s.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[p.length];
        for (int i = 0; i < p.length; i++) {
            int idx = (p[i] & 0xFF) + i + salt & 0xFF;
            out[i] = table[idx];
        }
        return out;
    }

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

    private void ensureHolder() {
        if (graph.getClasses().containsKey(holder)) return;
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = holder;
        cn.superName = "java/lang/Object";

        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);

        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, "T", "[B", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, "invT", "[B", null, null));

        // <clinit>: fill T, then compute invT[i] = indexOf(i) via invT[T[k]] = k.
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList cl = clinit.instructions;
        pushInt(cl, 256);
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < 256; i++) {
            cl.add(new InsnNode(Opcodes.DUP));
            pushInt(cl, i);
            pushByte(cl, table[i]);
            cl.add(new InsnNode(Opcodes.BASTORE));
        }
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "T", "[B"));
        // invT = new byte[256]
        pushInt(cl, 256);
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        // for k in 0..255: invT[T[k] & 0xFF] = k
        for (int k = 0; k < 256; k++) {
            cl.add(new InsnNode(Opcodes.DUP));                       // stack: [invT]
            // pushByte() emits SIPUSH for values > 127. Using a raw
            // IntInsnNode(BIPUSH, v) here would sign-extend v>=128 to a
            // negative index at runtime (BIPUSH sign-extends its byte), e.g.
            // v=173 (0xAD) -> -83 -> ArrayIndexOutOfBoundsException.
            pushByte(cl, table[k]);                                  // index = T[k] & 0xFF
            pushInt(cl, k);                                          // value = k
            cl.add(new InsnNode(Opcodes.BASTORE));                   // invT[index] = k
        }
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "invT", "[B"));
        cl.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 4;
        clinit.maxLocals = 0;
        cn.methods.add(clinit);

        // Multiple decryptor variants: each is (byte[] enc, int salt) -> String.
        //   out = new byte[enc.length]
        //   y = invT[enc[i] & 0xFF]; out[i] = (byte)((y - i - salt) & 0xFF)
        //   return new String(out, StandardCharsets.UTF_8)
        // KBX-STR-03: the encryption side encodes UTF-8 bytes, so the decryptor
        // MUST decode UTF-8. The old per-byte append((char)(x&0xFF)) was Latin-1
        // and silently corrupted every non-ASCII string (e.g. "中" -> "ä¸­").
        // No single API symbol exists to hook; each site picked one at random.
        for (String decName : decMethods) {
            MethodNode dec = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, decName,
                    DEC_DESC, null, null);
            InsnList d = new InsnList();
            // locals: arg0=enc(0), arg1=salt(1), out=2, i=3, y=4
            int out = 2, i = 3, y = 4;
            int saltSlot = 1;

            // out = new byte[enc.length]
            d.add(new VarInsnNode(Opcodes.ALOAD, 0));
            d.add(new InsnNode(Opcodes.ARRAYLENGTH));
            d.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
            d.add(new VarInsnNode(Opcodes.ASTORE, out));
            d.add(new InsnNode(Opcodes.ICONST_0));
            d.add(new VarInsnNode(Opcodes.ISTORE, i));

            LabelNode loopStart = new LabelNode();
            LabelNode loopEnd = new LabelNode();
            d.add(loopStart);
            d.add(new VarInsnNode(Opcodes.ILOAD, i));
            d.add(new VarInsnNode(Opcodes.ALOAD, 0));
            d.add(new InsnNode(Opcodes.ARRAYLENGTH));
            d.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

            // y = invT[enc[i] & 0xFF]
            d.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "invT", "[B"));
            d.add(new VarInsnNode(Opcodes.ALOAD, 0));
            d.add(new VarInsnNode(Opcodes.ILOAD, i));
            d.add(new InsnNode(Opcodes.BALOAD));          // enc[i] (sign-extended byte)
            d.add(new LdcInsnNode(0xFF));
            d.add(new InsnNode(Opcodes.IAND));            // enc[i] & 0xFF
            d.add(new InsnNode(Opcodes.BALOAD));          // invT[...]
            d.add(new VarInsnNode(Opcodes.ISTORE, y));

            // out[i] = (byte)((y - i - salt) & 0xFF)
            d.add(new VarInsnNode(Opcodes.ALOAD, out));
            d.add(new VarInsnNode(Opcodes.ILOAD, i));
            d.add(new VarInsnNode(Opcodes.ILOAD, y));
            d.add(new VarInsnNode(Opcodes.ILOAD, i));
            d.add(new InsnNode(Opcodes.ISUB));            // y - i
            d.add(new VarInsnNode(Opcodes.ILOAD, saltSlot)); // - salt
            d.add(new InsnNode(Opcodes.ISUB));            // y - i - salt
            d.add(new LdcInsnNode(0xFF));
            d.add(new InsnNode(Opcodes.IAND));            // & 0xFF
            d.add(new InsnNode(Opcodes.I2B));             // (byte)
            d.add(new InsnNode(Opcodes.BASTORE));

            d.add(new org.objectweb.asm.tree.IincInsnNode(i, 1));
            d.add(new JumpInsnNode(Opcodes.GOTO, loopStart));
            d.add(loopEnd);

            // return new String(out, StandardCharsets.UTF_8)
            d.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
            d.add(new InsnNode(Opcodes.DUP));
            d.add(new VarInsnNode(Opcodes.ALOAD, out));
            d.add(new FieldInsnNode(Opcodes.GETSTATIC,
                    "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
            d.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>",
                    "([BLjava/nio/charset/Charset;)V", false));
            d.add(new InsnNode(Opcodes.ARETURN));
            dec.instructions = d;
            dec.maxStack = 5;
            dec.maxLocals = 5;
            cn.methods.add(dec);
        }

        graph.getClasses().put(holder, cn);
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
}