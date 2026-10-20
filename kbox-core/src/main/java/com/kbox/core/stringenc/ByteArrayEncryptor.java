package com.kbox.core.stringenc;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 条目 45: constant {@code byte[]} literal encryption.
 *
 * <p>javac compiles {@code new byte[]{1,2,3,...}} into an inline
 * {@code NEWARRAY T_BYTE} followed by one {@code DUP; index; value; BASTORE}
 * group per element, so the plaintext bytes sit directly in the code array
 * (a trivial grep/hash target — embedded keys, lookup tables, magic blobs).
 * This pass rewrites the whole construction into
 * {@code KBoxRuntime.b(new byte[]{enc...})}: the constant bytes are
 * rolling-XOR encrypted under a fresh per-array key and only the ciphertext
 * remains in the class file.
 *
 * <p>Eligibility: fully constant arrays of at least {@link #MIN_LEN} elements.
 * Arrays built with non-constant elements, or with any label/jump target in
 * the middle, are left untouched (the pass never changes semantics).
 *
 * <p>Must run BEFORE string encryption: the string encryptor emits
 * ciphertext arrays in exactly this shape, and re-encrypting them would both
 * bloat the output and waste a decryptor call.
 */
public final class ByteArrayEncryptor {

    private static final String TAG = "byte-arrays";
    private static final String RUNTIME_OWNER = "com/kbox/runtime/KBoxRuntime";
    private static final String DEC_DESC = "([B)[B";
    /** Arrays shorter than this stay inline: the decryptor call would cost
     *  more bytes than the literal it replaces. */
    private static final int MIN_LEN = 6;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private int encrypted;

    public ByteArrayEncryptor(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isEncryptStrings()) return;
        int skipped = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.name.equals(RUNTIME_OWNER)) continue;
            if (!cfg.shouldProtectClass(cn.name)) { skipped++; continue; }
            try {
                for (MethodNode mn : (List<MethodNode>) cn.methods) {
                    if (mn.instructions == null || mn.instructions.size() == 0) continue;
                    encryptMethod(cn, mn);
                }
            } catch (Exception e) {
                if (cfg.isNeverFail()) {
                    KBoxLog.warn(TAG, "byte[] encryption failed for " + cn.name
                            + ": " + e.getMessage());
                } else {
                    throw new com.kbox.core.KBoxException(
                            "byte[] encryption failed for " + cn.name, e);
                }
            }
        }
        if (encrypted > 0) {
            KBoxLog.info(TAG, "Encrypted " + encrypted + " constant byte[] literal(s)");
        }
    }

    private void encryptMethod(ClassNode cn, MethodNode mn) {
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            IntInsnNode newArray = asNewArrayByte(ins);
            if (newArray != null) {
                // The length operand is the immediately preceding REAL
                // instruction (javac always emits a constant push there).
                AbstractInsnNode lenPush = skipPseudoBack(newArray.getPrevious());
                if (lenPush != null && intConst(lenPush) != Integer.MIN_VALUE) {
                    int replaced = tryRewrite(mn, lenPush, newArray);
                    if (replaced > 0) {
                        encrypted++;
                        graph.markCfModified(cn.name);
                        next = skipPseudo(newArray.getNext());
                    }
                }
            }
            ins = next;
        }
    }

    /** Returns the node when it is {@code NEWARRAY T_BYTE}, else null. */
    private static IntInsnNode asNewArrayByte(AbstractInsnNode ins) {
        if (ins instanceof IntInsnNode
                && ins.getOpcode() == Opcodes.NEWARRAY
                && ((IntInsnNode) ins).operand == Opcodes.T_BYTE) {
            return (IntInsnNode) ins;
        }
        return null;
    }

    /**
     * Attempts to consume {@code [len][NEWARRAY byte][DUP idx val BASTORE]*n}
     * and replace it with a decryptor call. Returns 1 on success, 0 otherwise.
     */
    private int tryRewrite(MethodNode mn, AbstractInsnNode lenPush, IntInsnNode newArray) {
        int len = intConst(lenPush);
        if (len < MIN_LEN || len > 8192) return 0;
        // Walk exactly the canonical construction sequence.
        byte[] values = new byte[len];
        AbstractInsnNode cur = skipPseudo(newArray.getNext());
        AbstractInsnNode last = newArray;
        for (int i = 0; i < len; i++) {
            if (cur == null || cur.getOpcode() != Opcodes.DUP) return 0;
            AbstractInsnNode idxPush = skipPseudo(cur.getNext());
            if (idxPush == null || intConst(idxPush) != i) return 0;
            AbstractInsnNode valPush = skipPseudo(idxPush.getNext());
            int v = intConst(valPush);
            if (v < Byte.MIN_VALUE || v > Byte.MAX_VALUE) return 0;
            AbstractInsnNode store = skipPseudo(valPush.getNext());
            if (store == null || store.getOpcode() != Opcodes.BASTORE) return 0;
            values[i] = (byte) v;
            last = store;
            cur = skipPseudo(store.getNext());
        }
        // Do not swallow a label/jump target that sits inside the sequence.
        for (AbstractInsnNode n = lenPush.getNext(); n != null && n != last; n = n.getNext()) {
            if (n instanceof LabelNode) return 0;
        }
        int key = ThreadLocalRandom.current().nextInt();
        byte[] enc = new byte[len + 4];
        enc[0] = (byte) (key >>> 24);
        enc[1] = (byte) (key >>> 16);
        enc[2] = (byte) (key >>> 8);
        enc[3] = (byte) key;
        for (int i = 0; i < len; i++) {
            int shift = (i * 7) % 32;
            int k = (key >>> shift) ^ (key << (32 - shift));
            enc[i + 4] = (byte) (values[i] ^ (k & 0xFF));
        }
        InsnList repl = new InsnList();
        StringEncryptor.pushInt(repl, enc.length);
        repl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < enc.length; i++) {
            repl.add(new InsnNode(Opcodes.DUP));
            StringEncryptor.pushInt(repl, i);
            StringEncryptor.pushByte(repl, enc[i]);
            repl.add(new InsnNode(Opcodes.BASTORE));
        }
        repl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_OWNER, "b", DEC_DESC, false));
        // Remove the original construction (length push .. last BASTORE).
        AbstractInsnNode stop = last.getNext();
        AbstractInsnNode n = lenPush;
        while (n != null && n != stop) {
            AbstractInsnNode nx = n.getNext();
            mn.instructions.remove(n);
            n = nx;
        }
        if (stop != null) {
            mn.instructions.insertBefore(stop, repl);
        } else {
            mn.instructions.add(repl);
        }
        return 1;
    }

    /** Skips labels / line numbers / frames; returns the next real instruction. */
    private static AbstractInsnNode skipPseudo(AbstractInsnNode n) {
        while (n != null && n.getOpcode() == -1) n = n.getNext();
        return n;
    }

    /** Backwards variant of {@link #skipPseudo}. */
    private static AbstractInsnNode skipPseudoBack(AbstractInsnNode n) {
        while (n != null && n.getOpcode() == -1) n = n.getPrevious();
        return n;
    }

    /** Constant int value of a push instruction, or Integer.MIN_VALUE when not a constant. */
    private static int intConst(AbstractInsnNode n) {
        if (n == null) return Integer.MIN_VALUE;
        int op = n.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) {
            return op - Opcodes.ICONST_0;
        }
        if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) {
            return ((IntInsnNode) n).operand;
        }
        if (op == Opcodes.LDC && n instanceof LdcInsnNode
                && ((LdcInsnNode) n).cst instanceof Integer) {
            return (Integer) ((LdcInsnNode) n).cst;
        }
        return Integer.MIN_VALUE;
    }
}
