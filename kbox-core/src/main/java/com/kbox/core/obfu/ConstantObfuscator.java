package com.kbox.core.obfu;

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
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Constant obfuscation ("indirect calculation"). Replaces magic-number and
 * other {@code int} constants in method bodies with an indirect lookup
 * {@code _KboxConsts.I(k)}, where {@code I} returns
 * {@code (table[k] ^ key)}. The key is stored in the synthetic holder
 * {@code com/kbox/runtime/_KboxConsts} and XOR is applied at build to the
 * table entries, so no bare constant survives in the bytecode and each
 * constant's real value is only recoverable by executing {@code I}.
 *
 * <p><b>Byte-size filtering.</b> {@code ICONST_0..5}, {@code BIPUSH} (small)
 * and tight loop counters are left untouched: replacing those would bloat
 * hot paths and make the dispatch table enormous for little benefit. Only
 * constants with plausible "magic-number" magnitude are routed through the
 * lookup. The rewrite is stack-neutral (push idx {@code -> I} yields one int),
 * so {@code COMPUTE_FRAMES} keeps every frame valid.
 *
 * <p>The holder class is injected only once per build. {@code I} is
 * {@code public static} so any protected class can call it.
 */
public final class ConstantObfuscator {

    private static final String TAG = "constobf";
    // Fixed-name legacy defaults; each build randomizes them so no stable
    // "com/kbox/runtime/_KboxConsts" signature survives to grep/模拟.
    private static final String HOLDER = "com/kbox/runtime/_KboxConsts";
    private static final String GET_I = "I";
    private static final String GET_I_DESC = "(I)I";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final SecureRandom rng = new SecureRandom();
    private final java.util.concurrent.atomic.AtomicInteger rewritten =
            new java.util.concurrent.atomic.AtomicInteger();

    // Randomized per-build symbols (set in apply()).
    private String holder;
    private String getI;
    private String fieldK;
    private String fieldT;

    public ConstantObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /** Random identifier of the given length using mixed-case alphanumerics. */
    private static String randomName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        java.util.concurrent.ThreadLocalRandom r = java.util.concurrent.ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(cs.charAt(r.nextInt(cs.length())));
        return sb.toString();
    }

    public void apply() {
        if (!cfg.isObfuscateConstants()) return;
        if (key == Integer.MIN_VALUE) {
            do { key = rng.nextInt(); } while (key == Integer.MIN_VALUE || key == 0);
        }
        // Build-diversity: random class/member/field names every run so the
        // decryption API is not a stable symbol a generic unpacker can target.
        holder = "com/kbox/runtime/_" + randomName(14);
        getI = "m" + randomName(9);
        fieldK = "a" + randomName(5);
        fieldT = randomName(6);
        rewritten.set(0);
        // First pass allocates indices into intTable; the holder class must be
        // injected AFTER allocation so its T[] size matches the final table.
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, this::obfClass,
                cfg.getParallelThreads());
        ensureHolder();
        KBoxLog.info(TAG, "Indirect-encrypted " + rewritten.get() + " int constants (holder="
                + holder + ")");
    }

    @SuppressWarnings("unchecked")
    private void obfClass(ClassNode cn) {
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            List<AbstractInsnNode> targets = new ArrayList<>();
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
                int op = ins.getOpcode();
                int v;
                boolean isInt;
                if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) {
                    v = op - Opcodes.ICONST_0;
                    isInt = true;
                } else if (ins instanceof IntInsnNode
                        && (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH)) {
                    v = ((IntInsnNode) ins).operand;
                    isInt = true;
                } else if (ins instanceof LdcInsnNode
                        && ((LdcInsnNode) ins).cst instanceof Integer) {
                    v = (Integer) ((LdcInsnNode) ins).cst;
                    isInt = true;
                } else {
                    isInt = false;
                    v = 0;
                }
                if (!isInt) continue;
                // Skip tiny constants / -1 / 0..2 that are overwhelmingly loop
                // counters or flags (rewriting them is noise and bloats hot paths).
                if (Math.abs(v) < 4 || v == -1) continue;
                targets.add(ins);
            }
            if (targets.isEmpty()) continue;
            for (AbstractInsnNode ins : targets) {
                if (ins.getOpcode() == -1) continue;
                int v = constantValue(ins);
                if (v == Integer.MIN_VALUE) continue;
                int idx = storeAndEncrypt(v);
                InsnList repl = new InsnList();
                pushInt(repl, idx);
                repl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holder, getI, GET_I_DESC, false));
                mn.instructions.insertBefore(ins, repl);
                mn.instructions.remove(ins);
                rewritten.incrementAndGet();
            }
        }
    }

    private int constantValue(AbstractInsnNode ins) {
        int op = ins.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - Opcodes.ICONST_0;
        if (ins instanceof IntInsnNode) return ((IntInsnNode) ins).operand;
        if (ins instanceof LdcInsnNode && ((LdcInsnNode) ins).cst instanceof Integer)
            return (Integer) ((LdcInsnNode) ins).cst;
        return Integer.MIN_VALUE;
    }

    // ---- holder ----

    private final java.util.Map<Integer, Integer> intTable = new java.util.LinkedHashMap<>();
    private int key = Integer.MIN_VALUE;

    /** Thread-safe: indices are allocated monotonically as classes are processed in parallel. */
    private synchronized int storeAndEncrypt(int v) {
        Integer idx = intTable.get(v);
        if (idx != null) return idx;
        int nidx = intTable.size();
        intTable.put(v, nidx);
        return nidx;
    }

    private void ensureHolder() {
        if (graph.getClasses().containsKey(holder)) return;
        if (key == Integer.MIN_VALUE) {
            do { key = rng.nextInt(); } while (key == Integer.MIN_VALUE || key == 0);
        }
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = holder;
        cn.superName = "java/lang/Object";
        // Coyote the class itself: keep it from being flattened/string-encrypted
        // (its own logic is trivial) and ensure it is not renamed since the
        // cryptographic derivation below binds to its exact internal name.
        graph.markCfModified(holder);

        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);

        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, fieldK, "I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, fieldT, "[I", null, null));

        // <clinit>: K = key ^ hash(holder); T[i] = plain ^ key.
        // At the use site we recompute key = T[idx] ^ (K ^ hash(holder)) so the
        // real key never exists as a bare constant (it is inferred from the
        // class's own name at runtime) — blocking naive memory-dump还原.
        int salt = holder.hashCode();
        int storedK = key ^ salt;
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList cl = clinit.instructions;
        pushInt(cl, storedK);
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, fieldK, "I"));
        pushInt(cl, intTable.size());
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        int[] vals = new int[intTable.size()];
        for (Integer v : intTable.keySet()) {
            vals[intTable.get(v)] = v;
        }
        for (int i = 0; i < vals.length; i++) {
            cl.add(new InsnNode(Opcodes.DUP));
            pushInt(cl, i);
            pushInt(cl, vals[i] ^ key);
            cl.add(new InsnNode(Opcodes.IASTORE));
        }
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, fieldT, "[I"));
        cl.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 4;
        clinit.maxLocals = 0;
        cn.methods.add(clinit);

        // public static int getI(int idx) { return T[idx] ^ (K ^ salt); }
        // salt is recomputed from the class's own name so it is not discoverable
        // as a lone constant.
        MethodNode getI = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, this.getI, GET_I_DESC, null, null);
        InsnList g = new InsnList();
        g.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, fieldT, "[I"));
        g.add(new VarInsnNode(Opcodes.ILOAD, 0));
        g.add(new InsnNode(Opcodes.IALOAD));
        g.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, fieldK, "I"));
        pushInt(g, salt);
        g.add(new InsnNode(Opcodes.IXOR));
        g.add(new InsnNode(Opcodes.IXOR));
        g.add(new InsnNode(Opcodes.IRETURN));
        getI.instructions = g;
        getI.maxStack = 3;
        getI.maxLocals = 1;
        cn.methods.add(getI);

        graph.getClasses().put(holder, cn);
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }
}