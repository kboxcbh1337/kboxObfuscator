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
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * S2 — kboxDedeobfShieldV1 opaque state-machine fake branches.
 *
 * <p>For a deterministic subset of real conditional / unconditional branch
 * instructions, insert a <em>runtime state machine</em> opaque predicate before
 * the branch, followed by a dead "poison" block:
 *
 * <pre>   invokestatic _Sg.guard()I        // consumes nothing below, pushes g (always 0)
 *   ifeq  LREAL                       // pops g, constants true -> always jumps
 *   new java/lang/RuntimeException
 *   dup; invokespecial &lt;init&gt;; athrow  // poison: unreachable
 * LREAL:
 *   &lt;original branch&gt;</pre>
 *
 * <p>{@code guard()} reads a chained static {@code state}, advances it with a
 * build-constant LCG-ish recurrence and returns {@code (x*(x+1))&amp;1}, which is
 * provably {@code 0} for every {@code int} {@code x} (x(x+1) is always even), so
 * the injected branch never diverts real flow — but any static analysis that
 * symbolically executes the CFG must now model the churn function and the dead
 * throw block to prove the true path, defeating single-pass reachability.
 *
 * <p><b>Verifier safety.</b> The injected code only touches the operand stack in
 * a balanced way: {@code guard()}I pushes exactly one value that {@code IFEQ}
 * consumes, leaving whatever the original branch operands were still in place;
 * the poison block is a standalone throw. {@code COMPUTE_FRAMES} recomputes every
 * frame at packaging, so all merge points stay valid.
 */
public final class OpaqueStateObfuscator {

    private static final String TAG = "opaqsm";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final AtomicInteger guarded = new AtomicInteger();

    public OpaqueStateObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    private static String randomName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        ThreadLocalRandom r = ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(cs.charAt(r.nextInt(cs.length())));
        return sb.toString();
    }

    public void apply() {
        int level = cfg.getOpaqueStateMachine();
        if (level <= 0) return;
        String holder = "com/kbox/shield/_S" + randomName(12);
        String fState = "s" + randomName(4);
        String mGuard = "g" + randomName(8);

        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, cn -> {
            if (cn.name == null || cn.name.length() == 0) return;
            if (cn.name.equals(holder)) return;
            for (Object m : cn.methods) {
                MethodNode mn = (MethodNode) m;
                if (mn.instructions == null) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                guardMethod(mn, holder, mGuard, level);
            }
        }, cfg.getParallelThreads());

        ensureHolder(holder, fState, mGuard);
        KBoxLog.info(TAG, "Opaque state-machine guards inserted on " + guarded.get()
                + " branches (holder=" + holder + ")");
    }

    private void guardMethod(MethodNode mn, String holder, String mGuard, int level) {
        List<AbstractInsnNode> branchInsns = new ArrayList<>();
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            int op = ins.getOpcode();
            boolean isBranch = op >= Opcodes.IFEQ && op <= Opcodes.IF_ACMPNE
                    || op == Opcodes.IFNULL || op == Opcodes.IFNONNULL
                    || op == Opcodes.GOTO;
            if (isBranch) branchInsns.add(ins);
        }
        // Sample a progressive subset by level so we never bloat hot micro-methods.
        int stride = level >= 3 ? 1 : (level == 2 ? 2 : 3);
        for (int i = 0; i < branchInsns.size(); i += stride) {
            AbstractInsnNode branch = branchInsns.get(i);
            if (branch.getOpcode() == -1) continue;
            injectGuard(mn.instructions, branch, holder, mGuard);
            guarded.incrementAndGet();
        }
    }

    /** Prepend the state-machine guard + dead poison block before {@code branch}. */
    private static void injectGuard(InsnList insns, AbstractInsnNode branch,
                                    String holder, String mGuard) {
        LabelNode dead = new LabelNode(new org.objectweb.asm.Label());
        LabelNode real = new LabelNode(new org.objectweb.asm.Label());
        // [g = guard(); ifeq real] -- leaves original operands untouched below.
        insns.insertBefore(branch,
                new MethodInsnNode(Opcodes.INVOKESTATIC, holder, mGuard, "()I", false));
        insns.insertBefore(branch, new JumpInsnNode(Opcodes.IFEQ, real));
        // dead poison block (unreachable, g is always 0)
        insns.insertBefore(branch, dead);
        insns.insertBefore(branch, new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
        insns.insertBefore(branch, new InsnNode(Opcodes.DUP));
        insns.insertBefore(branch, new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/RuntimeException", "<init>", "()V", false));
        insns.insertBefore(branch, new InsnNode(Opcodes.ATHROW));
        insns.insertBefore(branch, real);
    }

    private void ensureHolder(String holder, String fState, String mGuard) {
        if (graph.getClasses().containsKey(holder)) return;
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = holder;
        cn.superName = "java/lang/Object";
        graph.markCfModified(holder);

        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, fState, "I", null, null));

        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);

        // <clinit>: state = 1
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        pushInt(clinit.instructions, 1);
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, fState, "I"));
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 1;
        clinit.maxLocals = 0;
        cn.methods.add(clinit);

        // public static int guard(){ int x=state; state=(x*0x45D9)^0x9E3779B9;
        //                                int q = x*(x+1); return q & 1; }  // always 0
        MethodNode guard = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                mGuard, "()I", null, null);
        InsnList g = guard.instructions;
        g.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, fState, "I"));
        g.add(new VarInsnNode(Opcodes.ISTORE, 0));
        g.add(new VarInsnNode(Opcodes.ILOAD, 0));
        pushInt(g, 0x45D9);
        g.add(new InsnNode(Opcodes.IMUL));
        pushInt(g, 0x9E3779B9);
        g.add(new InsnNode(Opcodes.IXOR));
        g.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, fState, "I"));
        g.add(new VarInsnNode(Opcodes.ILOAD, 0));
        g.add(new VarInsnNode(Opcodes.ILOAD, 0));
        g.add(new InsnNode(Opcodes.ICONST_1));
        g.add(new InsnNode(Opcodes.IADD));
        g.add(new InsnNode(Opcodes.IMUL));
        g.add(new InsnNode(Opcodes.ICONST_1));
        g.add(new InsnNode(Opcodes.IAND));
        g.add(new InsnNode(Opcodes.IRETURN));
        guard.maxStack = 3;
        guard.maxLocals = 1;
        cn.methods.add(guard);

        graph.getClasses().put(holder, cn);
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }
}