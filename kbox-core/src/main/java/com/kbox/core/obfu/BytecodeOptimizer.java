package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 混淆前字节码优化器（与混淆流水线分离的独立优化通道）。
 *
 * <ul>
 *   <li><b>Peephole</b>：删除 NOP、{@code DUP;POP}、常量压栈后立即 POP。</li>
 *   <li><b>代数恒等式</b>：{@code x+0}、{@code x*1}、{@code x&-1}、{@code x^0}、
 *       {@code x|0}、{@code x-0} 收敛为单条取值。</li>
 *   <li><b>常量折叠</b>：两个 int 常量 + 算术 → 一个常量（不含除零类）。</li>
 *   <li><b>死代码消除</b>：GOTO/RETURN/ATHROW 之后到下一个跳转目标 label 之间的
 *       不可达指令；{@code GOTO next} 自跳转。</li>
 * </ul>
 *
 * <p>只处理 {@link ProtectionConfig#shouldTransformClass(String)} 允许的类；
 * 任何改动都标记 {@code cfModified}，打包期重算 StackMapTable。优化失败时
 * 打包器已有的回滚网会保留原始字节。</p>
 */
public final class BytecodeOptimizer {

    private static final String TAG = "optimizer";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public BytecodeOptimizer(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isOptimize()) return;
        int classes = 0;
        long removed = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldTransformClass(cn.name)) continue;
            boolean any = false;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                int before = mn.instructions.size();
                optimize(mn);
                if (mn.instructions.size() != before) {
                    any = true;
                    removed += before - mn.instructions.size();
                }
            }
            if (any) {
                graph.markCfModified(cn.name);
                classes++;
            }
        }
        KBoxLog.info(TAG, "Optimized " + classes + " class(es), removed "
                + removed + " instruction(s)");
    }

    private void optimize(MethodNode mn) {
        removeNops(mn.instructions);
        foldConstants(mn.instructions);
        identities(mn.instructions);
        removeGotoNext(mn.instructions);
        deadCode(mn);
    }

    private static void removeNops(InsnList list) {
        for (AbstractInsnNode ins = list.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            if (ins.getOpcode() == Opcodes.NOP) list.remove(ins);
            ins = next;
        }
    }

    /** Previous "real" instruction, skipping labels/frames/line numbers. */
    private static AbstractInsnNode prevReal(AbstractInsnNode ins) {
        AbstractInsnNode p = ins.getPrevious();
        while (p != null && (p instanceof LabelNode || p instanceof FrameNode
                || p instanceof LineNumberNode)) {
            p = p.getPrevious();
        }
        return p;
    }

    private static AbstractInsnNode nextReal(AbstractInsnNode ins) {
        AbstractInsnNode p = ins.getNext();
        while (p != null && (p instanceof LabelNode || p instanceof FrameNode
                || p instanceof LineNumberNode)) {
            p = p.getNext();
        }
        return p;
    }

    private static Integer intConst(AbstractInsnNode ins) {
        if (ins == null) return null;
        int op = ins.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) {
            return Integer.valueOf(op - Opcodes.ICONST_0);
        }
        if (ins instanceof IntInsnNode
                && (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH)) {
            return Integer.valueOf(((IntInsnNode) ins).operand);
        }
        if (ins instanceof LdcInsnNode) {
            Object c = ((LdcInsnNode) ins).cst;
            if (c instanceof Integer) return (Integer) c;
        }
        return null;
    }

    private static void foldConstants(InsnList list) {
        for (AbstractInsnNode ins = list.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            int op = ins.getOpcode();
            if (op >= Opcodes.IADD && op <= Opcodes.IUSHR || op == Opcodes.IAND
                    || op == Opcodes.IOR || op == Opcodes.IXOR || op == Opcodes.ISUB) {
                AbstractInsnNode b = prevReal(ins);
                AbstractInsnNode a = prevReal(b);
                Integer av = intConst(a);
                Integer bv = intConst(b);
                if (av != null && bv != null) {
                    Integer r = foldInt(op, av.intValue(), bv.intValue());
                    if (r != null) {
                        list.remove(a);
                        list.remove(b);
                        list.set(ins, intPush(r.intValue()));
                        next = ins.getNext();
                    }
                }
            }
            ins = next;
        }
    }

    private static Integer foldInt(int op, int a, int b) {
        switch (op) {
            case Opcodes.IADD: return Integer.valueOf(a + b);
            case Opcodes.ISUB: return Integer.valueOf(a - b);
            case Opcodes.IMUL: return Integer.valueOf(a * b);
            case Opcodes.IAND: return Integer.valueOf(a & b);
            case Opcodes.IOR: return Integer.valueOf(a | b);
            case Opcodes.IXOR: return Integer.valueOf(a ^ b);
            case Opcodes.ISHL: return Integer.valueOf(a << b);
            case Opcodes.ISHR: return Integer.valueOf(a >> b);
            case Opcodes.IUSHR: return Integer.valueOf(a >>> b);
            default: return null;
        }
    }

    private static AbstractInsnNode intPush(int v) {
        if (v == -1) return new InsnNode(Opcodes.ICONST_M1);
        if (v >= 0 && v <= 5) return new InsnNode(Opcodes.ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            return new IntInsnNode(Opcodes.BIPUSH, v);
        }
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            return new IntInsnNode(Opcodes.SIPUSH, v);
        }
        return new LdcInsnNode(Integer.valueOf(v));
    }

    private static void identities(InsnList list) {
        for (AbstractInsnNode ins = list.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            int op = ins.getOpcode();
            // DUP; POP
            if (op == Opcodes.POP) {
                AbstractInsnNode p = prevReal(ins);
                if (p != null && p.getOpcode() == Opcodes.DUP) {
                    list.remove(p);
                    list.remove(ins);
                    ins = next;
                    continue;
                }
                // const; POP
                if (p != null && (intConst(p) != null || p.getOpcode() == Opcodes.LCONST_0
                        || p.getOpcode() == Opcodes.LCONST_1
                        || p.getOpcode() == Opcodes.FCONST_0 || p.getOpcode() == Opcodes.FCONST_1
                        || p.getOpcode() == Opcodes.FCONST_2
                        || p.getOpcode() == Opcodes.DCONST_0 || p.getOpcode() == Opcodes.DCONST_1
                        || (p instanceof LdcInsnNode))) {
                    list.remove(p);
                    list.remove(ins);
                    ins = next;
                    continue;
                }
            }
            if (op == Opcodes.POP2) {
                AbstractInsnNode p = prevReal(ins);
                if (p != null && (p.getOpcode() == Opcodes.LCONST_0
                        || p.getOpcode() == Opcodes.LCONST_1
                        || p.getOpcode() == Opcodes.DCONST_0
                        || p.getOpcode() == Opcodes.DCONST_1)) {
                    list.remove(p);
                    list.remove(ins);
                    ins = next;
                    continue;
                }
            }
            // x op identity
            Integer right = identityRight(op);
            if (right != null) {
                AbstractInsnNode p = prevReal(ins);
                Integer c = intConst(p);
                if (c != null && c.intValue() == right.intValue()) {
                    list.remove(p);
                    list.remove(ins);
                    ins = next;
                    continue;
                }
            }
            ins = next;
        }
    }

    private static Integer identityRight(int op) {
        switch (op) {
            case Opcodes.IADD: return Integer.valueOf(0);
            case Opcodes.ISUB: return Integer.valueOf(0);
            case Opcodes.IMUL: return Integer.valueOf(1);
            case Opcodes.IAND: return Integer.valueOf(-1);
            case Opcodes.IOR: return Integer.valueOf(0);
            case Opcodes.IXOR: return Integer.valueOf(0);
            case Opcodes.LADD: return Integer.valueOf(0);
            default: return null;
        }
    }

    private static void removeGotoNext(InsnList list) {
        for (AbstractInsnNode ins = list.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            if (ins.getOpcode() == Opcodes.GOTO) {
                LabelNode target = ((JumpInsnNode) ins).label;
                AbstractInsnNode n = ins.getNext();
                while (n != null && (n instanceof LabelNode || n instanceof FrameNode
                        || n instanceof LineNumberNode)) {
                    if (n == target) {
                        list.remove(ins);
                        break;
                    }
                    n = n.getNext();
                }
            }
            ins = next;
        }
    }

    private static void deadCode(MethodNode mn) {
        Set<LabelNode> targets = new HashSet<LabelNode>();
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            if (ins instanceof JumpInsnNode) {
                targets.add(((JumpInsnNode) ins).label);
            }
        }
        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode t : mn.tryCatchBlocks) {
                if (t.start != null) targets.add(t.start);
                if (t.end != null) targets.add(t.end);
                if (t.handler != null) targets.add(t.handler);
            }
        }
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            int op = ins.getOpcode();
            if (op == Opcodes.GOTO || op == Opcodes.RETURN || op == Opcodes.ATHROW
                    || (op >= Opcodes.IRETURN && op <= Opcodes.ARETURN)) {
                AbstractInsnNode d = ins.getNext();
                while (d != null) {
                    if (d instanceof LabelNode && targets.contains(d)) {
                        break;
                    }
                    AbstractInsnNode dn = d.getNext();
                    mn.instructions.remove(d);
                    d = dn;
                }
                next = ins.getNext();
            }
            ins = next;
        }
    }
}
