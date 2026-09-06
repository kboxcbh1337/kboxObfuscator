package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.BitSet;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * S1 — kboxDedeobfShieldV1 method-body splitting + heterogeneous recombination.
 *
 * <p>Splits the straight-line body of an eligible method at a stack-empty "seam"
 * into two synthetic private static segment methods {@code seg0/seg1} in the same
 * class, threading a mutable shared {@code int[]} cache through both, then rewrites
 * the original method as a two-step recombiner:
 * {@code int[] c = new int[N]; seg0(args, c); return seg1(args, c);}.
 * The body no longer exists as a single continuous instruction list in any one
 * method — a decompiler must trace across three method boundaries through an
 * explicit cache frame to reconstruct the original data flow.
 *
 * <p><b>Safety gate.</b> A method is split only when every check below passes, so
 * the rewrite is exactly semantics-preserving and {@code COMPUTE_FRAMES} re-derives
 * every frame cleanly:
 * <ul>
 *   <li>{@code static}, straight-line: no jumps / table switches / exception
 *       handlers (a linear stack simulation is therefore exact);</li>
 *   <li>no two-slot (long/double) values anywhere — neither in the body nor in the
 *       parameters — so local slots == parameter positions and the depth model is
 *       trivial;</li>
 *   <li>a real stack-empty seam strictly inside the body;</li>
 *   <li>the locals <em>written</em> in the head segment and the locals <em>read</em>
 *       in the tail segment have an empty intersection, so no value is silently live
 *       across the split (params align by index; everything else is self-contained).</li>
 * </ul>
 * Irregular bodies are left untouched, keeping the pass honest and risk-free.
 */
public final class SegmentSplitObfuscator {

    private static final String TAG = "segsplit";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final AtomicInteger split = new AtomicInteger();

    public SegmentSplitObfuscator(ClassGraph graph, ProtectionConfig cfg) {
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
        int level = cfg.getMethodSplit();
        if (level <= 0) return;
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, cn -> {
            for (Object m : cn.methods) {
                MethodNode mn = (MethodNode) m;
                if (mn.instructions == null) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if ((mn.access & Opcodes.ACC_STATIC) == 0) continue;
                if (mn.name.equals("<clinit>") || mn.name.equals("<init>")) continue;
                trySplit(cn, mn);
            }
        }, cfg.getParallelThreads());
        KBoxLog.info(TAG, "S1 segment-split " + split.get() + " straight-line methods");
    }

    private void trySplit(ClassNode cn, MethodNode mn) {
        List<AbstractInsnNode> ins = linearList(mn.instructions);
        if (ins.size() < 6) return;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return;
        if (paramsHaveWide(mn.desc)) return;

        // -- eligibility: branchless / no two-slot values --
        for (AbstractInsnNode a : ins) {
            int op = a.getOpcode();
            if (op == -1) continue;
            if (a instanceof JumpInsnNode || op == Opcodes.GOTO
                    || a instanceof LookupSwitchInsnNode || a instanceof TableSwitchInsnNode) return;
            if (a instanceof VarInsnNode) {
                int vop = op;
                if ((vop >= Opcodes.LLOAD && vop <= Opcodes.DALOAD)) return;
                if ((vop >= Opcodes.ISTORE && vop <= Opcodes.ASTORE)
                        && (vop == Opcodes.LSTORE || vop == Opcodes.DSTORE)) return;
            }
            if (a instanceof LdcInsnNode && (((LdcInsnNode) a).cst instanceof Long
                    || ((LdcInsnNode) a).cst instanceof Double)) return;
            if (is2SlotOp(op)) return;
        }

        // -- linear stack depth, find genuine seam (depth==0 strictly inside) --
        int n = ins.size();
        int lo = Math.max(1, n / 3);
        int seam = -1;
        for (int i = lo; i < n - 1; i++) {
            int d = stackDepthAt(ins, i);
            if (d == 0) { seam = i; break; }
        }
        if (seam < 0) return;

        // -- cross-segment local dependency: written(head) ∩ read(tail) must be empty --
        BitSet writtenHead = new BitSet();
        BitSet readTail = new BitSet();
        for (int i = 0; i <= seam; i++) collectWritten(ins.get(i), writtenHead);
        for (int i = seam + 1; i < n; i++) collectRead(ins.get(i), readTail);
        writtenHead.and(readTail);
        if (!writtenHead.isEmpty()) return;

        // stash the param load opcodes & count
        int nArgs = staticArgCount(mn.desc);
        int cap = seam + 1;
        String cache = "c" + randomName(6);
        String seg0Name = "s0" + randomName(7);
        String seg1Name = "s1" + randomName(7);
        String segDesc = mn.desc.substring(mn.desc.indexOf('(')); // "(args)R"
        String seg0Desc = mn.desc.substring(0, mn.desc.indexOf(')') + 1) + "[I)V"; // (params,[I)V
        // seg1 returns same type: (params,[I)R
        String retType = mn.desc.substring(mn.desc.indexOf(')') + 1);

        cn.fields.add(new org.objectweb.asm.tree.FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, cache, "[I", null, null));

        // ---- seg0 = (params, [I)V : clone ins[0..seam] + RETURN ----
        MethodNode seg0 = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                seg0Name, seg0Desc, null, null);
        InsnList s0 = new InsnList();
        for (int i = 0; i <= seam; i++) s0.add(ins.get(i).clone(new java.util.HashMap<>()));
        s0.add(new InsnNode(Opcodes.RETURN));
        seg0.instructions = s0;
        seg0.maxStack = Math.max(4, nArgs + 2);
        seg0.maxLocals = nArgs + 2;
        cn.methods.add(seg0);

        // ---- seg1 = (params, [I)R : clone ins[seam+1 .. n-1] (ends with XRETURN) ----
        MethodNode seg1 = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                seg1Name, mn.desc.substring(0, mn.desc.indexOf(')') + 1) + "[I" + retType, null, null);
        InsnList s1 = new InsnList();
        for (int i = seam + 1; i < n; i++) s1.add(ins.get(i).clone(new java.util.HashMap<>()));
        seg1.instructions = s1;
        seg1.maxStack = Math.max(4, nArgs + 2);
        seg1.maxLocals = nArgs + 2;
        cn.methods.add(seg1);

        // ---- rewrite caller ----
        // int[] c = new int[cap];
        // seg0(args..., c);
        // seg1(args..., c);
        // <return as original>   (caller returns whichever type the method returned)
        InsnList caller = new InsnList();
        pushInt(caller, cap);
        caller.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        caller.add(new VarInsnNode(Opcodes.ASTORE, nArgs));           // c -> local nArgs
        List<Integer> loads = paramLoads(mn.desc, nArgs);
        for (int i = 0; i < nArgs; i++) caller.add(new VarInsnNode(loads.get(i), i));
        caller.add(new VarInsnNode(Opcodes.ALOAD, nArgs));
        caller.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, seg0Name, seg0Desc, false));
        for (int i = 0; i < nArgs; i++) caller.add(new VarInsnNode(loads.get(i), i));
        caller.add(new VarInsnNode(Opcodes.ALOAD, nArgs));
        caller.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, seg1Name,
                seg1.desc, false));
        if (retType.equals("V")) {
            caller.add(new InsnNode(Opcodes.RETURN));
        } else {
            caller.add(new InsnNode(returnInsn(retType)));
        }
        mn.instructions = caller;
        mn.maxStack = Math.max(4, nArgs + 2);
        mn.maxLocals = nArgs + 2;
        graph.markCfModified(cn.name);
        split.incrementAndGet();
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }

    // ---- utilities ----
    private static List<AbstractInsnNode> linearList(InsnList l) {
        List<AbstractInsnNode> out = new ArrayList<>();
        for (AbstractInsnNode it = l.getFirst(); it != null; it = it.getNext()) out.add(it);
        return out;
    }

    /** Cumulative operand-stack depth after executing ins[0..upto]. */
    private static int stackDepthAt(List<AbstractInsnNode> ins, int upto) {
        int d = 0;
        for (int i = 0; i <= upto; i++) d += stackEffect(ins.get(i));
        return d;
    }

    private static boolean paramsHaveWide(String desc) {
        if (desc == null || desc.indexOf(')') < 0) return false;
        String p = desc.substring(desc.indexOf('(') + 1, desc.indexOf(')'));
        for (int i = 0; i < p.length(); i++) {
            char ch = p.charAt(i);
            if (ch == 'J' || ch == 'D') return true;
            if (ch == 'L') { while (i + 1 < p.length() && p.charAt(i + 1) != ';') i++; }
        }
        return false;
    }

    private static int staticArgCount(String desc) {
        if (desc == null || desc.indexOf(')') < 0) return 0;
        String p = desc.substring(desc.indexOf('(') + 1, desc.indexOf(')'));
        int c = 0;
        for (int i = 0; i < p.length(); i++) {
            char ch = p.charAt(i);
            if (ch == '[') continue;
            c++;
            if (ch == 'L') { while (i + 1 < p.length() && p.charAt(i + 1) != ';') i++; }
        }
        return c;
    }

    /** Load opcode per parameter (1-slot only by gate). */
    private static List<Integer> paramLoads(String desc, int nArgs) {
        List<Integer> out = new ArrayList<>();
        if (desc == null || desc.indexOf(')') < 0) return out;
        String p = desc.substring(desc.indexOf('(') + 1, desc.indexOf(')'));
        for (int i = 0; i < p.length(); i++) {
            char ch = p.charAt(i);
            if (ch == '[') continue;
            switch (ch) {
                case 'L': out.add(Opcodes.ALOAD); while (i + 1 < p.length() && p.charAt(i + 1) != ';') i++; break;
                case 'I': case 'Z': case 'B': case 'C': case 'S': out.add(Opcodes.ILOAD); break;
                case 'F': out.add(Opcodes.FLOAD); break;
                default: break;
            }
            if (out.size() == nArgs) break;
        }
        return out;
    }

    private static int returnInsn(String retType) {
        switch (retType) {
            case "F": return Opcodes.FRETURN;
            case "J": case "D": return Opcodes.LRETURN; // excluded by gate, defensive
            case "V": return Opcodes.RETURN;
            default: return Opcodes.ARETURN;             // references start with L or [ or V
        }
    }

    private static void collectWritten(AbstractInsnNode a, BitSet set) {
        if (a instanceof VarInsnNode) {
            int op = a.getOpcode();
            if (op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) set.set(((VarInsnNode) a).var);
        }
        if (a instanceof org.objectweb.asm.tree.IincInsnNode) set.set(((org.objectweb.asm.tree.IincInsnNode) a).var);
    }

    private static void collectRead(AbstractInsnNode a, BitSet set) {
        if (a instanceof VarInsnNode) {
            int op = a.getOpcode();
            if (op >= Opcodes.ILOAD && op <= Opcodes.ALOAD) set.set(((VarInsnNode) a).var);
        }
        if (a instanceof org.objectweb.asm.tree.IincInsnNode) set.set(((org.objectweb.asm.tree.IincInsnNode) a).var);
    }

    private static boolean is2SlotOp(int op) {
        return op == Opcodes.LLOAD || op == Opcodes.DLOAD || op == Opcodes.LSTORE
                || op == Opcodes.DSTORE || op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1
                || op == Opcodes.DCONST_0 || op == Opcodes.DCONST_1 || op == Opcodes.LADD
                || op == Opcodes.LSUB || op == Opcodes.LMUL || op == Opcodes.LDIV
                || op == Opcodes.LREM || op == Opcodes.LNEG || op == Opcodes.DADD
                || op == Opcodes.DSUB || op == Opcodes.DMUL || op == Opcodes.DDIV
                || op == Opcodes.DREM || op == Opcodes.DNEG || op == Opcodes.RET
                || (op >= Opcodes.I2L && op <= Opcodes.F2D)
                || op == Opcodes.LCMP || op == Opcodes.DCMPL || op == Opcodes.DCMPG
                || op == Opcodes.LALOAD || op == Opcodes.DALOAD || op == Opcodes.LASTORE
                || op == Opcodes.DASTORE || op == Opcodes.LRETURN || op == Opcodes.DRETURN;
    }

    /** Net operand-stack delta for one instruction (1-slot, branchless). */
    private static int stackEffect(AbstractInsnNode a) {
        int op = a.getOpcode();
        if (op == -1) return 0;
        if (a instanceof org.objectweb.asm.tree.LabelNode || a instanceof org.objectweb.asm.tree.LineNumberNode
                || a instanceof org.objectweb.asm.tree.FrameNode) return 0;
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return 1;
        if (op == Opcodes.ACONST_NULL) return 1;
        if (a instanceof IntInsnNode) return 1;
        if (a instanceof LdcInsnNode) {
            Object c = ((LdcInsnNode) a).cst;
            return (c instanceof Long || c instanceof Double) ? 2 : 1;
        }
        if (a instanceof VarInsnNode) {
            int vop = op;
            if ((vop >= Opcodes.ILOAD && vop <= Opcodes.ALOAD)) return 1;
            if ((vop >= Opcodes.ISTORE && vop <= Opcodes.ASTORE)) return -1;
            return 0;
        }
        if (a instanceof FieldInsnNode) {
            int fop = op;
            if (fop == Opcodes.GETSTATIC) return 1;
            if (fop == Opcodes.PUTSTATIC) return -1;
            if (fop == Opcodes.GETFIELD) return 0;
            if (fop == Opcodes.PUTFIELD) return -2;
        }
        if (a instanceof MethodInsnNode) {
            int mop = op;
            MethodInsnNode mi = (MethodInsnNode) a;
            if (mop == Opcodes.INVOKESTATIC) return retSlots(mi.desc);
            if (mop == Opcodes.INVOKEVIRTUAL || mop == Opcodes.INVOKESPECIAL
                    || mop == Opcodes.INVOKEINTERFACE) return retSlots(mi.desc) - 1;
        }
        if (isArith2to1(op)) return -1;
        if (op == Opcodes.DUP || op == Opcodes.DUP_X1 || op == Opcodes.DUP_X2
                || op == Opcodes.DUP2 || op == Opcodes.DUP2_X1 || op == Opcodes.DUP2_X2) return 1;
        if (op == Opcodes.SWAP) return 0;
        if (op == Opcodes.POP || op == Opcodes.POP2) return -1;
        if (op >= Opcodes.IRETURN && op <= Opcodes.ARETURN) return -1;
        if (op == Opcodes.RETURN) return 0;
        return 0;
    }

    private static int retSlots(String d) {
        if (d == null || d.indexOf(')') < 0) return 0;
        String r = d.substring(d.indexOf(')') + 1);
        if (r.equals("V")) return 0;
        if (r.equals("J") || r.equals("D")) return 2;
        return 1;
    }

    private static boolean isArith2to1(int op) {
        return op == Opcodes.IADD || op == Opcodes.ISUB || op == Opcodes.IMUL
                || op == Opcodes.IDIV || op == Opcodes.IREM || op == Opcodes.IAND
                || op == Opcodes.IOR || op == Opcodes.IXOR || op == Opcodes.ISHL
                || op == Opcodes.ISHR || op == Opcodes.IUSHR || op == Opcodes.FCMPL
                || op == Opcodes.FCMPG;
    }
}