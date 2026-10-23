package com.kbox.core.sedvx;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.obfu.ExpressionSynthesizer;
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
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * SED-VX part D/E: dependency-constrained weaving with a build seed.
 *
 * <p>Rewrites only the slices selected by {@link CriticalSlicer} and only the
 * value sites inside them, choosing a realization from
 * {@link RealizationPool} through a stream derived from
 * (buildSeed, "sedvx", class#method). The choice therefore differs per build
 * but is reproducible for a given seed — the "build diversification" half of
 * the design.
 *
 * <p>Each method is rewritten as a <em>transaction</em>: the body is cloned,
 * the clone is transformed and verified with ASM's {@code Analyzer}, and only a
 * fully verified clone is committed. A failed verification leaves the original
 * body untouched and is recorded in the report, which is the "refuse rather
 * than risk" rule from the design document.
 */
public final class SedVxWeaver {

    private SedVxWeaver() {}

    /** Result of one weaving run. */
    public static final class Stats {
        public int slicesRewritten;
        public int sitesDiffused;
        public int sitesRejected;
        public int verifyFailures;
        public final Map<String, Integer> realizationUse = new java.util.LinkedHashMap<>();
        public final List<String> rejected = new ArrayList<>();
        final Map<String, String[]> runtimeSlots = new HashMap<>();
    }

    /**
     * Weaves into {@code graph} in place.
     *
     * @param slices  ordered slices from {@link CriticalSlicer}
     * @param budget  maximum rewritten sites per method
     */
    public static Stats weave(ClassGraph graph, ProtectionConfig cfg,
                              List<SemanticAtlas.MethodInfo> slices, int budget) {
        Stats st = new Stats();
        int depth = 1 + Math.max(1, cfg.getSedVx()) * 2;
        for (SemanticAtlas.MethodInfo slice : slices) {
            ClassNode cn = graph.getClasses().get(slice.owner);
            if (cn == null) continue;
            MethodNode target = find(cn, slice.name, slice.desc);
            if (target == null || target.instructions == null) continue;
            if ((target.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) continue;
            if (isNativeOrVmpTarget(cfg, slice.owner, slice.name, slice.desc)) continue;
            // Framework-constrained classes still get their constants rewritten;
            // only the reflection/indy environment is a hard exclusion here.
            String[] slot = runtimeSlot(cn, cfg);
            Random rng = com.kbox.core.util.DetRandom.of("sedvx", slice.key());
            MethodNode work = cloneMethod(target);
            int[] applied = applyToBody(work, cn, slot, budget, depth, rng, st);
            if (applied[0] == 0) continue;
            if (!verify(work)) {
                st.verifyFailures++;
                st.sitesRejected += applied[0];
                if (st.rejected.size() < 40) {
                    st.rejected.add(slice.key() + " (verification failed, reverted "
                            + applied[0] + " site(s))");
                }
                continue;
            }
            // Commit the verified body.
            target.instructions = work.instructions;
            target.maxStack = work.maxStack;
            target.maxLocals = work.maxLocals;
            if (work.tryCatchBlocks != null) target.tryCatchBlocks = work.tryCatchBlocks;
            if (work.localVariables != null) target.localVariables = work.localVariables;
            st.slicesRewritten++;
            st.sitesDiffused += applied[0];
        }
        return st;
    }

    /** Rewrites value sites inside one (cloned) body. Returns {appliedCount}. */
    private static int[] applyToBody(MethodNode mn, ClassNode cn, String[] slot,
                                     int budget, int depth, Random rng, Stats st) {
        List<AbstractInsnNode> intSites = new ArrayList<>();
        List<AbstractInsnNode> longSites = new ArrayList<>();
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            int v = intConstant(ins);
            if (v != Integer.MIN_VALUE) {
                if (Math.abs(v) >= 4 && v != -1) intSites.add(ins);
                continue;
            }
            Long lv = longConstant(ins);
            if (lv != null && Math.abs(lv) >= 4) longSites.add(ins);
        }
        int applied = 0;
        for (AbstractInsnNode ins : intSites) {
            if (applied >= budget) break;
            int v = intConstant(ins);
            if (v == Integer.MIN_VALUE) continue;
            RealizationPool.Realization r = RealizationPool.pick(
                    RealizationPool.Kind.INT, slot != null, rng);
            InsnList repl;
            if (r == RealizationPool.Realization.VAR_MBA && slot != null) {
                repl = ExpressionSynthesizer.synthesizeVarMba(v, slot[0], slot[1], rng);
            } else {
                r = RealizationPool.Realization.CONST_TREE;
                repl = ExpressionSynthesizer.synthesize(v, depth, rng);
            }
            mn.instructions.insertBefore(ins, repl);
            mn.instructions.remove(ins);
            bump(st.realizationUse, r.id);
            applied++;
        }
        for (AbstractInsnNode ins : longSites) {
            if (applied >= budget) break;
            Long lv = longConstant(ins);
            if (lv == null) continue;
            InsnList repl = ExpressionSynthesizer.synthesizeLong(lv, depth, rng);
            mn.instructions.insertBefore(ins, repl);
            mn.instructions.remove(ins);
            bump(st.realizationUse, RealizationPool.Realization.LONG_TREE.id);
            applied++;
        }
        if (applied > 0 && mn.maxStack < 4) mn.maxStack = 4;
        return new int[]{applied};
    }

    private static void bump(Map<String, Integer> m, String k) {
        m.put(k, m.getOrDefault(k, 0) + 1);
    }

    private static boolean verify(MethodNode mn) {
        try {
            new Analyzer<BasicValue>(new BasicInterpreter()).analyze(mn.name, mn);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static MethodNode find(ClassNode cn, String name, String desc) {
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.name.equals(name) && mn.desc.equals(desc)) return mn;
        }
        return null;
    }

    private static boolean isNativeOrVmpTarget(ProtectionConfig cfg, String owner, String name, String desc) {
        String key = ProtectionConfig.memberKey(owner, name, desc);
        return cfg.getNativeMethods().contains(key) || cfg.getVmpMethods().contains(key);
    }

    /**
     * Returns {@code {owner, field}} of a run-time-bound static int the identity
     * can read, creating one when the class can host it (never interfaces,
     * annotations, module-info, or a class whose {@code <clinit>} is a JNIC/VMP
     * target).
     */
    @SuppressWarnings("unchecked")
    private static String[] runtimeSlot(ClassNode cn, ProtectionConfig cfg) {
        if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) return null;
        if (cn.name.endsWith("module-info")) return null;
        String clinitKey = ProtectionConfig.memberKey(cn.name, "<clinit>", "()V");
        if (cfg.getNativeMethods().contains(clinitKey) || cfg.getVmpMethods().contains(clinitKey)) {
            return null;
        }
        for (FieldNode fn : (List<FieldNode>) cn.fields) {
            if ("I".equals(fn.desc) && (fn.access & Opcodes.ACC_STATIC) != 0
                    && (fn.access & Opcodes.ACC_FINAL) == 0) {
                return new String[]{cn.name, fn.name};
            }
        }
        String fname = "s" + Integer.toHexString((int) com.kbox.core.util.DetRandom
                .derive("sedvx-slot", cn.name) & 0xFFFFFF);
        cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                fname, "I", null, null));
        MethodNode clinit = null;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if ("<clinit>".equals(mn.name) && "()V".equals(mn.desc)) { clinit = mn; break; }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions = new InsnList();
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            clinit.maxStack = 1;
            clinit.maxLocals = 0;
            cn.methods.add(clinit);
        }
        InsnList init = new InsnList();
        init.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/System", "nanoTime", "()J", false));
        init.add(new InsnNode(Opcodes.L2I));
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, fname, "I"));
        clinit.instructions.insert(init);
        if (clinit.maxStack < 2) clinit.maxStack = 2;
        return new String[]{cn.name, fname};
    }

    // ------------------------------------------------------------------
    //  Transactional cloning
    // ------------------------------------------------------------------

    private static MethodNode cloneMethod(MethodNode src) {
        MethodNode dst = new MethodNode(src.access, src.name, src.desc, src.signature,
                src.exceptions == null ? null : src.exceptions.toArray(new String[0]));
        Map<org.objectweb.asm.tree.LabelNode, org.objectweb.asm.tree.LabelNode> labelMap = new HashMap<>();
        for (AbstractInsnNode ins = src.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            if (ins instanceof org.objectweb.asm.tree.LabelNode) {
                labelMap.put((org.objectweb.asm.tree.LabelNode) ins, new org.objectweb.asm.tree.LabelNode());
            }
        }
        for (AbstractInsnNode ins = src.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            dst.instructions.add(ins.clone(labelMap));
        }
        if (src.tryCatchBlocks != null) {
            dst.tryCatchBlocks = new ArrayList<>();
            for (TryCatchBlockNode t : src.tryCatchBlocks) {
                dst.tryCatchBlocks.add(new TryCatchBlockNode(
                        labelMap.get(t.start), labelMap.get(t.end), labelMap.get(t.handler), t.type));
            }
        }
        if (src.localVariables != null) {
            dst.localVariables = new ArrayList<>();
            for (org.objectweb.asm.tree.LocalVariableNode lv : src.localVariables) {
                dst.localVariables.add(new org.objectweb.asm.tree.LocalVariableNode(
                        lv.name, lv.desc, lv.signature,
                        labelMap.get(lv.start), labelMap.get(lv.end), lv.index));
            }
        }
        dst.maxLocals = src.maxLocals;
        dst.maxStack = src.maxStack;
        return dst;
    }

    private static int intConstant(AbstractInsnNode ins) {
        int op = ins.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - Opcodes.ICONST_0;
        if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) return ((IntInsnNode) ins).operand;
        if (ins instanceof LdcInsnNode && ((LdcInsnNode) ins).cst instanceof Integer)
            return (Integer) ((LdcInsnNode) ins).cst;
        return Integer.MIN_VALUE;
    }

    private static Long longConstant(AbstractInsnNode ins) {
        int op = ins.getOpcode();
        if (op == Opcodes.LCONST_0) return 0L;
        if (op == Opcodes.LCONST_1) return 1L;
        if (ins instanceof LdcInsnNode && ((LdcInsnNode) ins).cst instanceof Long)
            return (Long) ((LdcInsnNode) ins).cst;
        return null;
    }
}
