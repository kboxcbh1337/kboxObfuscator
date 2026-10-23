package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.concurrent.ParallelClassProcessor;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Intertwined-expression constant obfuscation.
 *
 * <p>Opt-in pass (config {@code mbaConstants}). Replaces inline {@code int}
 * "magic number" constants in method bodies with a {@link ExpressionSynthesizer
 * random, self-contained, verified expression tree} that produces the same value.
 *
 * <p>This complements {@link ConstantObfuscator} (the shared table decryptor). It
 * is intentionally the <em>alternative</em> mechanism: when {@code mbaConstants > 0}
 * the shared-decryptor pass is disabled and every constant is instead expanded
 * inline into a different random expression. Benefits:
 * <ul>
 *   <li><b>No shared signature</b> — there is no {@code _KboxConsts.I(...)} call-site
 *       to grep / script against, and no single table whose leak decrypts every
 *       constant at once.</li>
 *   <li><b>Heterogeneous</b> per instance — symbolic simplifiers / program synthesizers
 *       must tackle a fresh random tree for each constant instead of one known
 *       function, which is exactly the tactic hardened obfuscators use to defeat
 *       automated deobfuscation.</li>
 *   <li><b>Verified-correct</b> — every tree is check-evaluated before use.</li>
 * </ul>
 *
 * <p>KBX-STR-10 raised two limits of the original pass: it covered only
 * {@code int} constants whose trees were constant-only (foldable by one linear
 * pass). The pass now also rewrites {@code long} constants and, where the class
 * can host one, mixes a run-time {@code private static int} slot into half of the
 * int sites so a compile-time fold cannot recover the value from the tree alone.
 *
 * <p>Tiny constants ({@code ICONST_0..5}, {@code BIPUSH} small, loop counters) are
 * left untouched, mirroring {@link ConstantObfuscator}: rewriting them would bloat
 * hot paths and add noise without much benefit. The rewrite is stack-neutral
 * (push one value, consume nothing), so {@code COMPUTE_FRAMES} keeps frames valid.
 */
public final class MbaConstantObfuscator {

    private static final String TAG = "mbaconst";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final AtomicInteger rewritten = new AtomicInteger();
    private final AtomicInteger longRewritten = new AtomicInteger();
    private final AtomicInteger variableSites = new AtomicInteger();

    public MbaConstantObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        int level = cfg.getMbaConstants();
        if (level <= 0) {
            return; // opt-in only
        }
        rewritten.set(0);
        longRewritten.set(0);
        variableSites.set(0);
        ParallelClassProcessor.processAll(graph, cfg, this::obfClass, cfg.getParallelThreads());
        KBoxLog.info(TAG, "Intertwined-expression encrypted " + rewritten.get()
                + " int + " + longRewritten.get() + " long constants ("
                + variableSites.get() + " variable-bound sites, mbaConstants=" + level
                + ", maxDepth=" + maxDepth(level) + ")");
    }

    private static int maxDepth(int level) {
        // level 1 -> depth 3, level 2 -> depth 5: enough variety without bloat.
        return 1 + level * 2;
    }

    @SuppressWarnings("unchecked")
    private void obfClass(ClassNode cn) {
        // KBX-CF-18: deterministic per-class stream (reproducible build).
        Random rng = com.kbox.core.util.DetRandom.of("mba-const", cn.name);
        // KBX-STR-10: class-scoped run-time int slot for variable-bound MBA.
        String[] var = runtimeVar(cn);
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) continue;
            // JNIC/VMP targets are translated to the native interpreter, which
            // re-executes this method's bytecode. Its program model does not
            // reproduce every synthesized-expression opcode identically, so
            // rewriting their constants both wastes work (the body is replaced)
            // and produced WRONG results / hangs when combined with allMax.
            // Same rule {@link MbaRewriteObfuscator} already applies.
            if (isNativeOrVmpTarget(cn.name, mn.name, mn.desc)) continue;
            // Collect candidates first (iterate without mutating the list).
            List<AbstractInsnNode> intTargets = new ArrayList<>();
            List<AbstractInsnNode> longTargets = new ArrayList<>();
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
                int v = constantValue(ins);
                if (v != Integer.MIN_VALUE) {
                    // Keep tiny constants / -1 (loop counters, flags) as-is.
                    if (Math.abs(v) >= 4 && v != -1) intTargets.add(ins);
                    continue;
                }
                Long lv = longConstantValue(ins);
                if (lv != null && Math.abs(lv) >= 4) longTargets.add(ins);
            }
            for (AbstractInsnNode ins : intTargets) {
                int v = constantValue(ins);
                if (v == Integer.MIN_VALUE) continue;
                InsnList repl;
                if (var != null && rng.nextBoolean()) {
                    repl = ExpressionSynthesizer.synthesizeVarMba(v, var[0], var[1], rng);
                    variableSites.incrementAndGet();
                } else {
                    repl = ExpressionSynthesizer.synthesize(v, maxDepth(cfg.getMbaConstants()), rng);
                }
                mn.instructions.insertBefore(ins, repl);
                mn.instructions.remove(ins);
                rewritten.incrementAndGet();
            }
            for (AbstractInsnNode ins : longTargets) {
                Long lv = longConstantValue(ins);
                if (lv == null) continue;
                InsnList repl = ExpressionSynthesizer.synthesizeLong(
                        lv, maxDepth(cfg.getMbaConstants()), rng);
                mn.instructions.insertBefore(ins, repl);
                mn.instructions.remove(ins);
                longRewritten.incrementAndGet();
            }
        }
    }

    /**
     * KBX-STR-10: returns {@code {owner, fieldName}} of a run-time-bound
     * {@code static int} the synthesized expressions may read, or {@code null}.
     *
     * <p>Prefers an existing non-final static int field (its value is never a
     * ConstantValue). Otherwise a synthetic field is added and initialised at the
     * head of {@code <clinit>} from {@code System.nanoTime()}, so the value is
     * unknown until the class initialises. Interfaces/annotations are skipped
     * (their fields must be {@code public static final}) and so are classes whose
     * {@code <clinit>} is a JNIC/VMP target (that body is replaced later and the
     * initialiser would vanish).
     */
    @SuppressWarnings("unchecked")
    private String[] runtimeVar(ClassNode cn) {
        if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) return null;
        if (cn.name.endsWith("module-info")) return null;
        String clinitKey = ProtectionConfig.memberKey(cn.name, "<clinit>", "()V");
        if (cfg.getNativeMethods().contains(clinitKey) || cfg.getVmpMethods().contains(clinitKey)) {
            return null;
        }
        if (cn.fields != null) {
            for (FieldNode fn : (List<FieldNode>) cn.fields) {
                if ("I".equals(fn.desc)
                        && (fn.access & Opcodes.ACC_STATIC) != 0
                        && (fn.access & Opcodes.ACC_FINAL) == 0) {
                    return new String[]{cn.name, fn.name};
                }
            }
        }
        String fname = "k" + Integer.toHexString((int) com.kbox.core.util.DetRandom
                .derive("mba-const-field", cn.name) & 0xFFFFFF);
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

    /** True when this exact method is a selected JNIC/VMP target. */
    private boolean isNativeOrVmpTarget(String owner, String name, String desc) {
        String key = ProtectionConfig.memberKey(owner, name, desc);
        return cfg.getNativeMethods().contains(key) || cfg.getVmpMethods().contains(key);
    }

    /** Best-effort literal int constant of an instruction, or {@link Integer#MIN_VALUE}. */
    private static int constantValue(AbstractInsnNode ins) {
        int op = ins.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - Opcodes.ICONST_0;
        // Only the genuine int-push opcodes. IntInsnNode also covers NEWARRAY,
        // whose "operand" is an array type code (T_BOOLEAN=4 .. T_LONG=11): those
        // values slip past the abs(v)<4 filter below, so the old
        // "instanceof IntInsnNode" test replaced every array allocation with a
        // bare int expression. NEWARRAY pops a length and pushes a reference, so
        // dropping it left the operand stack unbalanced at return (+1) and made
        // the class unloadable — 92 classes of an 8.6k-class jar were rolled back
        // by the packaging verifier because of this.
        if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) return ((IntInsnNode) ins).operand;
        if (ins instanceof LdcInsnNode && ((LdcInsnNode) ins).cst instanceof Integer)
            return (Integer) ((LdcInsnNode) ins).cst;
        return Integer.MIN_VALUE;
    }

    /** KBX-STR-10: literal long constant ({@code LCONST_*} / {@code LDC Long}), or null. */
    private static Long longConstantValue(AbstractInsnNode ins) {
        int op = ins.getOpcode();
        if (op == Opcodes.LCONST_0) return 0L;
        if (op == Opcodes.LCONST_1) return 1L;
        if (ins instanceof LdcInsnNode && ((LdcInsnNode) ins).cst instanceof Long) {
            return (Long) ((LdcInsnNode) ins).cst;
        }
        return null;
    }
}
