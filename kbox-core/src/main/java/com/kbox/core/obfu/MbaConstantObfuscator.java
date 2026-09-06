package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.concurrent.ParallelClassProcessor;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.security.SecureRandom;
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
 * <p>Tiny constants ({@code ICONST_0..5}, {@code BIPUSH} small, loop counters) are
 * left untouched, mirroring {@link ConstantObfuscator}: rewriting them would bloat
 * hot paths and add noise without much benefit. The rewrite is stack-neutral
 * (push one int, consume nothing), so {@code COMPUTE_FRAMES} keeps frames valid.
 */
public final class MbaConstantObfuscator {

    private static final String TAG = "mbaconst";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final AtomicInteger rewritten = new AtomicInteger();

    /**
     * Per-thread RNG. {@link SecureRandom} seeds each thread's generator once so
     * every run (and every thread) produces different expression shapes, while a
     * plain {@link Random} keeps the hot synthesis loop cheap. Safe because each
     * worker thread uses its own instance.
     */
    private final ThreadLocal<Random> rngs = ThreadLocal.withInitial(() ->
            new Random(new SecureRandom().nextLong()));

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
        ParallelClassProcessor.processAll(graph, cfg, this::obfClass, cfg.getParallelThreads());
        KBoxLog.info(TAG, "Intertwined-expression encrypted " + rewritten.get()
                + " int constants (mbaConstants=" + level + ", maxDepth=" + maxDepth(level) + ")");
    }

    private static int maxDepth(int level) {
        // level 1 -> depth 3, level 2 -> depth 5: enough variety without bloat.
        return 1 + level * 2;
    }

    @SuppressWarnings("unchecked")
    private void obfClass(ClassNode cn) {
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            // Collect candidates first (iterate without mutating the list).
            List<AbstractInsnNode> targets = new ArrayList<>();
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
                int v = constantValue(ins);
                if (v == Integer.MIN_VALUE) continue;
                // Keep tiny constants / -1 (loop counters, flags) as-is.
                if (Math.abs(v) < 4 || v == -1) continue;
                targets.add(ins);
            }
            if (targets.isEmpty()) continue;
            for (AbstractInsnNode ins : targets) {
                int v = constantValue(ins);
                if (v == Integer.MIN_VALUE) continue;
                InsnList repl = ExpressionSynthesizer.synthesize(v, maxDepth(cfg.getMbaConstants()), rngs.get());
                mn.instructions.insertBefore(ins, repl);
                mn.instructions.remove(ins);
                rewritten.incrementAndGet();
            }
        }
    }

    /** Best-effort literal int constant of an instruction, or {@link Integer#MIN_VALUE}. */
    private static int constantValue(AbstractInsnNode ins) {
        int op = ins.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - Opcodes.ICONST_0;
        if (ins instanceof IntInsnNode) return ((IntInsnNode) ins).operand;
        if (ins instanceof LdcInsnNode && ((LdcInsnNode) ins).cst instanceof Integer)
            return (Integer) ((LdcInsnNode) ins).cst;
        return Integer.MIN_VALUE;
    }
}