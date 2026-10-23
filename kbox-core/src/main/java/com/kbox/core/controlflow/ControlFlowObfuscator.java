package com.kbox.core.controlflow;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.FileSelector;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.ClassWriter;
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
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Control-flow obfuscation. Two complementary techniques, both safe under
 * {@code COMPUTE_FRAMES}:
 *
 * <ol>
 *   <li><b>Opaque predicates</b>: insert {@code if (t*(t+1) % 2 != 0) goto bogus}
 *       where the predicate is provably always-false (a product of two
 *       consecutive ints is always even). The bogus branch is dead code that
 *       performs plausible arithmetic to confuse decompilers.</li>
 *   <li><b>Flattening</b>: for eligible methods (no exception handlers, every
 *       branch target has an empty operand stack) the body is rewritten into a
 *       state-machine driven by a {@code switch} on an int state variable,
 *       destroying the original block ordering.</li>
 * </ol>
 *
 * Methods that fail the eligibility check transparently fall back to opaque
 * predicates only, so the build never breaks.
 */
public final class ControlFlowObfuscator {

    private static final String TAG = "controlflow";

    /**
     * When {@code true}, per-file / per-method processing detail is emitted at
     * INFO level (always visible on the command line). When {@code false}, the
     * same detail goes to DEBUG level (only visible with {@code --verbose}).
     * Toggled on by the CLI flag {@code --debug-cf}.
     */
    static volatile boolean verboseCf = false;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private int predicatesInserted;
    private int methodsFlattened;
    private int methodsSkipped;
    private int substitutedThisClass;

    /** 条目 36: synthetic seed-derivation runtime class. All opaque predicates
     *  and CFG-junk conditions source their entropy through these statics so
     *  no direct System.nanoTime/currentTimeMillis/identityHashCode pattern
     *  survives in protected bodies. Injected into the graph and renamed/
     *  re-encrypted with everything else.
     *
     *  <p>Deliberately NOT named {@code com/kbox/runtime/_*}: that prefix is
     *  classified as "never loaded by the JVM" by the packager's COMPUTE_MAXS
     *  fallback, and this helper IS loaded at runtime — a frame-computation
     *  failure must stay visible instead of being silently serialized. */
    static final String SEED = "com/kbox/runtime/KboxCfSeedRt";

    public ControlFlowObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /** Enable per-file command-line debug for the control-flow phase. */
    public static void setVerboseCf(boolean v) { verboseCf = v; }

    /**
     * Emits a control-flow-phase log line. At INFO level when {@link #verboseCf}
     * is on (always visible on stdout); otherwise at DEBUG level.
     */
    private static void cfLog(String msg) {
        if (verboseCf) KBoxLog.info(TAG, msg);
        else KBoxLog.debug(TAG, msg);
    }

    public void obfuscate() {
        if (!cfg.isObfuscateControlFlow()) {
            KBoxLog.info(TAG, "Control flow obfuscation disabled");
            return;
        }
        // 条目 36: inject the seed-derivation helper BEFORE any class is
        // transformed. Opaque predicates then source their randomness through
        // _KboxCfSeed.now()/idh() instead of calling System.nanoTime /
        // currentTimeMillis / identityHashCode directly, so the classic
        // "INVOKESTATIC nanoTime; L2I; IREM" opaque-predicate signature no
        // longer exists in any protected method (and the helper itself gets
        // renamed + re-encrypted like every other graph class).
        ensureSeedClass();
        int total = graph.getClasses().size();
        int processed = 0;
        int skippedLibrary = 0;
        int failed = 0;
        long start = System.currentTimeMillis();
        KBoxLog.info(TAG, "Starting control-flow obfuscation: " + total
                + " classes, strength=" + cfg.getControlFlowStrength()
                + (verboseCf ? " [DEBUG-CF enabled: per-file output to stdout]" : ""));
        int thr = cfg.getParallelThreads();
        boolean parallelCf = (thr != 1) && total > 8;
        if (parallelCf) {
            // Deep speedup: control flow was the last heavy pass still running on
            // one core. Each class is transformed independently (graph + config
            // are read-only during CF), so the class list fans out over the
            // configured workers — 0 (default) = auto (CPU cores), 1 = force the
            // deterministic serial path below, N = fixed pool. Per-class
            // rollback + neverFail semantics are preserved inside
            // obfuscateClass(); every protected class is marked CF-modified so
            // the Packager recomputes frames (identical to the serial path,
            // which marks whenever any predicate/transform fired).
            final long pStart = System.currentTimeMillis();
            // Bound in-flight transformations: CF is memory-heavy (lazy rollback
            // deep-clone snapshots + COMPUTE_FRAMES validation buffers). Let the
            // pool fan out over all cores but only run ~4 concurrently, so a
            // 10k-class allMax run's peak transient heap stays bounded instead
            // of 16 simultaneous snapshots OOM-ing the heap.
            int cfConcurrent = Math.max(2, Math.min(4, cfg.getParallelThreads()));
            com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg,
                    cn -> {
                        try {
                            obfuscateClass(cn);
                        } catch (Throwable t) {
                            if (cfg.isNeverFail()) {
                                KBoxLog.warn(TAG, "Control-flow failed for " + cn.name + ": "
                                        + t.getClass().getSimpleName() + ": " + t.getMessage()
                                        + " — keeping original bytes (neverFail=true)");
                                return;
                            }
                            throw new com.kbox.core.KBoxException(
                                    "Control-flow obfuscation failed for " + cn.name, t);
                        }
                        graph.markCfModified(cn.name);
                    }, thr, cfConcurrent);
            double pSec = (System.currentTimeMillis() - pStart) / 1000.0;
            KBoxLog.info(TAG, "Control-flow obfuscation complete (parallel, pool=" + thr
                    + ") in " + pSec + "s over " + total + " classes at strength "
                    + cfg.getControlFlowStrength());
            return;
        }
        for (ClassNode cn : graph.getClasses().values()) {
            // Single canonical decision: library classes, KBox runtime, and
            // out-of-scope classes are skipped uniformly. Kept classes are
            // still body-protected (their names are preserved by renaming).
            if (!cfg.shouldProtectClass(cn.name)) {
                skippedLibrary++;
                cfLog("[skip] " + cn.name + " (library/skipped)");
                processed++;
                continue;
            }
            // Self-hosting guard: classes explicitly excluded from control flow
            // (e.g. the engine's own CFG/ASM-handling classes) are not flattened,
            // preventing COMPUTE_FRAMES corruption. All OTHER transforms still run.
            if (cfg.isExcludedFromControlFlow(cn.name)) {
                skippedLibrary++;
                cfLog("[skip] " + cn.name + " (excluded from control flow)");
                processed++;
                continue;
            }
            int beforePred = predicatesInserted;
            int beforeFlat = methodsFlattened;
            int beforeSkip = methodsSkipped;
            substitutedThisClass = 0;
            long classStart = System.currentTimeMillis();
            try {
                obfuscateClass(cn);
            } catch (Throwable t) {
                failed++;
                if (cfg.isNeverFail()) {
                    // Per-class failure must not abort the build: log and move on.
                    // The class retains its original (already-parsed) bytes,
                    // which the Packager will serialize normally.
                    KBoxLog.warn(TAG, "Control-flow failed for " + cn.name + ": "
                            + t.getClass().getSimpleName() + ": " + t.getMessage()
                            + " — keeping original bytes (neverFail=true)");
                } else {
                    throw new com.kbox.core.KBoxException(
                            "Control-flow obfuscation failed for " + cn.name, t);
                }
            }
            long classMs = System.currentTimeMillis() - classStart;
            int pred = predicatesInserted - beforePred;
            int flat = methodsFlattened - beforeFlat;
            int skip = methodsSkipped - beforeSkip;
            // Mark class as CF-modified if any predicates were injected or
            // methods were flattened (StackMapTable frames are now stale).
            if (pred > 0 || flat > 0 || substitutedThisClass > 0) {
                graph.markCfModified(cn.name);
            }
            // Per-class line: always visible with --debug-cf, else DEBUG level.
            cfLog(String.format("[%d/%d] %-60s methods=%-3d pred=%-2d flat=%-2d skip=%-2d %4dms",
                    processed + 1, total, cn.name,
                    cn.methods.size(), pred, flat, skip, classMs));
            processed++;
            if (processed % 20 == 0 || processed == total) {
                KBoxLog.progress(100 * processed / total,
                        "Obfuscated " + processed + "/" + total + " classes ("
                                + predicatesInserted + " pred, " + methodsFlattened + " flat, "
                                + methodsSkipped + " skip, " + skippedLibrary + " lib-skipped)");
            }
        }
        long elapsed = System.currentTimeMillis() - start;
        KBoxLog.info(TAG, "Control-flow obfuscation complete in " + (elapsed / 1000.0) + "s: "
                + predicatesInserted + " opaque predicates, flattened "
                + methodsFlattened + " methods, skipped " + methodsSkipped
                + " (ineligible), " + skippedLibrary + " library-skipped"
                + (failed > 0 ? ", " + failed + " failed (rolled back)" : "")
                + " at strength " + cfg.getControlFlowStrength());
    }

    /**
     * 条目 36: builds (once) the {@code _KboxCfSeed} runtime helper:
     * <ul>
     *   <li>{@code mix(I)I} — xorshift32 whitener,</li>
     *   <li>{@code now()I} — {@code mix((int) System.nanoTime())},</li>
     *   <li>{@code milli()I} — {@code mix((int) System.currentTimeMillis())},</li>
     *   <li>{@code idh()I} — {@code mix(System.identityHashCode(new Object()))}.</li>
     * </ul>
     * Pure Java, no native dependency, safe under JNIC/VMP selection (which
     * ran earlier in the pipeline so this class is never translated).
     */
    private void ensureSeedClass() {
        if (graph.getClasses().containsKey(SEED)) return;
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = SEED;
        cn.superName = "java/lang/Object";

        // static int mix(int x): xorshift32 — real deterministic arithmetic.
        MethodNode mix = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "mix", "(I)I", null, null);
        InsnList ml = mix.instructions;
        ml.add(new VarInsnNode(Opcodes.ILOAD, 0));
        ml.add(new InsnNode(Opcodes.DUP));
        ml.add(new IntInsnNode(Opcodes.BIPUSH, 13));
        ml.add(new InsnNode(Opcodes.ISHL));
        ml.add(new InsnNode(Opcodes.IXOR));
        ml.add(new InsnNode(Opcodes.DUP));
        ml.add(new IntInsnNode(Opcodes.SIPUSH, 17));
        ml.add(new InsnNode(Opcodes.IUSHR));
        ml.add(new InsnNode(Opcodes.IXOR));
        ml.add(new InsnNode(Opcodes.DUP));
        ml.add(new InsnNode(Opcodes.ICONST_5));
        ml.add(new InsnNode(Opcodes.ISHL));
        ml.add(new InsnNode(Opcodes.IXOR));
        ml.add(new InsnNode(Opcodes.IRETURN));
        cn.methods.add(mix);

        // static int now(): mix((int) System.nanoTime())
        cn.methods.add(seedMethod("now", "nanoTime"));
        // static int milli(): mix((int) System.currentTimeMillis())
        cn.methods.add(seedMethod("milli", "currentTimeMillis"));

        // static int idh(): mix(System.identityHashCode(new Object()))
        MethodNode idh = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "idh", "()I", null, null);
        InsnList il = idh.instructions;
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Object"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/System", "identityHashCode", "(Ljava/lang/Object;)I", false));
        il.add(callSeedMix());
        il.add(new InsnNode(Opcodes.IRETURN));
        cn.methods.add(idh);

        graph.getClasses().put(SEED, cn);
    }

    /** Builds {@code static int <name>(): mix((int) System.<jdk>())}. */
    private static MethodNode seedMethod(String name, String jdkMethod) {
        MethodNode m = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name, "()I", null, null);
        m.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/System", jdkMethod, jdkMethod.endsWith("Millis") ? "()J" : "()J", false));
        m.instructions.add(new InsnNode(Opcodes.L2I));
        m.instructions.add(callSeedMix());
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        return m;
    }

    private static MethodInsnNode callSeedMix() {
        return new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "mix", "(I)I", false);
    }

    @SuppressWarnings("unchecked")
    private void obfuscateClass(ClassNode cn) {
        // The seed helper must stay predicate-free: a predicate inside mix()
        // that calls idh() would recurse (idh -> mix -> predicate -> idh ...).
        if (SEED.equals(cn.name)) return;
        // PL-03: the exclusion gates MUST live here (single choke point). The
        // parallel path calls obfuscateClass directly and previously skipped
        // BOTH gates — excludeControlFlowPrefixes entries (Kotlin coroutine
        // state machines written by ModernStackAdapter, library class names)
        // were destructively flattened, while the log still reported them as
        // excluded. The serial path pre-checks too; duplicating the check here
        // makes every call site safe.
        if (!cfg.shouldProtectClass(cn.name) || cfg.isExcludedFromControlFlow(cn.name)) {
            return;
        }
        // Count methods that actually have code bodies.
        int methodCount = 0;
        List<MethodNode> methods = (List<MethodNode>) cn.methods;
        for (MethodNode mn : methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            methodCount++;
        }
        if (methodCount == 0) return;
        cfLog("  >> Processing class " + cn.name + " (" + methodCount + " methods with code)");
        // KBX-CF-18: per-class deterministic randomness. Every transform-shape
        // draw in this class comes from a stream derived from (buildSeed,
        // "cf", className), so the artifact no longer depends on thread count
        // or scheduling — the same input + config + seed reproduce it exactly.
        com.kbox.core.util.DetRandom crng = com.kbox.core.util.DetRandom.of("cf", cn.name);

        // Lazy snapshot: clone a method's instruction list ONLY right before it
        // is first mutated. If COMPUTE_FRAMES validation fails after CF
        // transforms, we restore these snapshots so the class retains valid
        // StackMapTable data. Classes where nothing changed skip both the
        // snapshot cost (a deep clone per method) and the validation cost (a
        // full COMPUTE_FRAMES serialization) entirely — on large jars the vast
        // majority of classes/methods fail eligibility and were paying both.
        Map<MethodNode, InsnList> originalInsns = new HashMap<>();
        Map<MethodNode, Integer> originalMaxLocals = new HashMap<>();
        Map<MethodNode, Integer> originalMaxStack = new HashMap<>();
        boolean mutated = false;

        for (MethodNode mn : methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            boolean isCtor = mn.name.charAt(0) == '<';
            int insnCount = mn.instructions.size();
            cfLog("    >> " + cn.name + "." + mn.name + mn.desc + " (insn=" + insnCount + ")");
            try {
                // JNIC-guard: methods selected for Java→native translation are
                // SKIPPED entirely here. They are translated (and their bytecode
                // cleared to ACC_NATIVE) at the later JNIC stage, so any
                // control-flow work done on them is wasted AND multiplies the
                // JNIC translator / gcc workload by the flattened instruction
                // count — the source of "JNIC 开启后 1 小时+" on large inputs.
                // (Same reasoning as the VMP-guard below, just skipping all CF.)
                boolean isJnicTarget = cfg.isEnableJnic()
                        && cfg.getNativeMethods()
                                .contains(com.kbox.core.config.ProtectionConfig
                                        .memberKey(cn.name, mn.name, mn.desc));
                if (isJnicTarget) {
                    methodsSkipped++;
                    cfLog("    << " + cn.name + "." + mn.name + mn.desc
                            + " [JNIC-target: skip CF]");
                    continue;
                }
                // MBA instruction substitution must run BEFORE opaque predicates
                // are injected: the predicates themselves contain balanced IADD
                // sequences (e.g. the MBA identity left - right computation).
                // Substituting those would corrupt the predicate's operand-stack
                // layout and produce an "Operand stack underflow" VerifyError.
                // Here we substitute on the clean original body only.
                if (!isCtor && cfg.getControlFlowStrength() >= 2) {
                    snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                    int n = substituteIAddMba(mn, cfg.getControlFlowStrength(), crng);
                    substitutedThisClass += n;
                    if (n > 0) mutated = true;
                }
                // Flatten BEFORE injecting opaque predicates. The predicates
                // contain internal branches (IFEQ/GOTO around a dead branch).
                // If the Flattener runs afterwards it treats those labels as
                // block boundaries and reorders/merges them, corrupting the
                // predicate's balanced operand stack (e.g. "Bad type on operand
                // stack: String not assignable to integer at iadd" on large
                // flattened methods). Injecting predicates into the already-
                // flattened switch is safe because every predicate is
                // net stack-neutral and inserted only at stack-producer points.
                //
                // VMP-guard: methods targeted by the VMP engine are NOT
                // flattened. VMP injection (pipeline stage 9) translates the
                // method AFTER control-flow obfuscation, and the flattened
                // dispatcher (a LOOKUPSWITCH state machine over id^mask) is
                // legal JVM, so translate() CAN consume it. But a full-strength
                // flatten multiplies the instruction count and introduces a
                // run-time dispatcher that the VMP translator must re-encode —
                // increasing the risk of a stack/register spill mismatch that
                // silently produces wrong VMP bytecode. To guarantee flatten
                // never corrupts VMP output, VMP targets keep their original
                // (pre-flatten) body and receive only the stack-neutral opaque
                // predicates below. Opaque predicates are verifier-safe (balanced
                // stack) and are what VMP re-encodes, exactly as designed.
                boolean flattened = false;
                boolean isVmpTarget = cfg.isEnableVmp()
                        && cfg.getVmpMethods()
                                .contains(com.kbox.core.config.ProtectionConfig
                                        .memberKey(cn.name, mn.name, mn.desc));
                // S6 EPL sweet-spot: flatten only when the real (non-label)
                // instruction count falls inside [flattenerMinInsns, flattenerMaxInsns].
                // A huge method risks StackMapTable precision blow-up; a tiny method
                // gains nothing from a dispatcher. This selects genuine business
                // methods (the classic "EPL" bandwidth) and bounds the switch size.
                if (!isCtor && !isVmpTarget && inFlattenWindow(mn)) {
                    snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                    flattened = Flattener.flatten(mn, cfg.getControlFlowStrength(), cn.name);
                    if (flattened) {
                        methodsFlattened++;
                        mutated = true;
                    } else {
                        methodsSkipped++;
                    }
                }
                int predBefore = predicatesInserted;
                // 条目 32/33/43: structural CFG deformation. All four run only
                // on NON-flattened bodies: a flattened body is already a
                // dispatcher state machine whose block layout is load-bearing
                // (relocating one of its blocks would interleave with the
                // dispatch table and the default thrower). VMP targets are
                // excluded as well — the native translator assumes the
                // original reducible body shape.
                if (!isCtor && !isVmpTarget && !flattened && !isJnicTarget) {
                    int st = cfg.getControlFlowStrength();
                    if (st >= 3) {
                        snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                        int n = injectCrossJumps(mn, crng);
                        substitutedThisClass += n;
                        if (n > 0) mutated = true;
                    }
                    if (st >= 2) {
                        snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                        int n = injectIrreducibleEdges(mn);
                        substitutedThisClass += n;
                        if (n > 0) mutated = true;
                        // Pseudo exception edges need handler-free methods and
                        // would make ExceptionJumpObfuscator skip the method.
                        if (!cfg.isExceptionJumpObf()) {
                            snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                            n = injectFakeExceptionEdges(mn);
                            substitutedThisClass += n;
                            if (n > 0) mutated = true;
                        }
                    }
                    if (st >= 3) {
                        snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                        int n = deformFrames(mn, crng);
                        substitutedThisClass += n;
                        if (n > 0) mutated = true;
                    }
                }
                // 条目 39: switch-key encryption (strength >= 2) — remap every
                // switch key through an injective runtime transform so the
                // decompiled switch shows unrelated constants.
                // 条目 40: loop-counter nonlinearization (strength >= 3) —
                // IINC becomes an equivalent non-linear arithmetic sequence.
                // Both are pure stack-neutral/local rewrites, safe under
                // COMPUTE_FRAMES, and must run BEFORE opaque predicates are
                // injected so the predicates' balanced IADD sequences are not
                // substituted/rewritten by anything downstream.
                if (!isJnicTarget) {
                    if (cfg.getControlFlowStrength() >= 2) {
                        snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                        int n = encryptSwitches(mn, crng);
                        substitutedThisClass += n;
                        if (n > 0) mutated = true;
                    }
                    if (cfg.getControlFlowStrength() >= 3) {
                        snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                        int n = encryptLoopCounters(mn, crng);
                        substitutedThisClass += n;
                        if (n > 0) mutated = true;
                    }
                }
                // KBX-CF-05: convert a few straight-line updates into a REAL
                // two-armed branch where BOTH arms contain live code (the same
                // update written in two different but equivalent encodings).
                // The old opaque predicates were single-in/single-out diamonds
                // whose dead arm had no observable effect and whose poison local
                // was zeroed at the merge — a constant folder could therefore
                // delete the dead edge in one pass. Here neither arm can be
                // dropped: removing either changes the program unless the
                // analyser first proves both arms equivalent.
                if (!isCtor && !isVmpTarget && !isJnicTarget
                        && cfg.getControlFlowStrength() >= 2) {
                    snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                    int nLive = injectLiveOpaqueBranches(mn, crng);
                    substitutedThisClass += nLive;
                    if (nLive > 0) mutated = true;
                }
                snapshotIfNeeded(mn, originalInsns, originalMaxLocals, originalMaxStack);
                injectOpaquePredicates(mn, isCtor ? 1 : cfg.getControlFlowStrength(), cn.name, cfg.getControlFlowStrength(), crng);
                if (predicatesInserted > predBefore) mutated = true;
                cfLog("    << " + cn.name + "." + mn.name + mn.desc
                        + " insn=" + insnCount
                        + (isCtor ? " [ctor: pred-only]" : "")
                        + (flattened ? " [FLATTENED]" : (!isCtor ? " [skip-flat]" : "")));
            } catch (Exception e) {
                KBoxLog.warn(TAG, "CF obfuscation failed for " + cn.name + "." + mn.name
                        + mn.desc + ": " + e.getMessage());
                java.io.StringWriter sw = new java.io.StringWriter();
                e.printStackTrace(new java.io.PrintWriter(sw));
                KBoxLog.warn(TAG, sw.toString());
            }
        }

        // Validate: can every method be serialized with COMPUTE_FRAMES?
        // Opaque predicates insert GOTO / IFNE instructions whose branch
        // targets require valid StackMapTable entries.  If COMPUTE_FRAMES
        // throws (NullPointerException from ASM's analyzer), the class
        // would fail JVM verification at runtime.  We roll back ALL CF
        // transforms for this class and keep the original bytecode.
        // (Skipped entirely when nothing was mutated: no frames went stale.)
        if (mutated && !validateClassForComputeFrames(cn)) {
            for (Map.Entry<MethodNode, InsnList> e : originalInsns.entrySet()) {
                MethodNode mn = e.getKey();
                mn.instructions = e.getValue();
                mn.maxLocals = originalMaxLocals.get(mn);
                mn.maxStack = originalMaxStack.get(mn);
            }
            cfLog("  << " + cn.name + " [CF-rollback: COMPUTE_FRAMES failed, "
                    + methodCount + " methods reverted to original]");
        }
    }

    /** Deep-clones {@code mn}'s instruction list into the rollback snapshots
     *  unless it was already snapshotted (lazy snapshot — see obfuscateClass). */
    private void snapshotIfNeeded(MethodNode mn,
                                  Map<MethodNode, InsnList> originalInsns,
                                  Map<MethodNode, Integer> originalMaxLocals,
                                  Map<MethodNode, Integer> originalMaxStack) {
        if (originalInsns.containsKey(mn)) return;
        originalInsns.put(mn, cloneInstructions(mn.instructions));
        originalMaxLocals.put(mn, mn.maxLocals);
        originalMaxStack.put(mn, mn.maxStack);
    }

    /** True when the method's real (non-label/frame/line) instruction count is
     *  inside the S6 flattener EPL window [flattenerMinInsns, flattenerMaxInsns].
     *  Escapes the precision blow-up of over-flattened huge switches while still
     *  selecting genuine business methods. */
    private boolean inFlattenWindow(MethodNode mn) {
        int minIns = cfg.getFlattenerMinInsns();
        int maxIns = cfg.getFlattenerMaxInsns();
        int n = 0;
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            if (ins.getOpcode() >= 0) n++; // skip labels(-1)/frames/line-numbers
            if (n > maxIns) return false;  // early out once past the upper bound
        }
        return n >= minIns;
    }

    /**
     * Deep-clones an instruction list, correctly remapping LabelNode and
     * FrameNode references.  This is critical for the snapshot / rollback
     * mechanism: without label remapping, the restored instructions would
     * reference stale LabelNode instances that no longer exist in the method.
     */
    private InsnList cloneInstructions(InsnList src) {
        Map<LabelNode, LabelNode> labelMap = new HashMap<>();
        // Pass 1: populate the label map.  Forward-jump targets may appear
        // AFTER the jump instruction, so we must map every LabelNode first.
        for (AbstractInsnNode insn = src.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labelMap.put((LabelNode) insn, new LabelNode());
            }
        }
        // Pass 2: clone with the fully-populated label map.
        InsnList dst = new InsnList();
        for (AbstractInsnNode insn = src.getFirst(); insn != null; insn = insn.getNext()) {
            dst.add(insn.clone(labelMap));
        }
        return dst;
    }

    /**
     * Tries to serialize the class with {@link ClassWriter#COMPUTE_FRAMES}.
     * Returns {@code true} if serialization succeeds without exceptions,
     * meaning all StackMapTable frames can be correctly computed.
     *
     * <p>Before serialization, existing {@link FrameNode} instances are
     * stripped from every method so that COMPUTE_FRAMES re-derives them
     * from scratch.  This catches cases where the CF transforms produced
     * instructions whose frame information is inconsistent or missing.
     */
    private boolean validateClassForComputeFrames(ClassNode cn) {
        // Strip all FrameNode instances so COMPUTE_FRAMES computes fresh frames.
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            Iterator<AbstractInsnNode> it = mn.instructions.iterator();
            while (it.hasNext()) {
                if (it.next() instanceof FrameNode) it.remove();
            }
        }
        try {
            // CF-03: graph-aware writer. The default getCommonSuperClass loads
            // types via the system classloader, so a branch join of two in-jar
            // types (`Object o = flag ? new A() : new B()`) threw and rolled
            // back the WHOLE class — the classic silent mass-no-protection
            // path. Resolve in-graph types from the ClassGraph instead and
            // only fall back to reflection for out-of-graph (JDK) types,
            // mirroring the Packager's writer.
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    if (type1.equals(type2)) return type1;
                    ClassNode n1 = graph.getClasses().get(type1);
                    ClassNode n2 = graph.getClasses().get(type2);
                    if (n1 != null && n2 != null) {
                        String a = type1, b = type2;
                        while (a != null) {
                            String t = b;
                            while (t != null) {
                                if (a.equals(t)) return a;
                                ClassNode tn = graph.getClasses().get(t);
                                t = tn == null ? null : tn.superName;
                            }
                            ClassNode an = graph.getClasses().get(a);
                            a = an == null ? null : an.superName;
                        }
                    }
                    try {
                        return super.getCommonSuperClass(type1, type2);
                    } catch (Throwable t) {
                        return "java/lang/Object";
                    }
                }
            };
            cn.accept(cw);
            cw.toByteArray();
            return true;
        } catch (Exception e) {
            cfLog("    [CF-validate] COMPUTE_FRAMES failed for " + cn.name
                    + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Inserts {@code count} opaque predicates at pseudo-random points in the
     * method.
     *
     * <p>At strength 1-2: uses simple predicates (t^2 mod 7 based)
     * with occasional runtime-bound IDENTITY_HASH predicates.
     * At strength 3: all predicates are runtime-bound, cycling through
     * IDENTITY_HASH and TIMING patterns.
     *
     * <p>Methods containing {@code NEW} instructions receive only simple
     * predicates to avoid uninitialized-object frame merge corruption.
     */
    private void injectOpaquePredicates(MethodNode mn, int count, String owner, int strength,
                                        com.kbox.core.util.DetRandom r) {
        int size = mn.instructions.size();
        if (size < 6) return;

        boolean hasAllocation = false;
        for (AbstractInsnNode insn = mn.instructions.getFirst();
             insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() == Opcodes.NEW) { hasAllocation = true; break; }
        }

        int tmp = mn.maxLocals;
        // tmp..tmp+2: predicate temps (POLY uses all three); tmp+3: poison
        // chain local (条目 35 interweaving — dead branches store into it and
        // the next predicate's always-true identity consumes it).
        mn.maxLocals = tmp + 4;
        boolean runtimePredicates = !hasAllocation && strength >= 3;
        // Predicate bodies peak at 5 operand slots (MBA: left operand held while
        // the right side needs 4). Section 42's simple predicate peaks at 2.
        // COMPUTE_MAXS recomputes the real value at packaging, but the tree-time
        // maxStack must stay sound for any analyzer that runs before it.
        if (runtimePredicates) {
            if (mn.maxStack < 6) mn.maxStack = 6;
        } else if (mn.maxStack < 2) {
            mn.maxStack = 2;
        }
        if (runtimePredicates) {
            // Zero-init the poison local at method entry. MBA/POLY conditions
            // READ it before any of their own stores execute (predicate
            // injection order is random), and ASM's Analyzer treats a
            // never-written local as UNINITIALIZED — CheckClassAdapter /
            // BasicVerifier would reject the method ("Expected I, but found
            // ."). A definite entry-store makes every read provably int.
            // Method entry always has an empty (or self-consistent) stack and
            // ICONST_0/ISTORE is stack-neutral, so this is verifier-safe.
            InsnList init = new InsnList();
            init.add(new InsnNode(Opcodes.ICONST_0));
            init.add(new VarInsnNode(Opcodes.ISTORE, tmp + 3));
            mn.instructions.insert(mn.instructions.getFirst(), init);
        }

        PredType[] types = PredType.values();
        int typeIdx = r.nextInt(types.length);

        for (int i = 0; i < count; i++) {
            AbstractInsnNode at = pickInsertionPoint(mn, r);
            if (at == null) break;

            InsnList block;
            if (hasAllocation || strength < 3) {
                // Simple predicate for methods with allocations, or low strength
                int t = r.nextInt(1, 1000000);
                block = buildSimplePredicate(t, tmp, r);
            } else {
                // Runtime-bound predicate, cycling through strategies
                PredType type = types[typeIdx % types.length];
                typeIdx++;
                block = buildOpaquePredicate(type, tmp, tmp + 3);
            }
            mn.instructions.insertBefore(at, block);
            predicatesInserted++;
        }
    }

    // ------------------------------------------------------------------
    // 条目 39: switch-key encryption
    // ------------------------------------------------------------------

    /**
     * Remaps every switch key through a per-site injective transform
     * {@code T(k) = ((k ^ m1) * a) + b} (m1/a/b random per switch, a odd), so
     * the key constants a decompiler shows are unrelated to the original
     * values. The transform is expanded inline before the switch:
     *
     * <pre>ISTORE s; ILOAD s; LDC m1; IXOR; LDC a; IMUL; LDC b; IADD; SWITCH(...)</pre>
     *
     * Each factor is bijective on ints (XOR: bijection; multiply by odd a:
     * bijection mod 2^32; add: bijection), so distinct keys stay distinct.
     *
     * <p>Small TABLESWITCHes (range &lt;= 64) are converted to sorted
     * LOOKUPSWITCHes because XOR breaks key contiguity. Large TABLESWITCHes
     * keep their table form under an affine-only transform {@code a*k+b}
     * (a &gt; 0, monotone) which preserves the contiguous range
     * {@code [a*min+b, a*max+b]}.
     */
    private int encryptSwitches(MethodNode mn, com.kbox.core.util.DetRandom r) {
        int n = 0;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                try {
                    int m1 = r.nextInt(1, Integer.MAX_VALUE);
                    int a = r.nextInt(1, 1 << 20) * 2 + 1; // odd → bijective
                    int b = r.nextInt(-1048576, 1048576);
                    java.util.TreeMap<Integer, LabelNode> map = new java.util.TreeMap<>();
                    boolean ok = ls.keys.size() == ls.labels.size();
                    for (int i = 0; ok && i < ls.keys.size(); i++) {
                        // injective transform → no collisions, but guard anyway
                        if (map.put(tKey(ls.keys.get(i), m1, a, b), ls.labels.get(i)) != null) ok = false;
                    }
                    if (ok) {
                        mn.instructions.insertBefore(insn, keyTransformSeq(m1, a, b, mn));
                        mn.instructions.insert(insn, toLookupSwitch(ls.dflt, map));
                        mn.instructions.remove(insn);
                        n++;
                    }
                } catch (Throwable ignore) { /* keep original switch */ }
            } else if (insn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                try {
                    // KBX-CF-06 / hang fix: compute the span in long. With
                    // min=Integer.MIN_VALUE and max=Integer.MAX_VALUE the int
                    // expression overflows to a small positive value, so the
                    // "range <= 64" branch was taken for a 2^32-entry switch and
                    // the per-key loop below ran ~4 billion times (observed as a
                    // build that spins at 100% CPU inside encryptSwitches).
                    long rangeL = (long) ts.max - (long) ts.min + 1L;
                    if (rangeL > 0 && rangeL <= 64) {
                        int m1 = r.nextInt(1, Integer.MAX_VALUE);
                        int a = r.nextInt(1, 1 << 20) * 2 + 1;
                        int b = r.nextInt(-1048576, 1048576);
                        java.util.TreeMap<Integer, LabelNode> map = new java.util.TreeMap<>();
                        for (int k = ts.min; k <= ts.max; k++) {
                            map.put(tKey(k, m1, a, b), ts.labels.get(k - ts.min));
                            if (map.size() > 64) break; // defensive: never loop huge
                        }
                        mn.instructions.insertBefore(insn, keyTransformSeq(m1, a, b, mn));
                        mn.instructions.insert(insn, toLookupSwitch(ts.dflt, map));
                        mn.instructions.remove(insn);
                        n++;
                    } else if (rangeL > 0 && rangeL <= 65536) {
                        // Large table: affine-only (a odd & > 0), no XOR — the
                        // key range stays contiguous: [a*min+b, a*max+b].
                        // CF-06: the transformed table holds a*range entries —
                        // an unrestricted a (up to 509) on a 65k switch emitted
                        // a 33M-entry table -> MethodTooLargeException -> the
                        // WHOLE class rolled back, losing all protection. Cap
                        // the blow-up at 4096 entries; beyond that a=1.
                        int aCap = Math.max(1, 4096 / (int) rangeL);
                        int a = aCap == 1 ? 1 : r.nextInt(0, aCap) * 2 + 1;
                        int b = r.nextInt(-1048576, 1048576);
                        long minP = (long) a * ts.min + b;
                        long maxP = (long) a * ts.max + b;
                        if (minP >= Integer.MIN_VALUE && maxP <= Integer.MAX_VALUE) {
                            mn.instructions.insertBefore(insn, keyTransformSeq(0, a, b, mn));
                            TableSwitchInsnNode repl = new TableSwitchInsnNode(
                                    (int) minP, (int) maxP, ts.dflt,
                                    ts.labels.toArray(new LabelNode[0]));
                            mn.instructions.insert(insn, repl);
                            mn.instructions.remove(insn);
                            n++;
                        }
                    }
                } catch (Throwable ignore) { /* keep original switch */ }
            }
            insn = next;
        }
        if (n > 0 && mn.maxStack < 2) mn.maxStack = 2;
        return n;
    }

    /** T(k) = ((k ^ m1) * a) + b — bijective on ints when a is odd. */
    private static int tKey(int k, int m1, int a, int b) {
        return ((k ^ m1) * a) + b;
    }

    /** Builds a sorted LOOKUPSWITCH node from the transformed key→label map. */
    private static LookupSwitchInsnNode toLookupSwitch(LabelNode dflt,
                                                       java.util.TreeMap<Integer, LabelNode> map) {
        int[] keys = new int[map.size()];
        LabelNode[] labels = new LabelNode[map.size()];
        int i = 0;
        for (java.util.Map.Entry<Integer, LabelNode> e : map.entrySet()) {
            keys[i] = e.getKey();
            labels[i] = e.getValue();
            i++;
        }
        return new LookupSwitchInsnNode(dflt, keys, labels);
    }

    /** Emits the inline key-transform sequence (skips XOR when m1 == 0). */
    private static InsnList keyTransformSeq(int m1, int a, int b, MethodNode mn) {
        int slot = mn.maxLocals++;
        InsnList l = new InsnList();
        l.add(new VarInsnNode(Opcodes.ISTORE, slot));
        l.add(new VarInsnNode(Opcodes.ILOAD, slot));
        if (m1 != 0) {
            l.add(new LdcInsnNode(m1));
            l.add(new InsnNode(Opcodes.IXOR));
        }
        l.add(new LdcInsnNode(a));
        l.add(new InsnNode(Opcodes.IMUL));
        l.add(new LdcInsnNode(b));
        l.add(new InsnNode(Opcodes.IADD));
        return l;
    }

    // ------------------------------------------------------------------
    // 条目 40: loop-counter nonlinearization
    // ------------------------------------------------------------------

    /**
     * Rewrites every {@code IINC var, c} into an equivalent arithmetic
     * sequence with a random odd multiplier K:
     *
     * <pre>i = i + c + (i * K) - (i * K)</pre>
     *
     * The two {@code i*K} terms are separate instruction sequences, so naive
     * CSE / pattern matchers read a non-linear counter update. Semantics are
     * bit-exact int arithmetic (no overflow hazard: the f-terms cancel).
     */
    private int encryptLoopCounters(MethodNode mn, com.kbox.core.util.DetRandom r) {
        int n = 0;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof IincInsnNode) {
                IincInsnNode inc = (IincInsnNode) insn;
                if (inc.incr != 0) {
                    int k = r.nextInt(3, 512) * 2 + 1; // odd
                    InsnList l = new InsnList();
                    l.add(new VarInsnNode(Opcodes.ILOAD, inc.var));
                    pushInt(l, inc.incr);
                    l.add(new InsnNode(Opcodes.IADD));
                    l.add(new VarInsnNode(Opcodes.ILOAD, inc.var));
                    pushInt(l, k);
                    l.add(new InsnNode(Opcodes.IMUL));
                    l.add(new InsnNode(Opcodes.IADD));
                    l.add(new VarInsnNode(Opcodes.ILOAD, inc.var));
                    pushInt(l, k);
                    l.add(new InsnNode(Opcodes.IMUL));
                    l.add(new InsnNode(Opcodes.ISUB));
                    l.add(new VarInsnNode(Opcodes.ISTORE, inc.var));
                    mn.instructions.insert(insn, l);
                    mn.instructions.remove(insn);
                    n++;
                }
            }
            insn = next;
        }
        if (n > 0) {
            // i + c + (i*K) - (i*K): peak depth 2 while IINC needed none.
            if (mn.maxStack < 2) mn.maxStack = 2;
        }
        return n;
    }

    // ------------------------------------------------------------------
    // 条目 32/33/43: cross jumps, fake exception edges, irreducible CFG,
    //               aggressive frame deformation
    // ------------------------------------------------------------------

    /**
     * 条目 33 (first half): block crossing. A whole basic block that ends in an
     * unconditional GOTO is lifted out of its original position and spliced
     * into the middle of an unrelated block, with the original position left
     * as a {@code GOTO moved} stub and the host block jumping over the
     * intruder:
     *
     * <pre>
     *   A: [A body] GOTO T          B: [B prefix] ...
     *   becomes
     *   A: GOTO A'                  B: [B prefix] GOTO B'
     *   ...                            A': [A body] GOTO T
     *                                  B': ...
     * </pre>
     *
     * Both stacks are empty at the split points (verified by a full height
     * walk), every label travels with its instructions, and no try/catch may
     * be present (a moved range would silently change the protected region).
     */
    private int injectCrossJumps(MethodNode mn, com.kbox.core.util.DetRandom r) {
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return 0;
        int total = mn.instructions.size();
        if (total < 12 || total > 900) return 0;
        int[] hgt = stackHeights(mn);
        if (hgt == null) return 0;
        AbstractInsnNode[] insns = mn.instructions.toArray();
        List<int[]> blocks = basicBlocks(mn, insns);
        if (blocks.size() < 3) return 0;
        // Deterministic candidate lists (random choice inside them) so the
        // transform actually fires on big if-chains instead of depending on
        // hitting the right block in a fixed number of random draws.
        List<int[]> sources = new ArrayList<>();   // [firstReal,lastReal] of GOTO-terminated blocks
        List<Integer> hosts = new ArrayList<>();   // first real instruction of each empty-stack block
        List<int[]> sourceRanges = new ArrayList<>();
        for (int[] blk : blocks) {
            int f = firstRealIndex(insns, blk[0], blk[1]);
            int l = lastRealIndex(insns, blk[0], blk[1]);
            if (f < 0 || l < 0) continue;
            if (hgt[f] == 0) hosts.add(f);
            if (insns[l].getOpcode() == Opcodes.GOTO && l - f >= 2) {
                sources.add(new int[]{f, l});
                sourceRanges.add(new int[]{f, l});
            }
        }
        if (sources.isEmpty() || hosts.isEmpty()) return 0;
        for (int attempt = 0; attempt < 12; attempt++) {
            int[] src = sources.get(r.nextInt(sources.size()));
            int firstReal = src[0], lastReal = src[1];
            int aStart = firstReal;
            int bFirst = hosts.get(r.nextInt(hosts.size()));
            boolean insideSource = false;
            for (int[] rng : sourceRanges) {
                if (bFirst >= rng[0] && bFirst <= rng[1]) { insideSource = true; break; }
            }
            if (insideSource) continue;
            if (bFirst == aStart) continue;
            // Lift [firstReal, lastReal] out of block A.
            InsnList moved = new InsnList();
            AbstractInsnNode n = insns[firstReal];
            AbstractInsnNode stop = insns[lastReal].getNext();
            while (n != null && n != stop) {
                AbstractInsnNode nx = n.getNext();
                mn.instructions.remove(n);
                moved.add(n);
                n = nx;
            }
            LabelNode movedLab = new LabelNode();
            moved.insert(movedLab);
            LabelNode cont = new LabelNode();
            InsnList seq = new InsnList();
            seq.add(new JumpInsnNode(Opcodes.GOTO, cont));
            seq.add(moved);
            seq.add(cont);
            mn.instructions.insertBefore(insns[bFirst], seq);
            // Original position: unconditional transfer to the relocated body.
            if (stop != null) {
                mn.instructions.insertBefore(stop, new JumpInsnNode(Opcodes.GOTO, movedLab));
            } else {
                mn.instructions.add(new JumpInsnNode(Opcodes.GOTO, movedLab));
            }
            cfLog("      cross-jump: block@" + aStart + " -> host@" + bFirst);
            return 1;
        }
        return 0;
    }

    /**
     * 条目 33 (second half): pseudo exception edge. Wraps the whole body in a
     * catch-all handler that simply rethrows the caught throwable. The
     * exception table gains an extra edge to a synthetic handler block, so
     * decompilers render a try/catch that exists only to obscure the CFG,
     * while runtime behaviour is bit-identical (same exception object, same
     * stack trace, same propagation).
     *
     * <p>Skipped for methods that already have handlers (range bookkeeping),
     * for methods containing {@code NEW} (uninitialized locals would degrade
     * to {@code top} on the handler edge), and for exception-jump targets
     * (that pass needs handler-free methods).
     */
    private int injectFakeExceptionEdges(MethodNode mn) {
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return 0;
        if (mn.instructions.size() < 8) return 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n.getOpcode() == Opcodes.NEW) return 0;
        }
        int slot = mn.maxLocals++;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        mn.instructions.insert(start);
        mn.instructions.add(end);
        mn.instructions.add(handler);
        mn.instructions.add(new VarInsnNode(Opcodes.ASTORE, slot));
        mn.instructions.add(new VarInsnNode(Opcodes.ALOAD, slot));
        mn.instructions.add(new InsnNode(Opcodes.ATHROW));
        mn.tryCatchBlocks = new java.util.ArrayList<>();
        mn.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(
                start, end, handler, "java/lang/Throwable"));
        if (mn.maxStack < 1) mn.maxStack = 1;
        cfLog("      fake-ex-edge: catch-all rethrow added (local " + slot + ")");
        return 1;
    }

    /**
     * KBX-CF-05: real (live) opaque branches.
     *
     * <p>The classic opaque predicate is a diamond whose dead arm has no
     * observable effect and whose poison local is reset at the merge point, so
     * a single constant-folding pass can delete the dead edge — the predicate
     * inflates the byte count without changing the recoverable CFG.
     *
     * <p>This transform instead rewrites a straight-line local update
     * ({@code IINC var, c}) into a genuinely two-armed branch selected by a
     * run-time condition, where BOTH arms perform the same update using
     * different encodings:
     * <pre>
     *   if (_KboxCfSeed.now() & 1 == 0) goto A
     *   var = var + c          // arm B (ILOAD/IADD/ISTORE)
     *   goto join
     * A: IINC var, c           // arm A (original encoding)
     * join:
     * </pre>
     * Neither edge can be removed by dead-code elimination (both carry live
     * writes) and the two encodings must be proven equivalent before the arms
     * can be merged, which is exactly the data-flow participation the audit
     * asked for. Restricted to handler-free methods, stack-neutral sites, and a
     * small budget so hot loops do not explode.
     */
    private int injectLiveOpaqueBranches(MethodNode mn, com.kbox.core.util.DetRandom r) {
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return 0;
        int total = mn.instructions.size();
        if (total < 10 || total > 1200) return 0;
        List<IincInsnNode> sites = new ArrayList<>();
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            if (ins instanceof IincInsnNode && ((IincInsnNode) ins).incr != 0) {
                sites.add((IincInsnNode) ins);
            }
        }
        if (sites.isEmpty()) return 0;
        int budget = Math.min(2, sites.size());
        int done = 0;
        for (int attempt = 0; attempt < budget * 3 && done < budget; attempt++) {
            IincInsnNode inc = sites.get(r.nextInt(sites.size()));
            if (inc.getOpcode() != Opcodes.IINC) continue; // already rewritten
            LabelNode armA = new LabelNode();
            LabelNode join = new LabelNode();
            InsnList pre = new InsnList();
            // Run-time bound selector: 50/50 at run time, opaque statically.
            pre.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "now", "()I", false));
            pre.add(new InsnNode(Opcodes.ICONST_1));
            pre.add(new InsnNode(Opcodes.IAND));
            pre.add(new JumpInsnNode(Opcodes.IFEQ, armA));
            // Arm B: same update, additive encoding.
            pre.add(new VarInsnNode(Opcodes.ILOAD, inc.var));
            pushInt(pre, inc.incr);
            pre.add(new InsnNode(Opcodes.IADD));
            pre.add(new VarInsnNode(Opcodes.ISTORE, inc.var));
            pre.add(new JumpInsnNode(Opcodes.GOTO, join));
            pre.add(armA);
            mn.instructions.insertBefore(inc, pre);
            mn.instructions.insert(inc, join);
            if (mn.maxStack < 2) mn.maxStack = 2;
            done++;
        }
        if (done > 0) cfLog("      live-opaque: " + done + " two-armed update branch(es)");
        return done;
    }

    /**
     * 条目 32: irreducible CFG. Prepends a small, genuinely executed
     * two-entry loop:
     *
     * <pre>
     *   if (_KboxCfSeed.idh() % 2 != 0) goto entry2
     *   entry1: t = 0; goto head
     *   entry2: t = 0; goto mid          &lt;- second entry into the loop body
     *   head:   t++
     *   mid:    if (t &lt; 2) goto head
     * </pre>
     *
     * {@code head} does not dominate {@code mid} (the entry2 edge reaches it
     * directly), so the loop is irreducible: dominance-tree based decompilers
     * (CFR/FernFlower) must fall back to labeled {@code while(true)} emission
     * or bail out. Unlike a dead-code region, BOTH entries are executed (the
     * branch depends on a runtime hash), so a decompiler cannot prune it by
     * constant folding. Semantics are unchanged: both entries initialise the
     * dedicated counter to 0 and the loop always terminates after two steps.
     */
    private int injectIrreducibleEdges(MethodNode mn) {
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return 0;
        int total = mn.instructions.size();
        if (total < 20 || total > 900) return 0;
        int t = mn.maxLocals++;
        LabelNode entry2 = new LabelNode();
        LabelNode entry1 = new LabelNode();
        LabelNode head = new LabelNode();
        LabelNode mid = new LabelNode();
        InsnList seq = new InsnList();
        seq.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "idh", "()I", false));
        seq.add(new InsnNode(Opcodes.ICONST_2));
        seq.add(new InsnNode(Opcodes.IREM));
        seq.add(new JumpInsnNode(Opcodes.IFNE, entry2));
        seq.add(new JumpInsnNode(Opcodes.GOTO, entry1));
        // Second entry: jumps straight into the loop body.
        seq.add(entry2);
        seq.add(new InsnNode(Opcodes.ICONST_0));
        seq.add(new VarInsnNode(Opcodes.ISTORE, t));
        seq.add(new JumpInsnNode(Opcodes.GOTO, mid));
        // First (header) entry.
        seq.add(entry1);
        seq.add(new InsnNode(Opcodes.ICONST_0));
        seq.add(new VarInsnNode(Opcodes.ISTORE, t));
        seq.add(head);
        seq.add(new IincInsnNode(t, 1));
        seq.add(mid);
        seq.add(new VarInsnNode(Opcodes.ILOAD, t));
        seq.add(new InsnNode(Opcodes.ICONST_2));
        seq.add(new JumpInsnNode(Opcodes.IF_ICMPLT, head));
        mn.instructions.insert(seq);
        if (mn.maxStack < 2) mn.maxStack = 2;
        cfLog("      irreducible: synthetic two-entry loop inserted (local " + t + ")");
        return 1;
    }

    /** Ensures {@code node} is preceded by a LabelNode and returns it. */
    private static LabelNode ensureLabel(MethodNode mn, AbstractInsnNode node) {
        AbstractInsnNode prev = node.getPrevious();
        if (prev instanceof LabelNode) return (LabelNode) prev;
        LabelNode l = new LabelNode();
        mn.instructions.insertBefore(node, l);
        return l;
    }

    /**
     * 条目 43: aggressive stack-map deformation. Splits a block with a
     * redundant {@code GOTO next} that targets the very next label. The JVM
     * requires a StackMapTable frame at every jump target, so each inserted
     * site forces an additional frame entry and an additional CFG edge that
     * carries no semantics — CFR/FernFlower must materialize an extra label
     * and {@code break}/{@code continue} structure for it, while the runtime
     * executes one extra resolved branch.
     */
    private int deformFrames(MethodNode mn, com.kbox.core.util.DetRandom r) {
        int total = mn.instructions.size();
        if (total < 10 || total > 1200) return 0;
        int[] hgt = stackHeights(mn);
        if (hgt == null) return 0;
        AbstractInsnNode[] insns = mn.instructions.toArray();
        List<int[]> blocks = basicBlocks(mn, insns);
        int budget = 2;
        int done = 0;
        for (int attempt = 0; attempt < 8 && done < budget; attempt++) {
            int[] blk = blocks.get(r.nextInt(blocks.size()));
            int f = firstRealIndex(insns, blk[0], blk[1]);
            if (f < 0 || hgt[f] != 0) continue;
            LabelNode here = ensureLabel(mn, insns[f]);
            InsnList seq = new InsnList();
            seq.add(new JumpInsnNode(Opcodes.GOTO, here));
            mn.instructions.insertBefore(here, seq);
            done++;
        }
        if (done > 0) cfLog("      frame-deform: " + done + " redundant frame edge(s)");
        return done;
    }

    /** Per-instruction operand-stack height, or {@code null} when any block
     *  boundary is non-empty (the transforms above require empty stacks). */
    private static int[] stackHeights(MethodNode mn) {
        AbstractInsnNode[] insns = mn.instructions.toArray();
        int total = insns.length;
        if (total == 0) return null;
        java.util.IdentityHashMap<AbstractInsnNode, Integer> pos = new java.util.IdentityHashMap<>();
        for (int i = 0; i < total; i++) pos.put(insns[i], i);
        boolean[] start = new boolean[total];
        start[0] = true;
        for (int i = 0; i < total; i++) {
            AbstractInsnNode n = insns[i];
            if (n instanceof JumpInsnNode) {
                Integer t = pos.get(((JumpInsnNode) n).label);
                if (t != null) start[t] = true;
            } else if (n instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode ts = (TableSwitchInsnNode) n;
                Integer t = pos.get(ts.dflt);
                if (t != null) start[t] = true;
                for (LabelNode l : ts.labels) {
                    Integer ti = pos.get(l);
                    if (ti != null) start[ti] = true;
                }
            } else if (n instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) n;
                Integer t = pos.get(ls.dflt);
                if (t != null) start[t] = true;
                for (LabelNode l : ls.labels) {
                    Integer ti = pos.get(l);
                    if (ti != null) start[ti] = true;
                }
            }
            int op = n.getOpcode();
            if (n instanceof JumpInsnNode || Flattener.isReturn(op) || op == Opcodes.ATHROW
                    || n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode) {
                int nx = i + 1;
                while (nx < total && insns[nx].getOpcode() == -1) nx++;
                if (nx < total) start[nx] = true;
            }
        }
        int[] h = new int[total];
        int cur = 0;
        for (int i = 0; i < total; i++) {
            if (start[i] && cur != 0) return null;
            h[i] = cur;
            cur += Flattener.stackEffect(insns[i]);
            if (cur < 0) return null;
        }
        return h;
    }

    /** Basic blocks as {@code [startIndex, endIndexExclusive)} pairs. */
    private static List<int[]> basicBlocks(MethodNode mn, AbstractInsnNode[] insns) {
        int total = insns.length;
        java.util.IdentityHashMap<AbstractInsnNode, Integer> pos = new java.util.IdentityHashMap<>();
        for (int i = 0; i < total; i++) pos.put(insns[i], i);
        boolean[] start = new boolean[total];
        start[0] = true;
        for (int i = 0; i < total; i++) {
            AbstractInsnNode n = insns[i];
            if (n instanceof JumpInsnNode) {
                Integer t = pos.get(((JumpInsnNode) n).label);
                if (t != null) start[t] = true;
            } else if (n instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode ts = (TableSwitchInsnNode) n;
                Integer t = pos.get(ts.dflt);
                if (t != null) start[t] = true;
                for (LabelNode l : ts.labels) {
                    Integer ti = pos.get(l);
                    if (ti != null) start[ti] = true;
                }
            } else if (n instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) n;
                Integer t = pos.get(ls.dflt);
                if (t != null) start[t] = true;
                for (LabelNode l : ls.labels) {
                    Integer ti = pos.get(l);
                    if (ti != null) start[ti] = true;
                }
            }
            int op = n.getOpcode();
            if (n instanceof JumpInsnNode || Flattener.isReturn(op) || op == Opcodes.ATHROW
                    || n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode) {
                int nx = i + 1;
                while (nx < total && insns[nx].getOpcode() == -1) nx++;
                if (nx < total) start[nx] = true;
            }
        }
        List<int[]> blocks = new ArrayList<>();
        int begin = -1;
        for (int i = 0; i < total; i++) {
            if (start[i]) {
                if (begin >= 0) blocks.add(new int[]{begin, i});
                begin = i;
            }
        }
        if (begin >= 0) blocks.add(new int[]{begin, total});
        return blocks;
    }

    private static int firstRealIndex(AbstractInsnNode[] insns, int from, int to) {
        for (int i = from; i < to; i++) {
            if (insns[i].getOpcode() >= 0) return i;
        }
        return -1;
    }

    private static int lastRealIndex(AbstractInsnNode[] insns, int from, int to) {
        for (int i = to - 1; i >= from; i--) {
            if (insns[i].getOpcode() >= 0) return i;
        }
        return -1;
    }

    /** Pushes an int constant with the tightest instruction form. */
    private static void pushInt(InsnList l, int v) {
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

    /**
     * Finds a safe insertion point for an opaque predicate. The predicate
     * pushes/pops on the operand stack, so it can only be inserted at points
     * where the stack is effectively empty OR where the following instruction
     * does not consume any values from the stack.
     *
     * <p>Safe insertion points:
     * <ul>
     *   <li>Before ICONST, BIPUSH, SIPUSH, LDC, ACONST_NULL — these push
     *       values but don't consume from the stack</li>
     *   <li>Before GETSTATIC — pushes static field, no consumption</li>
     * </ul>
     *
     * <p>EXPLICITLY EXCLUDED (even though stack-producer-only):
     * <ul>
     *   <li>NEW / NEWARRAY / ANEWARRAY — produce uninitialized references
     *       that are consumed by invokespecial &lt;init&gt; / array stores.
     *       Inserting a predicate between new and its initializer corrupts
     *       the uninitialized-object tracking in COMPUTE_FRAMES, producing
     *       "Bad type on operand stack" VerifyError.</li>
     * </ul>
     *
     * <p>UNSAFE insertion points (avoided):
     * <ul>
     *   <li>Before INVOKEVIRTUAL — expects arguments on stack</li>
     *   <li>Before IFxx — expects comparison operands</li>
     *   <li>Before PUTFIELD, IASTORE, AASTORE — expect values</li>
     *   <li>Before ARETURN, IRETURN, etc. — expect return value</li>
     *   <li>Between ALOAD and follow-up instruction — erases loaded value</li>
     * </ul>
     */
    private AbstractInsnNode pickInsertionPoint(MethodNode mn, com.kbox.core.util.DetRandom r) {
        int size = mn.instructions.size();
        int start = size / 3;
        int end = (size * 2) / 3;
        for (int tries = 0; tries < 16; tries++) {
            int idx = r.nextInt(start, Math.max(start + 1, end));
            AbstractInsnNode n = mn.instructions.get(idx);
            int op = n.getOpcode();

            // Skip labels, line numbers, frames.
            if (op == -1) continue;
            // Skip branches and returns.
            if (op == Opcodes.GOTO || op == Opcodes.RETURN || op == Opcodes.ATHROW
                    || op == Opcodes.IRETURN || op == Opcodes.LRETURN
                    || op == Opcodes.FRETURN || op == Opcodes.DRETURN
                    || op == Opcodes.ARETURN) continue;

            // Safe: instructions that don't consume from the stack.
            if (isStackProducerOnly(op)) return n;
        }
        return null;
    }

    /** Returns true if the given opcode pushes a value but never consumes from the stack. */
    private static boolean isStackProducerOnly(int op) {
        switch (op) {
            case Opcodes.ICONST_M1: case Opcodes.ICONST_0: case Opcodes.ICONST_1:
            case Opcodes.ICONST_2: case Opcodes.ICONST_3: case Opcodes.ICONST_4:
            case Opcodes.ICONST_5: case Opcodes.BIPUSH: case Opcodes.SIPUSH:
            case Opcodes.LDC: case Opcodes.ACONST_NULL: case Opcodes.FCONST_0:
            case Opcodes.FCONST_1: case Opcodes.FCONST_2: case Opcodes.LCONST_0:
            case Opcodes.LCONST_1: case Opcodes.DCONST_0: case Opcodes.DCONST_1:
            case Opcodes.GETSTATIC:
                return true;
            // NEW / NEWARRAY / ANEWARRAY are intentionally excluded:
            // they produce uninitialized-object references, and inserting
            // an opaque predicate before them corrupts the uninitialized-
            // object tracking in COMPUTE_FRAMES, causing "Bad type on
            // operand stack" VerifyError at invokespecial <init>.
            default: return false;
        }
    }

    /** Strategy enum for opaque predicate type selection (条目 34: 6 种策略). */
    private enum PredType { IDENTITY_HASH, TIMING, MBA, POLY, QUAD, XORCON }

    /**
     * Builds a runtime-bound opaque predicate selected by strategy type.
     *
     * <p>Unlike the textbook {@code t*(t+1)%2} pattern (trivially recognized
     * by CFR/Jadx), these predicates depend on runtime state that cannot be
     * folded by any static analyzer:
     *
     * <ul>
     *   <li><b>IDENTITY_HASH:</b> {@code System.identityHashCode(new Object()) % 2}
     *        — depends on heap allocator state, indeterminate statically.</li>
     *   <li><b>TIMING:</b> {@code (System.nanoTime() ^ tmp2) % 2}
     *        — nondeterministic; the branch is taken ~50% of the time at
     *        runtime, but both paths produce identical observable output
     *        (the dead branch contains compensating no-ops). Symbolic
     *        executors cannot prune either path.</li>
     *   <li><b>MBA:</b> Mixed Boolean-Arithmetic identity
     *        {@code (t + 1) == ((t ^ 1) + 2 * (t & 1))} — an instance of the
     *        classic {@code x + y == (x ^ y) + 2 * (x & y)} over integers,
     *        which ALWAYS holds. The predicate is therefore always-false
     *        (bogus branch is dead code), yet it is built from a mix of
     *        {@code +, ^, &, *} that defeats naive constant folding and
     *        simple pattern-matchers used by decompilers/optimizers.</li>
     * </ul>
     *
     * <p>The dead branch contains plausible junk that references the same
     * locals to confuse data-flow analysis, plus extra arithmetic on the
     * predicate result so it appears "used".
     */
    private InsnList buildOpaquePredicate(PredType type, int tmp, int poison) {
        InsnList l = new InsnList();
        // Runtime-bound condition computation → int on stack
        switch (type) {
            case IDENTITY_HASH:
                // 条目 36: int t = _KboxCfSeed.idh();  t % 2  [t==0 => even => IFEQ taken]
                // (identityHashCode of a fresh Object, whitened through the
                // synthetic helper — no recognizable JDK pattern remains).
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "idh", "()I", false));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new InsnNode(Opcodes.IREM));
                break;
            case TIMING:
                // 条目 36: int t = _KboxCfSeed.now() % 2 — nondeterministic;
                // both paths produce identical observable output.
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "now", "()I", false));
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new InsnNode(Opcodes.IREM));
                break;
            case MBA:
            default:
                // 条目 34 MBA（poison 交织版）：v = (t + 1 + p) - ((t ^ 1) + 2*(t & 1) + p)
                // 由恒等式 (x+y) == (x^y) + 2*(x&y)（x=t, y=1）知 v 恒为 0，
                // 且对任意 poison p 都成立 —— 死分支注入的 p 无法使谓词翻转。
                // 条目 36: seed via the synthetic helper (whitened time), then
                // mask to non-negative — POLY's Java-% sign argument requires
                // t >= 0 (t^5 - t must stay >= 0).
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "now", "()I", false));
                l.add(new LdcInsnNode(0x7fffffff));
                l.add(new InsnNode(Opcodes.IAND));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
                // left = t + 1 + p
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IADD));
                l.add(new VarInsnNode(Opcodes.ILOAD, poison));
                l.add(new InsnNode(Opcodes.IADD));
                // right = (t ^ 1) + 2*(t & 1) + p
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IXOR));
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IAND));
                l.add(new InsnNode(Opcodes.IMUL));
                l.add(new InsnNode(Opcodes.IADD));
                l.add(new VarInsnNode(Opcodes.ILOAD, poison));
                l.add(new InsnNode(Opcodes.IADD));
                // predicate = left - right  (always 0)
                l.add(new InsnNode(Opcodes.ISUB));
                break;
            case POLY:
                // 条目 34 POLY（poison 交织版）：
                //   v = ((t^5 - t) + 2p) % 10 - (2p) % 10   恒为 0
                // 由 t^5 ≡ t (mod 10)（Euler 定理），且死分支写入的 p 恒为非负
                // （&0x7F 后乘加），Java % 对同号被除数满足 (10k + a) % 10 == a % 10。
                // 条目 36: seed via the synthetic helper (whitened time), then
                // mask to non-negative — POLY's Java-% sign argument requires
                // t >= 0 (t^5 - t must stay >= 0).
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "now", "()I", false));
                l.add(new LdcInsnNode(0x7fffffff));
                l.add(new InsnNode(Opcodes.IAND));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
                // t2 = t*t ; t4 = t2*t2 ; t5 = t4*t
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.IMUL));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp + 1));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp + 1));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp + 1));
                l.add(new InsnNode(Opcodes.IMUL));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp + 2));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp + 2));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.IMUL));            // t^5
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));    // - t
                l.add(new InsnNode(Opcodes.ISUB));             // t^5 - t (>=0, ≡0 mod 10)
                l.add(new VarInsnNode(Opcodes.ILOAD, poison)); // + 2p
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new InsnNode(Opcodes.IMUL));
                l.add(new InsnNode(Opcodes.IADD));
                l.add(new IntInsnNode(Opcodes.BIPUSH, 10));
                l.add(new InsnNode(Opcodes.IREM));             // a = (t^5-t+2p)%10
                l.add(new VarInsnNode(Opcodes.ILOAD, poison)); // b = (2p)%10
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new InsnNode(Opcodes.IMUL));
                l.add(new IntInsnNode(Opcodes.BIPUSH, 10));
                l.add(new InsnNode(Opcodes.IREM));
                l.add(new InsnNode(Opcodes.ISUB));             // a - b == 0 恒成立
                break;
            case QUAD:
                // 条目 34 QUAD：数论恒假谓词。x² == 3y² - 1 无整数解：
                // 两边 mod 3，x² ∈ {0,1} 而 3y²-1 ≡ 2 (mod 3)，矛盾。
                // 取 x = t、y = t ^ 1（均为运行期种子），IFEQ 永不命中。
                // 条目 36: seed via the synthetic helper (whitened time), then
                // mask to non-negative — POLY's Java-% sign argument requires
                // t >= 0 (t^5 - t must stay >= 0).
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "now", "()I", false));
                l.add(new LdcInsnNode(0x7fffffff));
                l.add(new InsnNode(Opcodes.IAND));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
                // y = t ^ 1 → tmp+1
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IXOR));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp + 1));
                // v = x² - 3y² + 1   (never 0)
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.IMUL));             // x²
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp + 1));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp + 1));
                l.add(new InsnNode(Opcodes.IMUL));             // y²
                l.add(new InsnNode(Opcodes.ICONST_3));
                l.add(new InsnNode(Opcodes.IMUL));             // 3y²
                l.add(new InsnNode(Opcodes.ISUB));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IADD));
                break;
            case XORCON:
                // 条目 34 XORCON：t ^ (t+1) 恒为奇数（相邻整数最低位必相反），
                // 故 v = ((t ^ (t+1)) & 1) - 1 恒为 0。
                // 条目 36: seed via the synthetic helper (whitened time), then
                // mask to non-negative — POLY's Java-% sign argument requires
                // t >= 0 (t^5 - t must stay >= 0).
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "now", "()I", false));
                l.add(new LdcInsnNode(0x7fffffff));
                l.add(new InsnNode(Opcodes.IAND));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IADD));             // t+1
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));    // t
                l.add(new InsnNode(Opcodes.IXOR));             // t ^ (t+1) — always odd
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IAND));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.ISUB));             // always 0
                break;
        }
        // Branch: if condition == 0 → goto bogus
        LabelNode bogusBranch = new LabelNode();
        LabelNode endBranch = new LabelNode();
        l.add(new JumpInsnNode(Opcodes.IFEQ, bogusBranch));
        // fall-through: real code continues
        l.add(new JumpInsnNode(Opcodes.GOTO, endBranch));
        l.add(bogusBranch);
        // Dead branch (条目 35 poison 交织): the junk store makes this branch
        // LOOK live to data-flow analysis — the written value flows into the
        // NEXT predicate's always-true identity, which holds for any p >= 0,
        // so the dead edge can no longer be pruned as "no observable effect".
        // p is masked to 7 bits then linearly combined: always non-negative,
        // which the POLY identity's Java-% sign argument relies on. Seed source
        // is the synthetic helper (条目 36) — no direct nanoTime reference.
        l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, SEED, "now", "()I", false));
        l.add(new IntInsnNode(Opcodes.BIPUSH, 0x7F));
        l.add(new InsnNode(Opcodes.IAND));
        l.add(new InsnNode(Opcodes.ICONST_3));
        l.add(new InsnNode(Opcodes.IMUL));
        l.add(new InsnNode(Opcodes.ICONST_1));
        l.add(new InsnNode(Opcodes.IADD));
        l.add(new VarInsnNode(Opcodes.ISTORE, poison));
        // secondary junk (arithmetic that appears consumed)
        l.add(new InsnNode(Opcodes.ICONST_M1));
        l.add(new InsnNode(Opcodes.ICONST_1));
        l.add(new InsnNode(Opcodes.IADD));
        l.add(new InsnNode(Opcodes.POP));
        l.add(new JumpInsnNode(Opcodes.GOTO, endBranch));
        l.add(endBranch);
        // Merge point (both edges): real path resets poison to 0, so any later
        // predicate reads a value the identity holds for regardless of which
        // edge was taken at runtime.
        l.add(new InsnNode(Opcodes.ICONST_0));
        l.add(new VarInsnNode(Opcodes.ISTORE, poison));
        return l;
    }

    /** 条目 42: quadratic-residue table {modulus, non-residue}. For every
     *  entry, {@code t*t % m == r} is provably false for ALL ints (r is not a
     *  quadratic residue mod m) — varied per build so the fixed
     *  "t*t%7==3" textbook pattern can't be grepped. */
    private static final int[][] QR_PAIRS = {
            {5, 2}, {5, 3}, {7, 3}, {7, 5}, {7, 6},
            {11, 2}, {11, 6}, {11, 7}, {13, 2}, {13, 5}, {13, 6}, {13, 7},
    };

    /**
     * Builds the classic textbook predicate as a fallback for methods
     * that are too small to absorb the runtime-bound patterns. 条目 42: the
     * modulus / non-residue pair is randomized from the QR table above.
     */
    private InsnList buildSimplePredicate(int t, int tmp, com.kbox.core.util.DetRandom rr) {
        int[] pair = QR_PAIRS[rr.nextInt(QR_PAIRS.length)];
        int mod = pair[0], nonResidue = pair[1];
        InsnList l = new InsnList();
        l.add(new IntInsnNode(Opcodes.BIPUSH, t));
        l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
        l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
        l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
        l.add(new InsnNode(Opcodes.IMUL));          // t^2
        pushInt(l, mod);                            // mod
        l.add(new InsnNode(Opcodes.IREM));
        pushInt(l, nonResidue);
        LabelNode bogus = new LabelNode();
        LabelNode end = new LabelNode();
        l.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, bogus));  // t^2 % mod == nonResidue [never true]
        l.add(new JumpInsnNode(Opcodes.GOTO, end));
        l.add(bogus);
        l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
        l.add(new InsnNode(Opcodes.ICONST_3));
        l.add(new InsnNode(Opcodes.IMUL));
        l.add(new InsnNode(Opcodes.POP));
        l.add(new JumpInsnNode(Opcodes.GOTO, end));
        l.add(end);
        return l;
    }

    // ------------------------------------------------------------------
    // Instruction substitution (MBA arithmetic)
    // ------------------------------------------------------------------

    /**
     * Replaces up to {@code budget} {@code IADD} instructions with a provably
     * equivalent Mixed Boolean-Arithmetic (MBA) form:
     * <pre>
     *   x + y  ===  (x | y) + (x & y)
     * </pre>
     * Privacy: the identity holds in the ring Z/2^32 (Java int arithmetic), so
     * it is exact even with overflow. Static decompilers/optimizers cannot fold
     * the {@code |}+{@code &} form back into a plain {@code +} without a
     * rule-based MBA simplifier, which resists trivial pattern matching.
     *
     * <p>Implementation note: the two operands are already on the operand stack
     * when {@code IADD} executes, so we pop them into two fresh locals and
     * recompute {@code (x|y)+(x&amp;y)}. The stack effect (consume 2, push 1) is
     * identical, so {@code COMPUTE_FRAMES} frames stay valid. The substitution is
     * bounded (a few per method) to avoid pathological code bloat on hot paths.
     *
     * @param mn       the method to transform
     * @param budget   maximum number of IADD sites to substitute
     * @return the number of substitutions actually performed
     */
    private int substituteIAddMba(MethodNode mn, int budget, com.kbox.core.util.DetRandom r) {
        if (budget <= 0 || mn.instructions == null || mn.instructions.size() < 8) return 0;
        int done = 0;
        // Reserve one pair of fresh locals for the MBA temporaries. Use the
        // highest locals so they never alias the method's own variables.
        int tmpA = mn.maxLocals;
        int tmpB = mn.maxLocals + 1;
        // Collect candidate IADD nodes into a PLAIN list (not an InsnList).
        // An InsnList shares the very same AbstractInsnNode objects that live
        // in mn.instructions; when mn.instructions.remove(target) later severs
        // target.next/prev it silently corrupts an InsnList's internal linked
        // structure, leaving its size field stale so get() overruns the array
        // (ArrayIndexOutOfBoundsException: Index N out of bounds for length N).
        ArrayList<AbstractInsnNode> candidateTargets = new ArrayList<>();
        for (AbstractInsnNode insn = mn.instructions.getFirst();
             insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() == Opcodes.IADD) candidateTargets.add(insn);
        }
        if (candidateTargets.isEmpty()) return 0;
        // Randomly shuffle the candidate indices and take up to `budget`.
        int[] idx = new int[candidateTargets.size()];
        for (int i = 0; i < idx.length; i++) idx[i] = i;
        for (int i = idx.length - 1; i > 0; i--) {
            int j = r.nextInt(i + 1);
            int t = idx[i]; idx[i] = idx[j]; idx[j] = t;
        }
        int want = Math.min(budget, idx.length);
        for (int k = 0; k < want; k++) {
            AbstractInsnNode target = candidateTargets.get(idx[k]);
            if (target == null || target.getOpcode() != Opcodes.IADD) continue;
            InsnList mba = mbaAddSequence(tmpA, tmpB);
            mn.instructions.insertBefore(target, mba);
            mn.instructions.remove(target);
            done++;
        }
        if (done > 0) {
            mn.maxLocals += 2;
            // The MBA sequence's peak operand depth is 3 (load x,y → or → load
            // x,y), one slot deeper than the IADD it replaces. Without this the
            // stale maxStack makes ASM's Analyzer throw "Insufficient maximum
            // stack size" in later phases (e.g. the flattener's local-state
            // analysis), silently disabling flattening for every method that
            // received an MBA substitution. COMPUTE_MAXS recomputes it anyway,
            // but the tree-time value must stay sound for analyzers.
            if (mn.maxStack < 3) mn.maxStack = 3;
            KBoxLog.debug(TAG, "    [subst] " + mn.name + mn.desc + ": "
                    + done + " IADD -> (x|y)+(x&y) MBA substitution");
        }
        return done;
    }

    /**
     * Emits the MBA replacement for one {@code IADD}, given two fresh locals.
     * Assumes the two int operands {@code x, y} are on the operand stack
     * (y on top). Produces {@code (x|y)+(x&amp;y)} on the stack.
     */
    private InsnList mbaAddSequence(int tmpA, int tmpB) {
        InsnList l = new InsnList();
        l.add(new VarInsnNode(Opcodes.ISTORE, tmpB));   // y -> tmpB
        l.add(new VarInsnNode(Opcodes.ISTORE, tmpA));   // x -> tmpA
        l.add(new VarInsnNode(Opcodes.ILOAD, tmpA));    // x
        l.add(new VarInsnNode(Opcodes.ILOAD, tmpB));    // x, y
        l.add(new InsnNode(Opcodes.IOR));               // x|y
        l.add(new VarInsnNode(Opcodes.ILOAD, tmpA));    // x|y, x
        l.add(new VarInsnNode(Opcodes.ILOAD, tmpB));    // x|y, x, y
        l.add(new InsnNode(Opcodes.IAND));              // x|y, x&y
        l.add(new InsnNode(Opcodes.IADD));              // (x|y)+(x&y)
        return l;
    }
}
