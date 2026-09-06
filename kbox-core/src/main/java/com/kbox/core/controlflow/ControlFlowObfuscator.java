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
        int total = graph.getClasses().size();
        int processed = 0;
        int skippedLibrary = 0;
        int failed = 0;
        long start = System.currentTimeMillis();
        KBoxLog.info(TAG, "Starting control-flow obfuscation: " + total
                + " classes, strength=" + cfg.getControlFlowStrength()
                + (verboseCf ? " [DEBUG-CF enabled: per-file output to stdout]" : ""));
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

    @SuppressWarnings("unchecked")
    private void obfuscateClass(ClassNode cn) {
        // Count methods that actually have code bodies.
        int methodCount = 0;
        List<MethodNode> methods = (List<MethodNode>) cn.methods;
        for (MethodNode mn : methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            methodCount++;
        }
        if (methodCount == 0) return;
        cfLog("  >> Processing class " + cn.name + " (" + methodCount + " methods with code)");

        // Snapshot every method's instruction list BEFORE any mutation.
        // If COMPUTE_FRAMES validation fails after CF transforms, we restore
        // these snapshots so the class retains valid StackMapTable data.
        Map<MethodNode, InsnList> originalInsns = new HashMap<>();
        Map<MethodNode, Integer> originalMaxLocals = new HashMap<>();
        Map<MethodNode, Integer> originalMaxStack = new HashMap<>();
        for (MethodNode mn : methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            originalInsns.put(mn, cloneInstructions(mn.instructions));
            originalMaxLocals.put(mn, mn.maxLocals);
            originalMaxStack.put(mn, mn.maxStack);
        }

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
                    substitutedThisClass += substituteIAddMba(mn, cfg.getControlFlowStrength());
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
                // methods (the ZKM-style "EPL" bandwidth) and bounds the switch size.
                if (!isCtor && !isVmpTarget && inFlattenWindow(mn)) {
                    flattened = Flattener.flatten(mn, cfg.getControlFlowStrength());
                    if (flattened) {
                        methodsFlattened++;
                    } else {
                        methodsSkipped++;
                    }
                }
                injectOpaquePredicates(mn, isCtor ? 1 : cfg.getControlFlowStrength(), cn.name, cfg.getControlFlowStrength());
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
        if (!validateClassForComputeFrames(cn)) {
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
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
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
    private void injectOpaquePredicates(MethodNode mn, int count, String owner, int strength) {
        int size = mn.instructions.size();
        if (size < 6) return;

        boolean hasAllocation = false;
        for (AbstractInsnNode insn = mn.instructions.getFirst();
             insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() == Opcodes.NEW) { hasAllocation = true; break; }
        }

        ThreadLocalRandom r = ThreadLocalRandom.current();
        int tmp = mn.maxLocals;
        mn.maxLocals = tmp + 3;  // extra locals for runtime-bound predicates (POLY uses tmp..tmp+2)

        PredType[] types = PredType.values();
        int typeIdx = r.nextInt(types.length);

        for (int i = 0; i < count; i++) {
            AbstractInsnNode at = pickInsertionPoint(mn, r);
            if (at == null) break;

            InsnList block;
            if (hasAllocation || strength < 3) {
                // Simple predicate for methods with allocations, or low strength
                int t = r.nextInt(1, 1000000);
                block = buildSimplePredicate(t, tmp);
            } else {
                // Runtime-bound predicate, cycling through strategies
                PredType type = types[typeIdx % types.length];
                typeIdx++;
                block = buildOpaquePredicate(type, tmp);
            }
            mn.instructions.insertBefore(at, block);
            predicatesInserted++;
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
    private AbstractInsnNode pickInsertionPoint(MethodNode mn, ThreadLocalRandom r) {
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

    /** Strategy enum for opaque predicate type selection. */
    private enum PredType { IDENTITY_HASH, TIMING, MBA, POLY }

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
    private InsnList buildOpaquePredicate(PredType type, int tmp) {
        InsnList l = new InsnList();
        // Runtime-bound condition computation → int on stack
        switch (type) {
            case IDENTITY_HASH:
                // int t = System.identityHashCode(new Object());  t % 2  [t==0 => even => IFEQ taken]
                l.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Object"));
                l.add(new InsnNode(Opcodes.DUP));
                l.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "identityHashCode", "(Ljava/lang/Object;)I", false));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new InsnNode(Opcodes.IREM));
                break;
            case TIMING:
                // int t = (int)(System.nanoTime() & 1);
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false));
                l.add(new InsnNode(Opcodes.LCONST_1));
                l.add(new InsnNode(Opcodes.LAND));
                l.add(new InsnNode(Opcodes.L2I));
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new InsnNode(Opcodes.IREM));
                break;
            case MBA:
            default:
                // Custom MBA predicate: predicate = ((t ^ 1) + 2*(t & 1)) - (t + 1)
                // By the identity (x+y) == (x^y)+2*(x&y) with x=t, y=1, this equals 0 always.
                // t = (int)(System.currentTimeMillis() & 0x7fffffff) — a runtime seed.
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/System", "currentTimeMillis", "()J", false));
                l.add(new LdcInsnNode(0x7fffffffL));
                l.add(new InsnNode(Opcodes.LAND));
                l.add(new InsnNode(Opcodes.L2I));
                l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
                // left = t + 1
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IADD));
                // right = (t ^ 1) + 2*(t & 1)
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IXOR));
                l.add(new InsnNode(Opcodes.ICONST_2));
                l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
                l.add(new InsnNode(Opcodes.ICONST_1));
                l.add(new InsnNode(Opcodes.IAND));
                l.add(new InsnNode(Opcodes.IMUL));
                l.add(new InsnNode(Opcodes.IADD));
                // predicate = left - right  (always 0)
                l.add(new InsnNode(Opcodes.ISUB));
                break;
            case POLY:
                // Polynomial identity over ints, runtime seed t:
                //   p = (t^5 - t) mod 10   == 0   (Euler/totient: t^5 ≡ t mod 10)
                // t = (int)(System.currentTimeMillis() & 0x7fffffff)
                l.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/System", "currentTimeMillis", "()J", false));
                l.add(new LdcInsnNode(0x7fffffffL));
                l.add(new InsnNode(Opcodes.LAND));
                l.add(new InsnNode(Opcodes.L2I));
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
                l.add(new InsnNode(Opcodes.ISUB));             // t^5 - t
                l.add(new IntInsnNode(Opcodes.BIPUSH, 10));
                l.add(new InsnNode(Opcodes.IREM));             // mod 10 -> always 0
                break;
        }
        // Branch: if condition == 0 → goto bogus
        LabelNode bogusBranch = new LabelNode();
        LabelNode endBranch = new LabelNode();
        l.add(new JumpInsnNode(Opcodes.IFEQ, bogusBranch));
        // fall-through: real code continues
        l.add(new JumpInsnNode(Opcodes.GOTO, endBranch));
        l.add(bogusBranch);
        // Dead branch: plausible junk (self-contained, no locals)
        l.add(new InsnNode(Opcodes.ICONST_3));
        l.add(new InsnNode(Opcodes.ICONST_5));
        l.add(new InsnNode(Opcodes.IADD));
        l.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        l.add(new InsnNode(Opcodes.IMUL));
        l.add(new InsnNode(Opcodes.POP));
        // secondary junk
        l.add(new InsnNode(Opcodes.ICONST_M1));
        l.add(new InsnNode(Opcodes.ICONST_1));
        l.add(new InsnNode(Opcodes.IADD));
        l.add(new InsnNode(Opcodes.POP));
        l.add(new JumpInsnNode(Opcodes.GOTO, endBranch));
        l.add(endBranch);
        return l;
    }

    /**
     * Builds the classic textbook predicate as a fallback for methods
     * that are too small to absorb the runtime-bound patterns.
     */
    private InsnList buildSimplePredicate(int t, int tmp) {
        InsnList l = new InsnList();
        l.add(new IntInsnNode(Opcodes.BIPUSH, t));
        l.add(new VarInsnNode(Opcodes.ISTORE, tmp));
        // Quadratic-residue pattern: t^2 mod 7 [never 3,5,6 for small t]
        // more opaque than t*(t+1)%2 which CFR recognizes
        l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
        l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
        l.add(new InsnNode(Opcodes.IMUL));          // t^2
        l.add(new IntInsnNode(Opcodes.BIPUSH, 7));  // mod 7
        l.add(new InsnNode(Opcodes.IREM));
        l.add(new IntInsnNode(Opcodes.BIPUSH, 3));
        LabelNode bogus = new LabelNode();
        LabelNode end = new LabelNode();
        l.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, bogus));  // t^2 % 7 == 3 [never true]
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
    private int substituteIAddMba(MethodNode mn, int budget) {
        if (budget <= 0 || mn.instructions == null || mn.instructions.size() < 8) return 0;
        ThreadLocalRandom r = ThreadLocalRandom.current();
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
