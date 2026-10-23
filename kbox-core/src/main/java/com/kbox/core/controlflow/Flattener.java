package com.kbox.core.controlflow;

import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Conservative control-flow flattener. Rewrites an eligible method's body into a
 * state-machine driven by {@code switch(state)} so the original block order is
 * destroyed and the visible CFG collapses to a single dispatcher loop.
 *
 * <p><b>Eligibility</b> (must hold, otherwise {@link #flatten} returns false and
 * the caller keeps the original body + opaque predicates):
 * <ul>
 *   <li>No {@code try/catch} handlers (handlers start with a non-empty stack
 *       and require the original frame layout).</li>
 *   <li>Every branch target reachable from the entry has an empty operand
 *       stack (verified with ASM {@link BasicInterpreter}). This guarantees no
 *       operand-stack value needs to survive across the dispatch boundary, so
 *       no register spilling is required.</li>
 *   <li>Method body has at least two branches (otherwise flattening is noise).</li>
 *   <li>No {@code LOOKUPSWITCH}/{@code TABLESWITCH} (rewriting those inside a
 *       flattened dispatcher adds complexity without much benefit).</li>
 * </ul>
 *
 * The transform:
 * <ol>
 *   <li>Split into basic blocks; assign each an int id.</li>
 *   <li>Add state local {@code s}, initialized to the entry block id.</li>
 *   <li>Build {@code dispatch: switch(s){ case id_i: goto block_i; ... }}.</li>
 *   <li>Each block's terminator jump {@code GOTO L} / {@code IF_x L} becomes
 *       {@code s = id(L); goto dispatch} (for the taken branch) and the
 *       fall-through becomes {@code s = id(nextBlock); goto dispatch}.</li>
 *   <li>Return/throw terminators stay (they exit the machine).</li>
 * </ol>
 *
 * Frames are recomputed by the writer with {@code COMPUTE_FRAMES}.
 */
final class Flattener {

    private static final String TAG = "flatten";

    /** Signals a deliberately declined flatten (not an error) — see
     *  {@link #localInitPlan}. Never surfaced as a warning. */
    private static final class SkipFlatten extends RuntimeException {
        SkipFlatten(String why) { super(why); }
    }

    private Flattener() {}

    /**
     * Emits a flatten-phase log line. At INFO level when
     * {@link ControlFlowObfuscator#verboseCf} is on (always visible on stdout);
     * otherwise at DEBUG level.
     */
    private static void cfLog(String msg) {
        if (ControlFlowObfuscator.verboseCf) KBoxLog.info(TAG, msg);
        else KBoxLog.debug(TAG, msg);
    }

    static boolean flatten(MethodNode mn, int strength, String owner) {
        // KBX-CF-18: the transform-shape randomness (mix constants, pair
        // draws, fake-key count, block order) comes from a deterministic
        // stream derived from (buildSeed, pass, class#method) — never from
        // ThreadLocalRandom — so builds are reproducible per seed and
        // independent of thread scheduling.
        java.util.Random rng = com.kbox.core.util.DetRandom.of("cf-flatten",
                owner + "#" + mn.name + mn.desc);
        int insnSize = mn.instructions.size();
        int branches = countBranches(mn);
        String reason = checkEligibility(mn, strength);
        if (reason != null) {
            cfLog("      skip " + mn.name + mn.desc
                    + " insn=" + insnSize + " branches=" + branches
                    + " [" + reason + "]");
            return false;
        }
        try {
            // CF-02 transaction: rewrite a DEEP CLONE; only a clean success is
            // committed back. doFlatten mutates the instruction list in place,
            // and an exception mid-way would otherwise leave a half-flattened
            // body behind (frame-legal but wrong control flow) that ships.
            MethodNode work = cloneForFlatten(mn);
            int bc = doFlatten(work, strength, rng);
            mn.instructions = work.instructions;
            mn.maxLocals = work.maxLocals;
            mn.maxStack = work.maxStack;
            if (work.tryCatchBlocks != null) mn.tryCatchBlocks = work.tryCatchBlocks;
            if (work.localVariables != null) mn.localVariables = work.localVariables;
            cfLog("      flat " + mn.name + mn.desc
                    + " insn=" + insnSize + "->" + mn.instructions.size()
                    + " blocks=" + bc + " branches=" + branches);
            return true;
        } catch (SkipFlatten sf) {
            cfLog("      skip " + mn.name + mn.desc
                    + " insn=" + insnSize + " branches=" + branches
                    + " [" + sf.getMessage() + "]");
            return false;
        } catch (Exception e) {
            KBoxLog.warn(TAG, "Flatten aborted for " + mn.name + mn.desc
                    + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Deep-copies a method body (instructions + labels + handlers + locals
     * metadata) so the flattener can mutate the copy without corrupting the
     * original list — instruction nodes carry single-linked next/prev pointers,
     * so sharing nodes between two InsnLists is impossible.
     */
    private static MethodNode cloneForFlatten(MethodNode src) {
        MethodNode dst = new MethodNode(src.access, src.name, src.desc,
                src.signature, src.exceptions == null
                        ? null : src.exceptions.toArray(new String[0]));
        Map<LabelNode, LabelNode> labelMap = new HashMap<>();
        for (AbstractInsnNode ins : src.instructions) {
            if (ins instanceof LabelNode) labelMap.put((LabelNode) ins, new LabelNode());
        }
        for (AbstractInsnNode ins : src.instructions) {
            dst.instructions.add(ins.clone(labelMap));
        }
        if (src.tryCatchBlocks != null) {
            dst.tryCatchBlocks = new ArrayList<>();
            for (org.objectweb.asm.tree.TryCatchBlockNode t : src.tryCatchBlocks) {
                dst.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(
                        labelMap.get(t.start), labelMap.get(t.end),
                        labelMap.get(t.handler), t.type));
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

    // ---- local-slot normalization plan codes ----
    private static final int INIT_NONE = 0;
    private static final int INIT_INT = 1;
    private static final int INIT_LONG = 2;
    private static final int INIT_FLOAT = 3;
    private static final int INIT_DOUBLE = 4;
    private static final int INIT_NULL = 5;

    /**
     * Computes how each local slot must be default-initialised in the dispatcher
     * prologue so the flattened method stays verifiable, or {@code null} when the
     * method cannot be flattened safely.
     *
     * <p><b>Why this is required.</b> Flattening makes every basic block a target
     * of the entry {@code LOOKUPSWITCH}. The verifier merges the frame flowing out
     * of the dispatcher prologue (where only the parameters are initialised) with
     * the frame flowing in from the block's real predecessor. For a slot that the
     * original code assigns before use on every real path — the classic
     * {@code for (int v : arr)} loop variable — the prologue frame says
     * {@code top} while the real predecessor says {@code int}; the merge is
     * {@code top}, and the first {@code iload} then fails with
     * <pre>
     *   VerifyError: Bad local variable type
     *     ... Type top (current frame, locals[4]) is not assignable to integer
     * </pre>
     * Because the offending class could not be serialised, the packager rolled the
     * WHOLE class back to its untouched original bytes — so a class that should
     * have been flattened shipped completely unprotected (plaintext strings,
     * original control flow). That is the mechanism behind the observed
     * "verify-failed, rolled back" classes and the 64% plaintext-residue finding.
     *
     * <p>The fix is semantically free: those slots are always written before being
     * read on every real path (the flattening preserves the original CFG edges and
     * only adds a fake default case that throws), so the defaults are never
     * observed. Initialising them only removes the spurious {@code top}.
     */
    private static int[] localInitPlan(MethodNode mn, List<AbstractInsnNode> leaders, int firstFree) {
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<BasicValue>(new BasicInterpreter()).analyze(mn.name, mn);
        } catch (Throwable t) {
            cfLog("      localInitPlan: analyzer failed (" + t.getMessage() + ")");
            return null; // unanalysable: leave the method alone
        }
        if (frames == null) {
            cfLog("      localInitPlan: analyzer returned no frames");
            return null;
        }
        Map<AbstractInsnNode, Integer> idx = indexMap(mn);
        int n = mn.maxLocals;
        int[] plan = new int[Math.max(n, 0)];
        for (AbstractInsnNode leader : leaders) {
            Integer li = idx.get(leader);
            if (li == null) {
                cfLog("      localInitPlan: leader not in instruction list");
                return null;
            }
            Frame<BasicValue> f = frames[li];
            if (f == null) {
                // Unreachable in the original code. The dispatcher would make it
                // reachable, and unreachable bytecode carries no verifier contract
                // we could satisfy — refuse rather than risk an invalid class.
                cfLog("      localInitPlan: leader@" + li + " unreachable");
                return null;
            }
            for (int s = firstFree; s < n; s++) {
                BasicValue v = s < f.getLocals() ? f.getLocal(s) : null;
                if (v == null || v == BasicValue.UNINITIALIZED_VALUE) continue; // merges fine with top
                if (v == BasicValue.RETURNADDRESS_VALUE) return null; // JSR return address: no safe default
                int want;
                if (v == BasicValue.INT_VALUE) want = INIT_INT;
                else if (v == BasicValue.LONG_VALUE) want = INIT_LONG;
                else if (v == BasicValue.FLOAT_VALUE) want = INIT_FLOAT;
                else if (v == BasicValue.DOUBLE_VALUE) want = INIT_DOUBLE;
                else want = INIT_NULL; // any reference (or return address): null merges with it
                if (plan[s] != INIT_NONE && plan[s] != want) {
                    cfLog("      localInitPlan: slot " + s + " category conflict "
                            + plan[s] + " vs " + want + " at leader@" + li);
                    return null; // two different categories on one slot: cannot merge
                }
                plan[s] = want;
            }
        }
        // A 2-slot local writes top into its upper half, so the upper slot must not
        // be needed as a value of its own anywhere.
        for (int s = 0; s + 1 < plan.length; s++) {
            if ((plan[s] == INIT_LONG || plan[s] == INIT_DOUBLE) && plan[s + 1] != INIT_NONE) {
                return null;
            }
        }
        return plan;
    }

    /** Emits the default-value stores described by {@link #localInitPlan}. */
    private static void emitLocalInits(InsnList out, int[] plan) {
        if (plan == null) return;
        for (int s = 0; s < plan.length; s++) {
            switch (plan[s]) {
                case INIT_INT:
                    out.add(new InsnNode(Opcodes.ICONST_0));
                    out.add(new VarInsnNode(Opcodes.ISTORE, s));
                    break;
                case INIT_LONG:
                    out.add(new InsnNode(Opcodes.LCONST_0));
                    out.add(new VarInsnNode(Opcodes.LSTORE, s));
                    break;
                case INIT_FLOAT:
                    out.add(new InsnNode(Opcodes.FCONST_0));
                    out.add(new VarInsnNode(Opcodes.FSTORE, s));
                    break;
                case INIT_DOUBLE:
                    out.add(new InsnNode(Opcodes.DCONST_0));
                    out.add(new VarInsnNode(Opcodes.DSTORE, s));
                    break;
                case INIT_NULL:
                    out.add(new InsnNode(Opcodes.ACONST_NULL));
                    out.add(new VarInsnNode(Opcodes.ASTORE, s));
                    break;
                default:
                    break;
            }
        }
    }

    /** First local slot not occupied by {@code this} / declared parameters. */
    private static int firstFreeLocal(MethodNode mn) {
        int argSlots = Type.getArgumentsAndReturnSizes(mn.desc) >> 2;
        return ((mn.access & Opcodes.ACC_STATIC) != 0) ? argSlots - 1 : argSlots;
    }

    private static int countBranches(MethodNode mn) {
        int b = 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof JumpInsnNode) b++;
        }
        return b;
    }

    /**
     * Returns {@code null} if the method is eligible for flattening, or a
     * short reason string explaining why it was skipped (for debug output).
     *
     * <p>Eligibility is decided by a single O(n) stack-HEIGHT walk (no ASM
     * {@code Analyzer}, no per-method thread — those were the CF bottleneck:
     * one thread per method plus an 800ms analyzer timeout added up to tens of
     * thousands of thread spawns and discarded most real business methods).
     * The walk maintains the operand-stack height (in slots) from each block
     * start and requires every block boundary to have height 0, which is
     * exactly what the flattener needs: its dispatcher stub ({@code s=id; goto
     * dispatch}) is inserted only at block starts, so no operand-stack value
     * may cross a block edge. Heights are type-independent, so this is sound:
     * any method passing the walk has empty stacks at every jump target and
     * fall-through successor, precisely the property the old type-based
     * analyzer check enforced (it only ever looked at {@code getStackSize()}).
     */
    private static String checkEligibility(MethodNode mn, int strength) {
        // 条目 31: methods WITH exception handlers become flattenable at
        // strength >= 2. Every handler entry must be reachable ONLY through the
        // JVM's exception-dispatch edge (never a jump target, never a
        // conditional's fall-through), so the dispatcher never needs a case
        // with the caught exception on the stack. Handler bodies are then
        // ordinary blocks: the entry ASTORE restores an empty stack and the
        // terminator becomes a state transition like any other block.
        java.util.Set<LabelNode> handlerStarts = new java.util.HashSet<>();
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) {
            if (strength < 2) return "try-catch";
            if (mn.tryCatchBlocks.size() > 8) return "too-many-handlers";
            for (org.objectweb.asm.tree.TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                if (tcb.handler != null) handlerStarts.add(tcb.handler);
                else return "handler-null";
            }
        }
        int total = mn.instructions.size();
        if (total < 6) return "too-small";
        // Allow methods up to 1600 instructions (was 1000) for more aggressive flattening.
        if (total > 1600) return "too-large:" + total;
        AbstractInsnNode[] insns = mn.instructions.toArray();
        int branches = 0;
        boolean hasSwitch = false;
        for (AbstractInsnNode n : insns) {
            int op = n.getOpcode();
            if (op == Opcodes.TABLESWITCH || op == Opcodes.LOOKUPSWITCH) hasSwitch = true;
            if (op == Opcodes.JSR || op == Opcodes.RET) return "jsr-ret";
            if (n instanceof JumpInsnNode) branches++;
        }
        if (hasSwitch) return "switch";
        if (branches < 1) return "few-branches:" + branches;
        // Branch budget: doFlatten cost grows with the number of blocks (one
        // LOOKUPSWITCH case per branch), and the whole class is re-serialized
        // with COMPUTE_FRAMES afterwards — a 100+ block dispatcher is expensive
        // to build AND to verify. The old Analyzer-based gate discarded most
        // real methods on its 800ms timeout, which kept flatten coverage low
        // (and CF fast but weak); the O(n) walk below is instant, so without a
        // budget it flattens every windowed method and the build regresses
        // badly on big jars. Keep the coverage at the level the Analyzer gate
        // actually achieved: a few dozen blocks per method.
        if (branches > 40) return "too-many-branches:" + branches;
        if (branches == 1) {
            // Single-branch methods: still eligible if there's at least one
            // conditional (not just a GOTO). This catches methods like:
            //   if (x) { a } else { b }
            // (the height walk below then verifies the successors are empty).
            boolean onlyGoto = true;
            for (AbstractInsnNode n : insns) {
                if (n instanceof JumpInsnNode && n.getOpcode() != Opcodes.GOTO) {
                    onlyGoto = false;
                    break;
                }
            }
            if (onlyGoto) return "single-goto";
        }
        // Block-start bitmaps: entry (index 0), every jump target, and the
        // instruction right after every terminator (fall-through successor).
        boolean[] isJumpTarget = new boolean[total];
        boolean[] isBlockStart = new boolean[total];
        isBlockStart[0] = true;
        Map<AbstractInsnNode, Integer> pos = new IdentityHashMap<>();
        for (int i = 0; i < total; i++) pos.put(insns[i], i);
        for (int i = 0; i < total; i++) {
            AbstractInsnNode n = insns[i];
            if (n instanceof JumpInsnNode) {
                Integer ti = pos.get(((JumpInsnNode) n).label);
                if (ti != null) {
                    isJumpTarget[ti] = true;
                    isBlockStart[ti] = true;
                }
            }
            int op = n.getOpcode();
            if (n instanceof JumpInsnNode || op == Opcodes.RETURN
                    || op == Opcodes.IRETURN || op == Opcodes.LRETURN
                    || op == Opcodes.FRETURN || op == Opcodes.DRETURN
                    || op == Opcodes.ARETURN || op == Opcodes.ATHROW) {
                // 条目 31: the boundary is the IMMEDIATE successor, which may
                // itself be a LabelNode (in particular a handler entry whose
                // frame starts with the caught Throwable on the stack). The old
                // "skip labels first" version attributed the boundary to the
                // first real instruction, where the height is already 1.
                int next = i + 1;
                if (next < total) isBlockStart[next] = true;
            }
        }
        // 条目 31: validate each handler entry is JVM-dispatch-only and that
        // the first real instruction consumes the caught exception (so the
        // operand-stack height the walk tracks stays correct).
        if (!handlerStarts.isEmpty()) {
            Map<AbstractInsnNode, Integer> hpos = new IdentityHashMap<>();
            for (int i = 0; i < total; i++) hpos.put(insns[i], i);
            for (LabelNode hs : handlerStarts) {
                if (hs == insns[0]) return "handler-at-entry";
                Integer hi = hpos.get(hs);
                if (hi == null) return "handler-orphan";
                if (isJumpTarget[hi]) return "handler-is-jump-target@" + hi;
                int prev = hi - 1;
                while (prev >= 0 && insns[prev].getOpcode() == -1) prev--;
                if (prev < 0) return "handler-no-pred";
                int pop = insns[prev].getOpcode();
                if (pop != Opcodes.GOTO && !isReturn(pop) && pop != Opcodes.ATHROW) {
                    return "handler-fall-in@" + hi;
                }
                int fst = hi + 1;
                while (fst < total && insns[fst].getOpcode() == -1) fst++;
                if (fst >= total) return "handler-empty";
                int fop = insns[fst].getOpcode();
                if (fop != Opcodes.ASTORE && fop != Opcodes.ATHROW && fop != Opcodes.POP) {
                    return "handler-entry-op@" + hi + ":op" + fop;
                }
            }
        }
        // Single O(n) height walk. h = operand-stack height in slots within the
        // current block (every block starts at height 0; any nonzero boundary
        // means a value would have to survive the dispatcher -> ineligible).
        // 条目 31: handler-entry blocks start at height 1 — the JVM pushes the
        // caught Throwable on the exception edge, and the handler's first real
        // instruction (ASTORE/POP/ATHROW) consumes it.
        int h = 0;
        for (int i = 0; i < total; i++) {
            boolean handlerEntry = insns[i] instanceof LabelNode
                    && handlerStarts.contains(insns[i]);
            if (handlerEntry) {
                h = 1;
            } else if (isBlockStart[i] && h != 0) {
                return (isJumpTarget[i] ? "non-empty-stack@" : "fall-thru-stack@") + i
                        + ":op" + insns[i].getOpcode() + ":h" + h;
            }
            int e = stackEffect(insns[i]);
            h += e;
            if (h < 0) return "stack-underflow@" + i + ":op" + insns[i].getOpcode();
            AbstractInsnNode n = insns[i];
            if (n instanceof JumpInsnNode) {
                int op = n.getOpcode();
                if (op == Opcodes.GOTO) {
                    // GOTO transfers the whole stack; successor must be empty.
                    if (h != 0) return "fall-thru-stack@" + i + ":goto:h" + h;
                } else if (op != Opcodes.JSR) {
                    // Conditional: pops its condition on BOTH paths; successors
                    // (target + fall-through) must both be empty.
                    if (h != 0) return "non-empty-stack@" + i + ":cond:h" + h;
                }
            }
        }
        return null; // eligible
    }

    /**
     * Net operand-stack height effect (pushes − pops, in slots) of one
     * instruction. Long/double count 2 slots. Type-independent.
     */
    static int stackEffect(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op == -1) return 0; // labels / frames / line numbers
        switch (op) {
            // Pushes
            case Opcodes.ACONST_NULL: case Opcodes.ICONST_M1: case Opcodes.ICONST_0:
            case Opcodes.ICONST_1: case Opcodes.ICONST_2: case Opcodes.ICONST_3:
            case Opcodes.ICONST_4: case Opcodes.ICONST_5: case Opcodes.BIPUSH:
            case Opcodes.SIPUSH: case Opcodes.FCONST_0: case Opcodes.FCONST_1:
            case Opcodes.FCONST_2: case Opcodes.NEW:
                return 1;
            // NEWARRAY pops the element count and pushes the array reference.
            case Opcodes.NEWARRAY:
                return 0;
            case Opcodes.LCONST_0: case Opcodes.LCONST_1: case Opcodes.DCONST_0:
            case Opcodes.DCONST_1:
                return 2;
            // Stack ops
            case Opcodes.POP: return -1;
            case Opcodes.POP2: return -2;
            case Opcodes.DUP: case Opcodes.DUP_X1: case Opcodes.DUP_X2: return 1;
            case Opcodes.DUP2: case Opcodes.DUP2_X1: case Opcodes.DUP2_X2: return 2;
            case Opcodes.SWAP: return 0;
            // Int arithmetic
            case Opcodes.IADD: case Opcodes.ISUB: case Opcodes.IMUL:
            case Opcodes.IDIV: case Opcodes.IREM: case Opcodes.IAND:
            case Opcodes.IOR: case Opcodes.IXOR: case Opcodes.ISHL:
            case Opcodes.ISHR: case Opcodes.IUSHR:
                return -1;
            case Opcodes.INEG: return 0;
            // Long arithmetic
            case Opcodes.LADD: case Opcodes.LSUB: case Opcodes.LMUL:
            case Opcodes.LDIV: case Opcodes.LREM: case Opcodes.LAND:
            case Opcodes.LOR: case Opcodes.LXOR:
                return -2;
            case Opcodes.LNEG: return 0;
            case Opcodes.LSHL: case Opcodes.LSHR: case Opcodes.LUSHR: return -1;
            // Float / double arithmetic
            case Opcodes.FADD: case Opcodes.FSUB: case Opcodes.FMUL:
            case Opcodes.FDIV: case Opcodes.FREM:
                return -1;
            case Opcodes.FNEG: return 0;
            case Opcodes.DADD: case Opcodes.DSUB: case Opcodes.DMUL:
            case Opcodes.DDIV: case Opcodes.DREM:
                return -2;
            case Opcodes.DNEG: return 0;
            // Conversions
            case Opcodes.I2L: case Opcodes.I2D: case Opcodes.F2L: case Opcodes.F2D:
                return 1;
            case Opcodes.L2I: case Opcodes.L2F: case Opcodes.D2I: case Opcodes.D2F:
                return -1;
            case Opcodes.I2F: case Opcodes.L2D: case Opcodes.D2L:
            case Opcodes.F2I: case Opcodes.I2B: case Opcodes.I2C: case Opcodes.I2S:
                return 0;
            // Comparisons
            case Opcodes.LCMP: case Opcodes.DCMPL: case Opcodes.DCMPG: return -3;
            case Opcodes.FCMPL: case Opcodes.FCMPG: return -1;
            // Conditional branches (pop their condition on both paths)
            case Opcodes.IFEQ: case Opcodes.IFNE: case Opcodes.IFLT: case Opcodes.IFGE:
            case Opcodes.IFGT: case Opcodes.IFLE: case Opcodes.IFNULL:
            case Opcodes.IFNONNULL:
                return -1;
            case Opcodes.IF_ICMPEQ: case Opcodes.IF_ICMPNE: case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE: case Opcodes.IF_ICMPGT: case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ: case Opcodes.IF_ACMPNE:
                return -2;
            case Opcodes.GOTO: return 0;
            case Opcodes.JSR: return 1; // pushes return address
            // Returns / throw
            case Opcodes.IRETURN: case Opcodes.FRETURN: case Opcodes.ARETURN:
            case Opcodes.ATHROW:
                return -1;
            case Opcodes.LRETURN: case Opcodes.DRETURN: return -2;
            case Opcodes.RETURN: return 0;
            // Array load / store
            case Opcodes.IALOAD: case Opcodes.FALOAD: case Opcodes.AALOAD:
            case Opcodes.BALOAD: case Opcodes.CALOAD: case Opcodes.SALOAD:
                return -1;
            case Opcodes.LALOAD: case Opcodes.DALOAD: return 0;
            case Opcodes.IASTORE: case Opcodes.FASTORE: case Opcodes.AASTORE:
            case Opcodes.BASTORE: case Opcodes.CASTORE: case Opcodes.SASTORE:
                return -3;
            case Opcodes.LASTORE: case Opcodes.DASTORE: return -4;
            case Opcodes.ARRAYLENGTH: case Opcodes.CHECKCAST:
            case Opcodes.INSTANCEOF: case Opcodes.IINC:
                return 0;
            case Opcodes.MONITORENTER: case Opcodes.MONITOREXIT: return -1;
            default:
                break;
        }
        if (n instanceof VarInsnNode) {
            // Short forms (raw opcodes 26..45 loads / 59..78 stores) are
            // normalized to the generic opcodes by ASM's ClassReader, but a
            // MethodNode built by another pass may still carry them. Groups of
            // four: I, L, F, D, A; L and D occupy two slots. ASM's Opcodes
            // interface does not export named constants for these.
            if (op >= 26 && op <= 45) {
                int g = (op - 26) / 4;
                return (g == 1 || g == 3) ? 2 : 1;
            }
            if (op >= 59 && op <= 78) {
                int g = (op - 59) / 4;
                return (g == 1 || g == 3) ? -2 : -1;
            }
            switch (op) {
                case Opcodes.ILOAD: case Opcodes.FLOAD: case Opcodes.ALOAD: return 1;
                case Opcodes.LLOAD: case Opcodes.DLOAD: return 2;
                case Opcodes.ISTORE: case Opcodes.FSTORE: case Opcodes.ASTORE: return -1;
                case Opcodes.LSTORE: case Opcodes.DSTORE: return -2;
                default: return 0; // RET etc.
            }
        }
        if (n instanceof LdcInsnNode) {
            Object cst = ((LdcInsnNode) n).cst;
            // Java 11+ dynamic constants: the pushed size is the descriptor's
            // size, which may be 2 for long/double (a plain "1" would corrupt
            // the height walk on Java 11+ classes).
            if (cst instanceof org.objectweb.asm.ConstantDynamic) {
                return Type.getType(((org.objectweb.asm.ConstantDynamic) cst).getDescriptor())
                        .getSize();
            }
            return (cst instanceof Long || cst instanceof Double) ? 2 : 1;
        }
        if (n instanceof TypeInsnNode) {
            return (op == Opcodes.ANEWARRAY || op == Opcodes.CHECKCAST
                    || op == Opcodes.INSTANCEOF) ? 0 : 1; // NEW -> 1
        }
        if (n instanceof MultiANewArrayInsnNode) {
            return 1 - ((MultiANewArrayInsnNode) n).dims;
        }
        if (n instanceof FieldInsnNode) {
            int size = Type.getType(((FieldInsnNode) n).desc).getSize();
            switch (op) {
                case Opcodes.GETSTATIC: return size;
                case Opcodes.PUTSTATIC: return -size;
                case Opcodes.GETFIELD: return size - 1;
                case Opcodes.PUTFIELD: return -(size + 1);
                default: return 0;
            }
        }
        if (n instanceof MethodInsnNode || n instanceof InvokeDynamicInsnNode) {
            String desc = (n instanceof MethodInsnNode)
                    ? ((MethodInsnNode) n).desc
                    : ((InvokeDynamicInsnNode) n).desc;
            int v = Type.getArgumentsAndReturnSizes(desc);
            // ASM counts the implicit `this` in EVERY descriptor, regardless of
            // the invocation kind: `v >>> 2` is (receiver + real args) for an
            // instance call and (1 + real args) for static/indy. The old code
            // subtracted a receiver for instance calls AND used the raw value
            // for static ones — i.e. it popped one slot too many in both cases.
            // Result: every method containing a call (StringBuilder.append,
            // Kind.values(), ...) failed the height walk with a bogus
            // "stack-underflow", so nothing was ever flattened.
            int slotsInclThis = v >>> 2;
            int retSlots = v & 0x03; // 0=void, 1=one slot, 2=long/double
            boolean hasReceiver = n instanceof MethodInsnNode && op != Opcodes.INVOKESTATIC;
            int pops = hasReceiver ? slotsInclThis : slotsInclThis - 1;
            return retSlots - pops;
        }
        return 0; // unknown instruction: neutral (never reached for valid bytecode)
    }

    private static int doFlatten(MethodNode mn, int strength, java.util.Random rng) {
        // 条目 31: handler entry labels are leaders reached only by the JVM's
        // exception-dispatch edge — they must never become dispatcher cases.
        java.util.Set<LabelNode> handlerStarts = new java.util.HashSet<>();
        if (mn.tryCatchBlocks != null) {
            for (org.objectweb.asm.tree.TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                if (tcb.handler != null) handlerStarts.add(tcb.handler);
            }
        }
        // 1. Compute basic-block leaders (entry + jump targets + post-jump/return points).
        //    Each leader is normalized to a LabelNode so LOOKUPSWITCH can target it.
        Map<AbstractInsnNode, LabelNode> labelFor = new HashMap<>();
        List<AbstractInsnNode> leadersRaw = new ArrayList<>();
        AbstractInsnNode entry = ensureLeaderLabel(mn, mn.instructions.getFirst(), labelFor);
        leadersRaw.add(entry);
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            int op = n.getOpcode();
            if (n instanceof JumpInsnNode) {
                JumpInsnNode j = (JumpInsnNode) n;
                // jump target is already a LabelNode (j.label)
                if (!leadersRaw.contains(j.label)) leadersRaw.add(j.label);
                AbstractInsnNode after = skipToLeader(j.getNext(), handlerStarts);
                if (after != null) {
                    AbstractInsnNode lab = ensureLeaderLabel(mn, after, labelFor);
                    if (!leadersRaw.contains(lab)) leadersRaw.add(lab);
                }
            } else if (isReturn(op) || op == Opcodes.ATHROW) {
                AbstractInsnNode after = skipToLeader(n.getNext(), handlerStarts);
                if (after != null) {
                    AbstractInsnNode lab = ensureLeaderLabel(mn, after, labelFor);
                    if (!leadersRaw.contains(lab)) leadersRaw.add(lab);
                }
            }
        }
        // 条目 31: handler labels themselves are leaders (block boundaries) even
        // when no jump/post-terminator scan landed on them.
        if (mn.tryCatchBlocks != null) {
            for (org.objectweb.asm.tree.TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                if (tcb.handler != null && !leadersRaw.contains(tcb.handler)) {
                    leadersRaw.add(tcb.handler);
                }
            }
        }
        // Sort by traversal index.
        Map<AbstractInsnNode, Integer> pos = indexMap(mn);
        leadersRaw.sort((a, b) -> Integer.compare(pos.get(a), pos.get(b)));

        // 1b. Decide the prologue's local default-initialisation BEFORE anything is
        //     rewritten (the plan is derived from the original data flow). Throws
        //     nothing but returns null when the method cannot be flattened safely —
        //     the caller then keeps the original body, which is always valid.
        int[] initPlan = localInitPlan(mn, leadersRaw, firstFreeLocal(mn));
        if (initPlan == null) {
            throw new SkipFlatten("local-state merge unsafe");
        }

        // 2. Assign ids. No id-list shuffle anymore: KBX-CF-04 physically
        //    reorders the blocks (reorderBlocks below) and the case keys are
        //    now nonlinear hashes of random (A, B) pairs, so neither the case
        //    numbering nor the physical layout leaks the original order.
        Map<AbstractInsnNode, Integer> idOf = new HashMap<>();
        int nBlocks = leadersRaw.size();
        for (int i = 0; i < nBlocks; i++) {
            idOf.put(leadersRaw.get(i), i);
        }

        // 3. Rewrite each block terminator: jumps become "sA = A_i; sB = B_i;
        //    goto dispatch". KBX-CF-04: the dispatcher no longer keys on the
        //    XOR identity (s1 ^ s2 == id), where one pattern match on the
        //    immediate pair rebuilt the whole CFG. Each block now stores a
        //    random (A, B) immediate pair and the dispatcher evaluates a
        //    per-method nonlinear mix  key = M(A, B)  (xor-shift + odd
        //    multipliers + rotate, constants drawn per method). The immediates
        //    alone are meaningless — recovering the case->block map statically
        //    requires emulating M for every pair, and M differs per method.
        LabelNode dispatch = new LabelNode();
        int stateLocal = mn.maxLocals;     // slot A
        int maskLocal = mn.maxLocals + 1;  // slot B
        mn.maxLocals += 2;
        // Per-method mix parameters. MUST stay in exact sync with mixEval().
        int mixR1 = 1 + rng.nextInt(31);
        int mixC1 = rng.nextInt() | 1;   // odd: IMUL stays bijective mod 2^32
        int mixC2 = rng.nextInt();
        boolean mixUshr = rng.nextBoolean();
        int mixR2 = 1 + rng.nextInt(31);
        int mixC3 = rng.nextInt() | 1;
        int[] pairA = new int[nBlocks];
        int[] pairB = new int[nBlocks];
        int[] keyOf = new int[nBlocks];
        java.util.Set<Integer> usedKeys = new java.util.HashSet<>();
        for (int i = 0; i < nBlocks; i++) {
            int guard = 0;
            while (!usedKeys.add(mixEval(
                    pairA[i] = rng.nextInt(), pairB[i] = rng.nextInt(),
                    mixR1, mixC1, mixC2, mixUshr, mixR2, mixC3))) {
                if (++guard > 256) {
                    // n^2 / 2^32 collisions needed to get here — never seen in
                    // practice; refuse rather than emit a broken switch.
                    throw new SkipFlatten("state-key space exhausted");
                }
            }
        }
        for (int bi = 0; bi < leadersRaw.size(); bi++) {
            AbstractInsnNode blockStart = leadersRaw.get(bi);
            AbstractInsnNode end = (bi + 1 < leadersRaw.size()) ? leadersRaw.get(bi + 1) : null;
            AbstractInsnNode term = null;
            AbstractInsnNode cur = blockStart;
            while (cur != null && cur != end) {
                int op = cur.getOpcode();
                if (op == Opcodes.GOTO || (cur instanceof JumpInsnNode) || isReturn(op) || op == Opcodes.ATHROW) {
                    term = cur;
                    break;
                }
                cur = cur.getNext();
            }
            if (term == null) {
                // 条目 31: a block ending at a handler label keeps its original
                // fall-through (defensive — eligibility already guarantees the
                // predecessor is an unconditional terminator, so this is
                // unreachable for valid code).
                if (end != null && !(end instanceof LabelNode && handlerStarts.contains(end))) {
                    int endId = idOf.get(end);
                    mn.instructions.insertBefore(end, exitStub(stateLocal, maskLocal, dispatch,
                            pairA[endId], pairB[endId]));
                }
                continue;
            }
            int top = term.getOpcode();
            if (top == Opcodes.GOTO) {
                JumpInsnNode g = (JumpInsnNode) term;
                int targetId = idOf.get(g.label);
                mn.instructions.insert(term, exitStub(stateLocal, maskLocal, dispatch,
                        pairA[targetId], pairB[targetId]));
                mn.instructions.remove(term);
            } else if (isReturn(top)) {
                // keep: return exits the state machine.
            } else {
                JumpInsnNode c = (JumpInsnNode) term;
                int takenId = idOf.get(c.label);
                AbstractInsnNode fallThrough = skipLabels(c.getNext());
                LabelNode skip = new LabelNode();
                InsnList inverted = new InsnList();
                inverted.add(new JumpInsnNode(invert(c.getOpcode()), skip));
                InsnList stub = exitStub(stateLocal, maskLocal, dispatch,
                        pairA[takenId], pairB[takenId]);
                // InsnList.getFirst() does NOT unlink the node, so the previous
                // "while (stub.size() > 0) inverted.add(stub.getFirst())" spun
                // forever (same node re-added, size never shrank). add(InsnList)
                // moves every instruction and clears the source list.
                inverted.add(stub);
                inverted.add(skip);
                mn.instructions.insert(term, inverted);
                mn.instructions.remove(term);
                if (fallThrough != null) {
                    AbstractInsnNode ftLab = labelFor.get(fallThrough);
                    if (ftLab == null) ftLab = ensureLeaderLabel(mn, fallThrough, labelFor);
                    Integer ftId = idOf.get(ftLab);
                    if (ftId != null) {
                        mn.instructions.insertBefore(ftLab, exitStub(stateLocal, maskLocal,
                                dispatch, pairA[ftId], pairB[ftId]));
                    }
                }
            }
        }

        // 3b. KBX-CF-04: physically shuffle the basic blocks. Every block now
        //     ends in an explicit state transition (or exits), so the physical
        //     order carries no control-flow meaning — but only re-order when
        //     there are no exception handlers, whose label-delimited ranges a
        //     reorder would tear apart.
        reorderBlocks(mn, leadersRaw, rng);

        // 4. Prepend: store entry (A, B) pair; dispatch label; LOOKUPSWITCH on
        //    M(sA, sB). Add fake dispatch entries at strength >= 2 to bloat the
        //    switch table and confuse static analysis.
        int fakeCount = (strength >= 3) ? 8 + rng.nextInt(8)
                : (strength >= 2 ? 3 + rng.nextInt(3) : 0);
        InsnList head = new InsnList();
        // 4a. Local-state normalization (see localInitPlan): gives every slot a
        //     definite verifier type before the dispatcher, so the merge with each
        //     block's real predecessor can never degrade to `top`.
        emitLocalInits(head, initPlan);
        // The state a block stores before jumping to the dispatcher is its own
        // (A, B) pair (see every exitStub() call above), so the ENTRY state must
        // be the pair of the first block.
        int entryId = idOf.get(leadersRaw.get(0));
        pushInt(head, pairA[entryId]);
        head.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        pushInt(head, pairB[entryId]);
        head.add(new VarInsnNode(Opcodes.ISTORE, maskLocal));
        head.add(dispatch);
        // Dispatch table: M(state, mask) -> the block that owns that pair.
        //
        // Two invariants are mandatory and were both violated before:
        //
        //  1. Pairing. exitStub() stores block i's (A, B) pair, so case key
        //     keyOf[i] = M(A_i, B_i) must map to block i. Keys and pairs come
        //     from the same arrays, so the pairing holds by construction.
        //
        //  2. Ordering. ASM's MethodWriter requires LOOKUPSWITCH keys to be
        //     strictly increasing and throws
        //       "The keys must be sorted in increasing order"
        //     from visitLookupSwitchInsn otherwise. A TreeMap keyed by the final
        //     case value satisfies both invariants by construction.
        LabelNode def = new LabelNode();
        java.util.TreeMap<Integer, LabelNode> byKey = new java.util.TreeMap<>();
        for (int i = 0; i < leadersRaw.size(); i++) {
            AbstractInsnNode leader = leadersRaw.get(i);
            // 条目 31: handler entries are JVM-dispatch-only — no case value
            // may target them (the frame there carries the caught exception).
            if (leader instanceof LabelNode && handlerStarts.contains(leader)) continue;
            int id = idOf.get(leader);
            byKey.put(keyOf[id], (LabelNode) leader);
        }
        // Fake entries → default (defensive throw). They must not collide with a
        // real case value, or the real block would become unreachable.
        for (int i = 0; i < fakeCount; i++) {
            int fakeKey;
            do { fakeKey = rng.nextInt(); } while (byKey.containsKey(fakeKey));
            byKey.put(fakeKey, def);
        }
        head.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        head.add(new VarInsnNode(Opcodes.ILOAD, maskLocal));
        // KBX-CF-04: per-method nonlinear mix. MUST mirror mixEval() exactly:
        //   t  = a ^ (b >>> r1)
        //   t  = t * c1  (+ c2)
        //   t ^= (ushr ? t >>> r2 : t << r2)
        //   key = t * c3
        pushInt(head, mixR1);
        head.add(new InsnNode(Opcodes.ISHR));
        head.add(new InsnNode(Opcodes.IXOR));
        pushInt(head, mixC1);
        head.add(new InsnNode(Opcodes.IMUL));
        pushInt(head, mixC2);
        head.add(new InsnNode(Opcodes.IADD));
        head.add(new InsnNode(Opcodes.DUP));
        pushInt(head, mixR2);
        head.add(new InsnNode(mixUshr ? Opcodes.IUSHR : Opcodes.ISHL));
        head.add(new InsnNode(Opcodes.IXOR));
        pushInt(head, mixC3);
        head.add(new InsnNode(Opcodes.IMUL));
        int total = byKey.size();
        int[] keys = new int[total];
        LabelNode[] lbls = new LabelNode[total];
        int idx = 0;
        for (Map.Entry<Integer, LabelNode> e : byKey.entrySet()) {
            keys[idx] = e.getKey();
            lbls[idx] = e.getValue();
            idx++;
        }
        head.add(new LookupSwitchInsnNode(def, keys, lbls));
        // Default / fake-case target. The label IS a jump target, so the verifier
        // analyses this block: a bare ATHROW there has no Throwable to pop and the
        // whole method fails with
        //   "Cannot pop operand off an empty stack" (at the default block)
        // which rolled the entire class back to its unprotected bytes. Build a
        // real, stack-correct thrower instead.
        head.add(def);
        head.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        head.add(new InsnNode(Opcodes.DUP));
        head.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/IllegalStateException", "<init>", "()V", false));
        head.add(new InsnNode(Opcodes.ATHROW)); // unreachable in normal operation
        // Dispatcher mix evaluation peaks at 3 operand slots ([a, b, r1]); the
        // default block pushes a reference and its dup. Keep a 4-slot floor.
        if (mn.maxStack < 4) mn.maxStack = 4;
        mn.instructions.insertBefore(mn.instructions.getFirst(), head);
        return leadersRaw.size();
    }

    /**
     * Build-time mirror of the dispatcher's emitted mix sequence. MUST stay in
     * exact sync with the instruction sequence emitted in {@link #doFlatten}
     * (step 4): {@code t = a ^ (b >>> r1); t = t * c1 + c2;
     * t ^= ushr ? t >>> r2 : t << r2; return t * c3;}.
     */
    private static int mixEval(int a, int b, int r1, int c1, int c2,
                               boolean ushr, int r2, int c3) {
        int t = a ^ (b >>> r1);
        t = t * c1 + c2;
        t ^= ushr ? (t >>> r2) : (t << r2);
        return t * c3;
    }

    /**
     * KBX-CF-04: physically shuffles the basic blocks in the instruction list
     * so the case order, the original block order and the physical layout are
     * three unrelated permutations. Safe only when the method has no exception
     * handlers (handler ranges are label-delimited and a reorder would tear
     * them apart) and every block ends in an explicit transition — which the
     * terminator rewrite guarantees. Labels and jump targets are object
     * references, so the rewrite is order-independent by construction.
     */
    private static void reorderBlocks(MethodNode mn, List<AbstractInsnNode> leaders,
                                      java.util.Random rng) {
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return;
        int n = leaders.size();
        if (n < 3) return;
        Map<AbstractInsnNode, Integer> pos = indexMap(mn);
        int[] starts = new int[n];
        for (int i = 0; i < n; i++) {
            Integer p = pos.get(leaders.get(i));
            if (p == null) return; // leader missing from the list: skip reorder
            starts[i] = p;
        }
        for (int i = 1; i < n; i++) {
            if (starts[i] <= starts[i - 1]) return; // not strictly increasing: skip
        }
        int total = mn.instructions.size();
        AbstractInsnNode[] insns = mn.instructions.toArray();
        Integer[] order = new Integer[n];
        for (int i = 0; i < n; i++) order[i] = i;
        for (int i = n - 1; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            Integer t = order[i]; order[i] = order[j]; order[j] = t;
        }
        java.util.List<AbstractInsnNode> ordered = new ArrayList<>(total);
        for (int i = 0; i < n; i++) {
            int seg = order[i];
            int from = starts[seg];
            int to = (seg + 1 < n) ? starts[seg + 1] : total;
            for (int k = from; k < to; k++) ordered.add(insns[k]);
        }
        // Detach through the InsnList API (remove() clears the node's own
        // prev/next links); adding a node that is still linked to its old
        // neighbours leaves a stale `next` pointer and creates a cycle that
        // makes every later traversal of the list loop forever.
        for (AbstractInsnNode node : ordered) mn.instructions.remove(node);
        for (AbstractInsnNode node : ordered) mn.instructions.add(node);
    }

    /**
     * If {@code node} is a LabelNode return it as-is. Otherwise insert a fresh
     * LabelNode immediately before {@code node} (so it can be a switch target)
     * and remember the mapping for later lookups.
     */
    private static AbstractInsnNode ensureLeaderLabel(MethodNode mn, AbstractInsnNode node,
                                                      Map<AbstractInsnNode, LabelNode> labelFor) {
        if (node instanceof LabelNode) return node;
        LabelNode existing = labelFor.get(node);
        if (existing != null) return existing;
        LabelNode l = new LabelNode();
        mn.instructions.insertBefore(node, l);
        labelFor.put(node, l);
        return l;
    }

    private static Map<AbstractInsnNode, Integer> indexMap(MethodNode mn) {
        Map<AbstractInsnNode, Integer> m = new HashMap<>();
        int i = 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            m.put(n, i++);
        }
        return m;
    }

    private static AbstractInsnNode skipLabels(AbstractInsnNode n) {
        while (n != null && n.getOpcode() == -1) n = n.getNext();
        return n;
    }

    /** Like {@link #skipLabels}, but stops AT a handler-entry label instead of
     *  skipping past it (条目 31) — the handler label itself is the block
     *  boundary the flattener must see. */
    private static AbstractInsnNode skipToLeader(AbstractInsnNode n,
                                                 java.util.Set<LabelNode> stopAt) {
        while (n != null && n.getOpcode() == -1 && !stopAt.contains(n)) n = n.getNext();
        return n;
    }

    /** {@code sA = a; sB = b; goto dispatch;} — the dispatcher resolves the
     *  real case key as M(a, b) (see {@link #mixEval}); the immediates alone
     *  are meaningless (KBX-CF-04). */
    private static InsnList exitStub(int stateLocal, int maskLocal,
                                     LabelNode dispatch, int a, int b) {
        InsnList l = new InsnList();
        pushInt(l, a);
        l.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        pushInt(l, b);
        l.add(new VarInsnNode(Opcodes.ISTORE, maskLocal));
        l.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
        return l;
    }

    /** Pushes an int constant with the most compact instruction. Falls back to
     *  LDC for values outside signed-16-bit range (rotation masks can exceed it). */
    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new org.objectweb.asm.tree.LdcInsnNode(v));
    }

    static boolean isReturn(int op) {
        switch (op) {
            case Opcodes.RETURN: case Opcodes.IRETURN: case Opcodes.LRETURN:
            case Opcodes.FRETURN: case Opcodes.DRETURN: case Opcodes.ARETURN:
                return true;
            default: return false;
        }
    }

    /** Invert a conditional branch opcode (IFEQ<->IFNE, etc.). */
    private static int invert(int op) {
        switch (op) {
            case Opcodes.IFEQ: return Opcodes.IFNE;
            case Opcodes.IFNE: return Opcodes.IFEQ;
            case Opcodes.IFLT: return Opcodes.IFGE;
            case Opcodes.IFGE: return Opcodes.IFLT;
            case Opcodes.IFGT: return Opcodes.IFLE;
            case Opcodes.IFLE: return Opcodes.IFGT;
            case Opcodes.IF_ICMPEQ: return Opcodes.IF_ICMPNE;
            case Opcodes.IF_ICMPNE: return Opcodes.IF_ICMPEQ;
            case Opcodes.IF_ICMPLT: return Opcodes.IF_ICMPGE;
            case Opcodes.IF_ICMPGE: return Opcodes.IF_ICMPLT;
            case Opcodes.IF_ICMPGT: return Opcodes.IF_ICMPLE;
            case Opcodes.IF_ICMPLE: return Opcodes.IF_ICMPGT;
            case Opcodes.IFNULL: return Opcodes.IFNONNULL;
            case Opcodes.IFNONNULL: return Opcodes.IFNULL;
            default: return Opcodes.IFNE; // best-effort fallback (should not happen)
        }
    }

    private static LabelNode firstLabel(MethodNode mn) {
        AbstractInsnNode n = mn.instructions.getFirst();
        if (n instanceof LabelNode) return (LabelNode) n;
        LabelNode l = new LabelNode();
        mn.instructions.insert(l);
        return l;
    }
}
