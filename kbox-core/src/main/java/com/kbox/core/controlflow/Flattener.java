package com.kbox.core.controlflow;

import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

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

    static boolean flatten(MethodNode mn, int strength) {
        int insnSize = mn.instructions.size();
        int branches = countBranches(mn);
        // Run the entire flatten (eligibility check + transform) in a daemon
        // thread with a 3-second timeout. The ASM Analyzer and/or doFlatten can
        // be pathologically slow on certain CFG shapes after opaque-predicate
        // injection, and no single method should be allowed to block the build.
        final java.util.concurrent.atomic.AtomicReference<String> skipReason =
                new java.util.concurrent.atomic.AtomicReference<>(null);
        final java.util.concurrent.atomic.AtomicReference<Integer> blockCount =
                new java.util.concurrent.atomic.AtomicReference<>(-1);
        final java.util.concurrent.atomic.AtomicReference<Exception> errRef =
                new java.util.concurrent.atomic.AtomicReference<>(null);
        final int fstrength = strength;
        Thread t = new Thread(() -> {
            try {
                String reason = checkEligibility(mn);
                if (reason != null) {
                    skipReason.set(reason);
                    return;
                }
                int bc = doFlatten(mn, fstrength);
                blockCount.set(bc);
            } catch (Exception e) {
                errRef.set(e);
            }
        }, "kbox-flatten");
        t.setDaemon(true);
        t.start();
        try {
            // Timeout for the whole flatten. Timeout-skips were previously waited
            // 3s each, which made CF on large inputs (thousands of methods) crawl
            // (flatten-timeout 3000ms * N). The skipped method is discarded anyway,
            // so a short budget is enough for methods that DO flatten; pathological
            // CFGs simply skip faster.
            t.join(700); // 700ms budget (was 3000ms) — big CF speedup on large jars
        } catch (InterruptedException e) {
            t.interrupt();
            cfLog("      skip " + mn.name + mn.desc
                    + " insn=" + insnSize + " branches=" + branches
                    + " [interrupted]");
            return false;
        }
        if (t.isAlive()) {
            t.interrupt();
            cfLog("      skip " + mn.name + mn.desc
                    + " insn=" + insnSize + " branches=" + branches
                    + " [flatten-timeout]");
            return false;
        }
        if (errRef.get() != null) {
            KBoxLog.warn(TAG, "Flatten aborted for " + mn.name + mn.desc
                    + ": " + errRef.get().getMessage());
            return false;
        }
        String reason = skipReason.get();
        if (reason != null) {
            cfLog("      skip " + mn.name + mn.desc
                    + " insn=" + insnSize + " branches=" + branches
                    + " [" + reason + "]");
            return false;
        }
        int bc = blockCount.get();
        if (bc >= 0) {
            cfLog("      flat " + mn.name + mn.desc
                    + " insn=" + insnSize + "->" + mn.instructions.size()
                    + " blocks=" + bc + " branches=" + branches);
            return true;
        }
        cfLog("      skip " + mn.name + mn.desc
                + " insn=" + insnSize + " branches=" + branches
                + " [unknown]");
        return false;
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
     */
    private static String checkEligibility(MethodNode mn) {
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return "try-catch";
        if (mn.instructions == null || mn.instructions.size() < 6) return "too-small";
        // Allow methods up to 1000 instructions (was 500) for more aggressive flattening.
        if (mn.instructions.size() > 1000) return "too-large:" + mn.instructions.size();
        int branches = 0;
        boolean hasSwitch = false;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            int op = n.getOpcode();
            if (op == Opcodes.TABLESWITCH || op == Opcodes.LOOKUPSWITCH) hasSwitch = true;
            if (n instanceof JumpInsnNode) branches++;
        }
        if (hasSwitch) return "switch";
        if (branches < 1) return "few-branches:" + branches;
        if (branches == 1) {
            // Single-branch methods: still eligible if there's at least one
            // conditional (not just a GOTO). This catches methods like:
            //   if (x) { a } else { b }
            for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
                int op = n.getOpcode();
                if (op != Opcodes.GOTO && n instanceof JumpInsnNode) return null; // eligible
            }
            return "single-goto";
        }
        // Run the ASM Analyzer in a daemon thread with a 2-second timeout.
        // The Analyzer can be pathologically slow on certain CFG shapes even
        // with <200 instructions (especially after opaque-predicate injection
        // adds dead-code branches that confuse fixpoint iteration).
        final MethodNode fn = mn;
        final java.util.concurrent.atomic.AtomicReference<Frame<BasicValue>[]> ref =
                new java.util.concurrent.atomic.AtomicReference<>(null);
        final java.util.concurrent.atomic.AtomicReference<Exception> err =
                new java.util.concurrent.atomic.AtomicReference<>(null);
        Thread t = new Thread(() -> {
            try {
                ref.set(new Analyzer<>(new BasicInterpreter()).analyze("__tmp", fn));
            } catch (Exception e) {
                err.set(e);
            }
        }, "kbox-analyzer");
        t.setDaemon(true);
        t.start();
        try {
            t.join(500); // 500ms analyzer budget (was 2000ms) — CF speedup, skipped anyway
        } catch (InterruptedException e) {
            t.interrupt();
            return "analyzer-interrupted";
        }
        if (t.isAlive()) {
            t.interrupt();
            return "analyzer-timeout";
        }
        if (err.get() != null) return "analyzer-error";
        Frame<BasicValue>[] frames = ref.get();
        if (frames == null) return "analyzer-null";
        for (int i = 0; i < mn.instructions.size(); i++) {
            AbstractInsnNode n = mn.instructions.get(i);
            if (n instanceof JumpInsnNode) {
                JumpInsnNode j = (JumpInsnNode) n;
                if (!hasEmptyStack(mn, j.label, frames)) return "non-empty-stack";
            }
        }
        // The checks above only cover jump TARGETS. A block reached purely by
        // fall-through (no incoming jump) can carry values on the operand stack
        // across the block boundary. The flattener inserts its dispatcher stub
        // (s = id; goto dispatch) at every such boundary; if values are on the
        // stack there, the dispatcher's `ILOAD state; LOOKUPSWITCH` lands on top
        // of them and every subsequent operand is shifted, producing invalid
        // bytecode that COMPUTE_FRAMES happily serializes but the JVM verifier
        // rejects (e.g. "Bad type on operand stack: String not assignable to
        // integer at iadd" on Swing paintComponent-style methods). So we also
        // require an EMPTY stack at the entry and at every fall-through
        // successor, guaranteeing no operand-stack value crosses a block edge.
        if (frames[0] == null || frames[0].getStackSize() != 0) return "entry-stack";
        for (int i = 0; i < mn.instructions.size(); i++) {
            AbstractInsnNode n = mn.instructions.get(i);
            boolean isTerminator = false;
            if (n instanceof JumpInsnNode) {
                isTerminator = true;
            } else {
                int op = n.getOpcode();
                isTerminator = (op == Opcodes.RETURN || op == Opcodes.IRETURN
                        || op == Opcodes.LRETURN || op == Opcodes.FRETURN
                        || op == Opcodes.DRETURN || op == Opcodes.ARETURN
                        || op == Opcodes.ATHROW);
            }
            if (isTerminator) {
                AbstractInsnNode ft = skipLabels(n.getNext());
                if (ft != null) {
                    int ftIdx = indexOf(mn, ft);
                    if (ftIdx >= 0 && ftIdx < frames.length) {
                        Frame<BasicValue> ff = frames[ftIdx];
                        if (ff != null && ff.getStackSize() != 0) return "fall-thru-stack";
                    }
                }
            }
        }
        return null; // eligible
    }

    private static boolean hasEmptyStack(MethodNode mn, LabelNode label, Frame<BasicValue>[] frames) {
        int idx = indexOf(mn, label);
        if (idx < 0 || idx >= frames.length) return false;
        Frame<BasicValue> f = frames[idx];
        return f != null && f.getStackSize() == 0;
    }

    private static int indexOf(MethodNode mn, AbstractInsnNode target) {
        int i = 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n == target) return i;
            i++;
        }
        return -1;
    }

    private static int doFlatten(MethodNode mn, int strength) {
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
                AbstractInsnNode after = skipLabels(j.getNext());
                if (after != null) {
                    AbstractInsnNode lab = ensureLeaderLabel(mn, after, labelFor);
                    if (!leadersRaw.contains(lab)) leadersRaw.add(lab);
                }
            } else if (isReturn(op) || op == Opcodes.ATHROW) {
                AbstractInsnNode after = skipLabels(n.getNext());
                if (after != null) {
                    AbstractInsnNode lab = ensureLeaderLabel(mn, after, labelFor);
                    if (!leadersRaw.contains(lab)) leadersRaw.add(lab);
                }
            }
        }
        // Sort by traversal index.
        Map<AbstractInsnNode, Integer> pos = indexMap(mn);
        leadersRaw.sort((a, b) -> Integer.compare(pos.get(a), pos.get(b)));

        // 2. Assign ids (optionally shuffled at strength>=2 so switch cases look random).
        Map<AbstractInsnNode, Integer> idOf = new HashMap<>();
        List<Integer> ids = new ArrayList<>();
        for (int i = 0; i < leadersRaw.size(); i++) {
            idOf.put(leadersRaw.get(i), i);
            ids.add(i);
        }
        if (strength >= 2) {
            ThreadLocalRandom r = ThreadLocalRandom.current();
            for (int i = ids.size() - 1; i > 0; i--) {
                int j = r.nextInt(i + 1);
                int t = ids.get(i); ids.set(i, ids.get(j)); ids.set(j, t);
            }
        }

        // 3. Rewrite each block terminator: jumps become "s1 = id; s2 = mask; goto dispatch".
        //    Multi-state dispatch: the dispatcher keys on (s1 ^ s2), where s2 is a
        //    per-block rotation mask. Because s2 is fixed per block, the XOR always
        //    resolves back to the s1 value the block stored, but the visible case
        //    values are scrambled (blockId ^ mask) so a decompiler cannot statically
        //    recognise a fixed case/src transition.
        LabelNode dispatch = new LabelNode();
        int stateLocal = mn.maxLocals;
        int maskLocal = mn.maxLocals + 1;
        mn.maxLocals += 2;
        // Per-id rotation mask. mask[i] is derived deterministically so the build
        // is reproducible run-to-run.
        Map<Integer, Integer> idMask = new HashMap<>();
        int seed = 0x9E3779B9;
        java.util.Set<Integer> usedKeys = new java.util.HashSet<>();
        for (int i = 0; i < ids.size(); i++) {
            int mid = ids.get(i);
            int mask;
            int guard = 0;
            do {
                mask = Integer.rotateLeft(seed ^ (mid * 0x85EBCA6B), i & 31);
                guard++;
            } while (!usedKeys.add(mid ^ mask) && guard < 32);
            idMask.put(mid, mask);
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
                if (end != null) {
                    mn.instructions.insertBefore(end, exitStub(stateLocal, maskLocal, dispatch,
                            idOf.get(end), idMask.get(idOf.get(end))));
                }
                continue;
            }
            int top = term.getOpcode();
            if (top == Opcodes.GOTO) {
                JumpInsnNode g = (JumpInsnNode) term;
                int targetId = idOf.get(g.label);
                mn.instructions.insert(term, exitStub(stateLocal, maskLocal, dispatch,
                        targetId, idMask.get(targetId)));
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
                        takenId, idMask.get(takenId));
                while (stub.size() > 0) inverted.add(stub.getFirst());
                inverted.add(skip);
                mn.instructions.insert(term, inverted);
                mn.instructions.remove(term);
                if (fallThrough != null) {
                    AbstractInsnNode ftLab = labelFor.get(fallThrough);
                    if (ftLab == null) ftLab = ensureLeaderLabel(mn, fallThrough, labelFor);
                    Integer ftId = idOf.get(ftLab);
                    if (ftId != null) {
                        mn.instructions.insertBefore(ftLab, exitStub(stateLocal, maskLocal,
                                dispatch, ftId, idMask.get(ftId)));
                    }
                }
            }
        }

        // 4. Prepend: store entry id+mask; dispatch label; LOOKUPSWITCH on (s1 ^ s2).
        //    Add fake dispatch entries at strength >= 2 to bloat the switch table
        //    and confuse static analysis.
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        int fakeCount = (strength >= 3) ? rng.nextInt(8, 16) : (strength >= 2 ? rng.nextInt(3, 6) : 0);
        // Collect existing IDs to avoid collisions.
        java.util.Set<Integer> usedIds = new java.util.HashSet<>(ids);

        InsnList head = new InsnList();
        int entryId = ids.get(0);
        pushInt(head, entryId);
        head.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        pushInt(head, idMask.get(entryId));
        head.add(new VarInsnNode(Opcodes.ISTORE, maskLocal));
        head.add(dispatch);
        Map<Integer, LabelNode> idToLeader = new LinkedHashMap<>();
        for (int i = 0; i < leadersRaw.size(); i++) {
            idToLeader.put(ids.get(i), (LabelNode) leadersRaw.get(i));
        }
        // Generate fake labels that all point to the default (defensive throw)
        LabelNode def = new LabelNode();
        for (int i = 0; i < fakeCount; i++) {
            int fakeId;
            do { fakeId = rng.nextInt(100, 100000); } while (usedIds.contains(fakeId));
            usedIds.add(fakeId);
            idToLeader.put(fakeId, def);  // fake entries → default
        }
        head.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        head.add(new VarInsnNode(Opcodes.ILOAD, maskLocal));
        head.add(new InsnNode(Opcodes.IXOR));
        int total = idToLeader.size();
        int[] keys = new int[total];
        LabelNode[] lbls = new LabelNode[total];
        int idx = 0;
        for (Map.Entry<Integer, LabelNode> e : idToLeader.entrySet()) {
            Integer id = e.getKey();
            Integer mask = idMask.get(id);
            keys[idx] = (mask != null) ? (id ^ mask) : id;
            lbls[idx] = e.getValue();
            idx++;
        }
        head.add(new LookupSwitchInsnNode(def, keys, lbls));
        head.add(def);
        head.add(new InsnNode(Opcodes.ATHROW)); // unreachable: defensive
        mn.instructions.insertBefore(mn.instructions.getFirst(), head);
        return leadersRaw.size();
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

    /** {@code s1 = id; s2 = mask; goto dispatch;} */
    private static InsnList exitStub(int stateLocal, int maskLocal,
                                     LabelNode dispatch, int id, int mask) {
        InsnList l = new InsnList();
        pushInt(l, id);
        l.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        // s2 = mask so later (s1 ^ s2) == id at the dispatcher.
        pushInt(l, mask);
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

    private static boolean isReturn(int op) {
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
