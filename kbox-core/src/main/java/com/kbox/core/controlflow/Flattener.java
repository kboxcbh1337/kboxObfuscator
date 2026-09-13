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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
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
        String reason = checkEligibility(mn);
        if (reason != null) {
            cfLog("      skip " + mn.name + mn.desc
                    + " insn=" + insnSize + " branches=" + branches
                    + " [" + reason + "]");
            return false;
        }
        try {
            int bc = doFlatten(mn, strength);
            cfLog("      flat " + mn.name + mn.desc
                    + " insn=" + insnSize + "->" + mn.instructions.size()
                    + " blocks=" + bc + " branches=" + branches);
            return true;
        } catch (Exception e) {
            KBoxLog.warn(TAG, "Flatten aborted for " + mn.name + mn.desc
                    + ": " + e.getMessage());
            return false;
        }
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
    private static String checkEligibility(MethodNode mn) {
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return "try-catch";
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
                int next = i + 1;
                while (next < total && insns[next].getOpcode() == -1) next++;
                if (next < total) isBlockStart[next] = true;
            }
        }
        // Single O(n) height walk. h = operand-stack height in slots within the
        // current block (every block starts at height 0; any nonzero boundary
        // means a value would have to survive the dispatcher -> ineligible).
        int h = 0;
        for (int i = 0; i < total; i++) {
            if (isBlockStart[i] && h != 0) {
                return isJumpTarget[i] ? "non-empty-stack" : "fall-thru-stack";
            }
            int e = stackEffect(insns[i]);
            h += e;
            if (h < 0) return "stack-underflow";
            AbstractInsnNode n = insns[i];
            if (n instanceof JumpInsnNode) {
                int op = n.getOpcode();
                if (op == Opcodes.GOTO) {
                    // GOTO transfers the whole stack; successor must be empty.
                    if (h != 0) return "fall-thru-stack";
                } else if (op != Opcodes.JSR) {
                    // Conditional: pops its condition on BOTH paths; successors
                    // (target + fall-through) must both be empty.
                    if (h != 0) return "non-empty-stack";
                }
            }
        }
        return null; // eligible
    }

    /**
     * Net operand-stack height effect (pushes − pops, in slots) of one
     * instruction. Long/double count 2 slots. Type-independent.
     */
    private static int stackEffect(AbstractInsnNode n) {
        int op = n.getOpcode();
        if (op == -1) return 0; // labels / frames / line numbers
        switch (op) {
            // Pushes
            case Opcodes.ACONST_NULL: case Opcodes.ICONST_M1: case Opcodes.ICONST_0:
            case Opcodes.ICONST_1: case Opcodes.ICONST_2: case Opcodes.ICONST_3:
            case Opcodes.ICONST_4: case Opcodes.ICONST_5: case Opcodes.BIPUSH:
            case Opcodes.SIPUSH: case Opcodes.FCONST_0: case Opcodes.FCONST_1:
            case Opcodes.FCONST_2: case Opcodes.NEW: case Opcodes.NEWARRAY:
                return 1;
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
            int v = Type.getArgumentsAndReturnSizes(
                    (n instanceof MethodInsnNode)
                            ? ((MethodInsnNode) n).desc
                            : ((InvokeDynamicInsnNode) n).desc);
            int argSlots = v >>> 2;
            int retSlots = v & 0x03; // 0=void, 1=one slot, 2=long/double
            if (n instanceof MethodInsnNode && op != Opcodes.INVOKESTATIC) {
                return retSlots - (argSlots + 1); // receiver
            }
            return retSlots - argSlots;
        }
        return 0; // unknown instruction: neutral (never reached for valid bytecode)
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
