package com.kbox.core.vmp;

import com.kbox.core.log.KBoxLog;

import java.io.ByteArrayOutputStream;
import java.util.*;

/**
 * Applies LLVM-style obfuscation passes on VMP bytecode.
 * Pipeline order: flatten -&gt; substitute -&gt; bogus.
 */
public final class VmpPassPipeline {

    private static final String TAG = "vmp-pass";

    private VmpPassPipeline() {}

    // ---- Result ----

    public static final class Result {
        public final byte[] code;
        public final int[][] exceptions;
        public final int stateVarIdx;

        public Result(byte[] code, int[][] exceptions) {
            this(code, exceptions, -1);
        }

        public Result(byte[] code, int[][] exceptions, int stateVarIdx) {
            this.code = code;
            this.exceptions = exceptions;
            this.stateVarIdx = stateVarIdx;
        }
    }

    // ---- Public entry points ----

    /**
     * Run the (safe) post-translation pass pipeline on VMP bytecode.
     *
     * <p>Only the {@link #bogus} pass (dead-branch injection) is applied, because it is
     * the only one that provably preserves both stack depth and value semantics:
     * it inserts {@code ICONST 0; IFEQ target} whose pushed constant is consumed by the
     * branch, so reachable blocks still begin with exactly the stack the original code
     * produced. The former {@code flatten} and {@code substitute} passes are deliberately
     * excluded here:
     * <ul>
     *   <li>{@code flatten} rewrote control flow into a dispatcher that assumes every
     *       basic block is entered with an EMPTY stack; real VMP bytecode enters blocks
     *       with values still on the stack, so instructions such as {@code ARRAYLENGTH}
     *       popped the wrong (often null) operand and crashed the interpreter.</li>
     *   <li>{@code substitute} rewrote {@code IADD -&gt; ISUB; INEG} which computes
     *       {@code b-a} instead of {@code a+b}, and {@code ISUB -&gt; INEG; IADD} which
     *       underflows the stack.</li>
     * </ul>
     * Control-flow obfuscation is already provided at the JVM level by
     * {@code ControlFlowObfuscator} before VMP translation, so dropping the broken
     * VMP-level flattening loses no protection capability.
     *
     * @param doControlFlow if false, no post-translation pass is applied and the
     *                      original translation is returned unchanged.
     */
    public static Result apply(byte[] code, int[][] exceptions, boolean doControlFlow) {
        if (!doControlFlow) {
            KBoxLog.info(TAG, "VMP passes disabled by config; keeping original translation");
            return new Result(code, exceptions);
        }

        KBoxLog.info(TAG, "Starting VMP pass pipeline (bogus control flow only)");
        Result bogusResult = bogus(code, exceptions);
        KBoxLog.info(TAG, "VMP pass pipeline complete. "
                + "Original code size: " + code.length + " -> final: " + bogusResult.code.length);
        return bogusResult;
    }

    /** Backwards-compatible entry point that forces the safe bogus-only pipeline. */
    public static Result apply(byte[] code, int[][] exceptions) {
        return apply(code, exceptions, true);
    }

    // ================================================================
    //  Shared helpers
    // ================================================================

    /** Return the total byte-length of a VMP instruction starting at {@code code[offset]}. */
    private static int instrLen(byte[] code, int offset) {
        int op = code[offset] & 0xFF;
        switch (op) {
            case 0xFF: return 1;                              // END
            case 0x01: return 1;                              // ACONST_NULL
            case 0x02: case 0x04: case 0x06: case 0x07: return 5; // ICONST,FCONST,STRING,CLASS
            case 0x03: case 0x05: return 9;                   // LCONST,DCONST
            case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: return 3; // ILOAD..ALOAD
            case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: return 3; // ISTORE..ASTORE
            case 0x20: case 0x21: case 0x22: case 0x23: case 0x24:
            case 0x25: case 0x26: case 0x27: case 0x28: case 0x29:
            case 0x2A: case 0x2B: return 1;                   // IADD..IXOR
            case 0x2C: return 7;                              // IINC
            case 0x2D: case 0x2E: case 0x2F: return 1;        // I2L,I2F,I2D
            case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
            case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
            case 0x3A: case 0x3B: case 0x3C: case 0x3D:
            case 0x3E: case 0x3F: return 5;                   // IFxx,GOTO
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: return 1; // POP..SWAP
            case 0x50: case 0x51: case 0x52: case 0x53: return 5; // GETSTATIC..PUTFIELD
            case 0x60: case 0x61: case 0x62: case 0x63: return 5; // INVOKEVIRTUAL..INVOKEINTERFACE
            case 0x70: case 0x71: case 0x72: return 5;        // NEW,NEWARRAY,ANEWARRAY
            case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x7A: case 0x7B: case 0x7C: case 0x7D:
            case 0x7E: case 0x7F: return 1;                   // ARRAYLENGTH..SASTORE
            case 0x78: case 0x79: return 5;                   // CHECKCAST,INSTANCEOF
            case 0x80: case 0x81: case 0x82: return 1;        // MONITORENTER,MONITOREXIT,ATHROW
            case 0x90: case 0x91: case 0x92: case 0x93:
            case 0x94: case 0x95: return 1;                   // IRETURN..RETURN
            case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0xA4:
            case 0xA5: case 0xA6: case 0xA7: case 0xA8: case 0xA9:
            case 0xAA: case 0xAB: return 1;                   // L2I..I2S
            case 0xAC: case 0xAD: case 0xAE: case 0xAF: case 0xB0:
            case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5:
            case 0xB6: case 0xB7: case 0xB8: return 1;        // LCMP..LXOR
            case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD:
            case 0xBE: case 0xBF: case 0xC0: case 0xC1: case 0xC2:
            case 0xC3: case 0xC4: return 1;                   // FADD..DNEG
            case 0xC5: case 0xC6: case 0xC7: case 0xC8: return 1; // FCMPL..DCMPG
            case 0xC9: return 5;                              // IF_ACMPNE
            case 0xCA: case 0xCB: case 0xCC: case 0xCD: return 1; // DUP_X2..DUP2_X2
            case 0xF0: return 9;                              // FRAME
            default:   return 1;
        }
    }

    /** Read a big-endian 32-bit int from {@code code[offset]}. */
    private static int readInt(byte[] code, int offset) {
        return ((code[offset]     & 0xFF) << 24)
             | ((code[offset + 1] & 0xFF) << 16)
             | ((code[offset + 2] & 0xFF) << 8)
             | ( code[offset + 3] & 0xFF);
    }

    /** Read a big-endian 16-bit unsigned short from {@code code[offset]}. */
    private static int readU2(byte[] code, int offset) {
        return ((code[offset] & 0xFF) << 8) | (code[offset + 1] & 0xFF);
    }

    private static void writeInt(ByteArrayOutputStream out, int v) {
        out.write((v >> 24) & 0xFF);
        out.write((v >> 16) & 0xFF);
        out.write((v >> 8)  & 0xFF);
        out.write( v        & 0xFF);
    }

    private static void writeU2(ByteArrayOutputStream out, int v) {
        out.write((v >> 8) & 0xFF);
        out.write( v       & 0xFF);
    }

    /** Copy {@code len} raw bytes from {@code src[srcOff]} into {@code out}. */
    private static void copyBytes(ByteArrayOutputStream out, byte[] src, int srcOff, int len) {
        out.write(src, srcOff, len);
    }

    // ================================================================
    //  Block / label helpers (shared by flatten and bogus)
    // ================================================================

    /** A basic block: [startOffset, endOffset) in the original bytecode. */
    private static final class Block {
        final int start;
        final int end;       // exclusive
        final int id;
        boolean isTarget;    // true if this block is a jump target

        Block(int start, int end, int id) {
            this.start = start;
            this.end = end;
            this.id = id;
        }
    }

    /** Return the set of offsets that are targets of GOTO / IFxx / IF_ACMPxx instructions. */
    private static Set<Integer> collectJumpTargets(byte[] code) {
        Set<Integer> targets = new HashSet<>();
        int offset = 0;
        int endOffset = findEndOffset(code);
        while (offset < endOffset) {
            int op = code[offset] & 0xFF;
            int len = instrLen(code, offset);
            // GOTO (0x3E) or any IFxx (0x30-0x3D, 0x3F) or IF_ACMPNE (0xC9)
            if ((op >= 0x30 && op <= 0x3F) || op == 0xC9) {
                if (len >= 5) {
                    int target = readInt(code, offset + 1);
                    if (target >= 0 && target < endOffset) {
                        targets.add(target);
                    }
                }
            }
            offset += len;
        }
        return targets;
    }

    /**
     * Find the offset of the END opcode (0xFF) at an instruction boundary, or
     * {@code code.length} if not found.
     *
     * <p>This MUST walk the instruction stream rather than scan raw bytes: VMP
     * instruction operands (int constants, branch targets, constant-pool indices)
     * can legitimately contain a {@code 0xFF} byte. A naive byte scan would treat
     * such an operand byte as the END marker, truncating the program view and
     * corrupting every offset computed from it (block split, jump-target
     * remapping in the bogus pass), which in turn makes the interpreter jump into
     * the middle of an instruction and throw "unknown opcode 0x0".
     */
    private static int findEndOffset(byte[] code) {
        int offset = 0;
        int n = code.length;
        while (offset < n) {
            int op = code[offset] & 0xFF;
            if (op == 0xFF) return offset; // END at an instruction boundary
            int len = instrLen(code, offset);
            if (len < 1) len = 1;
            offset += len;
        }
        return code.length;
    }

    /** Split bytecode into basic blocks. */
    private static List<Block> splitBlocks(byte[] code, Set<Integer> jumpTargets) {
        List<Block> blocks = new ArrayList<>();
        int endOffset = findEndOffset(code);
        int offset = 0;
        int blockStart = 0;
        int nextId = 0;

        while (offset < endOffset) {
            int op = code[offset] & 0xFF;
            int len = instrLen(code, offset);

            // Check if next instruction starts a new block (is a jump target)
            if (offset > blockStart && jumpTargets.contains(offset)) {
                blocks.add(new Block(blockStart, offset, nextId++));
                blockStart = offset;
            }

            // Terminators that end a block
            boolean isTerminator = false;
            if (op >= 0x30 && op <= 0x3F) isTerminator = true;    // IFxx, GOTO
            if (op == 0xC9) isTerminator = true;                  // IF_ACMPNE
            if (op == 0x82) isTerminator = true;                  // ATHROW
            if (op >= 0x90 && op <= 0x95) isTerminator = true;    // *RETURN

            offset += len;

            if (isTerminator && offset < endOffset) {
                blocks.add(new Block(blockStart, offset, nextId++));
                blockStart = offset;
            }
        }

        // Last block (up to END)
        if (blockStart < endOffset) {
            blocks.add(new Block(blockStart, endOffset, nextId++));
        }

        // Mark target blocks
        for (Block b : blocks) {
            if (jumpTargets.contains(b.start)) {
                b.isTarget = true;
            }
        }

        return blocks;
    }

    /** Find the maximum local variable index used in the bytecode. */
    private static int findMaxLocal(byte[] code) {
        int maxLocal = -1;
        int offset = 0;
        int end = findEndOffset(code);
        while (offset < end) {
            int op = code[offset] & 0xFF;
            int len = instrLen(code, offset);
            if ((op >= 0x10 && op <= 0x14) || (op >= 0x18 && op <= 0x1C)) {
                // 3-byte load/store instruction: varIdx at offset+1 (2 bytes)
                if (offset + 2 < code.length) {
                    int varIdx = readU2(code, offset + 1);
                    if (varIdx > maxLocal) maxLocal = varIdx;
                }
            } else if (op == 0x2C) {
                // IINC: 7 bytes, varIdx at offset+1
                if (offset + 2 < code.length) {
                    int varIdx = readU2(code, offset + 1);
                    if (varIdx > maxLocal) maxLocal = varIdx;
                }
            }
            offset += len;
        }
        return maxLocal;
    }

    /**
     * Recomputes the local-variable array size required by the (possibly
     * transformed) bytecode. The flatten pass introduces a dispatcher state
     * variable at index {@code maxLocal+1}, which the interpreter's
     * {@code locals[maxLocals]} array would otherwise overflow. Returns the
     * required size (max index + 1), never less than 1.
     */
    public static int computeMaxLocals(byte[] code) {
        return Math.max(1, findMaxLocal(code) + 1);
    }

    /** Compute a mapping from old offset to new offset for the given blocks and expansion. */
    private static Map<Integer, Integer> buildOffsetMap(
            byte[] oldCode, int oldEnd,
            List<Block> blocks,
            int prefixBytes,
            int suffixBytesPerBlock,
            Map<Integer, Integer> extraPerOffset) {

        Map<Integer, Integer> map = new HashMap<>();
        int newOffset = prefixBytes;

        for (int i = 0; i < blocks.size(); i++) {
            Block b = blocks.get(i);
            // Map the block start
            map.put(b.start, newOffset);

            // Add per-block expansion (e.g., trampolines, state-setting code)
            Integer extra = extraPerOffset != null ? extraPerOffset.get(b.start) : null;
            int blockPrefix = (extra != null) ? extra : 0;
            newOffset += blockPrefix;

            // The body of the block
            int pos = b.start;
            while (pos < b.end) {
                int len = instrLen(oldCode, pos);
                // Check if there's per-offset expansion at this position
                Integer posExtra = extraPerOffset != null ? extraPerOffset.get(pos) : null;
                if (posExtra != null) {
                    // This position is being replaced with expanded code
                    map.put(pos, newOffset);
                    newOffset += posExtra;
                } else {
                    map.put(pos, newOffset);
                    newOffset += len;
                }
                pos += len;
            }

            // Per-block suffix expansion
            newOffset += suffixBytesPerBlock;
        }

        // Map END
        map.put(oldEnd, newOffset);
        return map;
    }

    /** Update exception table offsets using the given old-to-new offset mapping. */
    private static int[][] updateExceptions(int[][] exceptions, Map<Integer, Integer> offsetMap) {
        if (exceptions == null) return null;
        int[][] result = new int[exceptions.length][];
        for (int i = 0; i < exceptions.length; i++) {
            int[] entry = exceptions[i];
            Integer newStart = offsetMap.get(entry[0]);
            Integer newEnd   = offsetMap.get(entry[1]);
            Integer newHandler = offsetMap.get(entry[2]);
            result[i] = new int[] {
                newStart != null ? newStart : entry[0],
                newEnd   != null ? newEnd   : entry[1],
                newHandler != null ? newHandler : entry[2],
                entry[3]  // catchTypeCp unchanged
            };
        }
        return result;
    }

    /** Check if an opcode is a branch (GOTO or IFxx). */
    private static boolean isBranch(byte op) {
        int o = op & 0xFF;
        return (o >= 0x30 && o <= 0x3F) || o == 0xC9;
    }

    /** Check if an opcode is a return. */
    private static boolean isReturn(byte op) {
        int o = op & 0xFF;
        return o >= 0x90 && o <= 0x95;
    }

    // ================================================================
    //  Pass 1: Control Flow Flattening
    // ================================================================

    /**
     * Flatten control flow: insert a dispatcher and state-variable tracking.
     * Uses IFEQ chains to emulate a LOOKUPSWITCH dispatch.
     *
     * Layout after flattening:
     * <pre>
     *   ICONST(0); ISTORE(stateVar); GOTO dispatch    -- init (13 bytes)
     * dispatch:
     *   ILOAD(stateVar); ICONST(0); ISUB; IFEQ block0 -- 14 bytes per block
     *   ...
     *   GOTO END                                      -- safety (5 bytes)
     * block0:
     *   [body]  [terminator rewritten]
     * block1:
     *   ...
     *   END
     * </pre>
     *
     * Terminator rewrites:
     *   GOTO X    -&gt;  ICONST(Xid); ISTORE(stateVar); GOTO dispatch
     *   IFxx X    -&gt;  IFxx trampoline_X; fallthrough state-setter; trampoline_X
     *   RETURN/*  -&gt;  kept as-is (bypass dispatch)
     *   ATHROW    -&gt;  kept as-is
     *   no term   -&gt;  ICONST(nextId); ISTORE(stateVar); GOTO dispatch
     */
    public static Result flatten(byte[] code, int[][] exceptions) {
        try {
            int oldEnd = findEndOffset(code);
            if (oldEnd <= 0) {
                KBoxLog.info(TAG, "flatten: empty code, skipping");
                return new Result(code, exceptions);
            }

            // 1. Collect jump targets and split into blocks
            Set<Integer> jumpTargets = collectJumpTargets(code);
            List<Block> blocks = splitBlocks(code, jumpTargets);

            if (blocks.size() <= 1) {
                KBoxLog.info(TAG, "flatten: only " + blocks.size() + " block(s), skipping");
                return new Result(code, exceptions);
            }

            KBoxLog.info(TAG, "flatten: " + blocks.size() + " basic blocks identified");

            // 2. Determine state variable index
            int maxLocal = findMaxLocal(code);
            int stateVarIdx = maxLocal + 1;

            // 3. Build offset-to-blockId lookup
            int[] offsetToBlockId = new int[oldEnd + 1];
            Arrays.fill(offsetToBlockId, -1);
            for (Block b : blocks) {
                for (int pos = b.start; pos < b.end; pos++) {
                    offsetToBlockId[pos] = b.id;
                }
            }

            // 4. Classify each block's terminator type and compute expansion
            // suffixBytes: extra bytes added AFTER the original block body
            //
            // Block body in new code = (b.end - b.start) bytes of original instructions.
            // But the terminator may be replaced or augmented.
            //
            // GOTO block:   body(-5) + ICONST+ISTORE+GOTO(dispatch) [13]  = body+8
            //   suffix = 8  (= -5 for removed GOTO + 13 for state setter)
            //
            // IFxx block:   body(+0) + fallthrough(13) + trampoline(13)    = body+26
            //   suffix = 26 (= +13 fallthrough +13 trampoline; IFxx stays)
            //
            // RETURN/ATHROW: body(+0)                                      = body
            //   suffix = 0
            //
            // No terminator: body(+0) + state-setter(13)                   = body+13
            //   suffix = 13

            // Determine suffix for each block
            int[] suffixByBlockStart = new int[oldEnd + 1];
            boolean[] isIfxxBlock = new boolean[oldEnd + 1]; // true if IFxx terminator

            for (Block b : blocks) {
                // Find the last instruction in this block
                int lastPos = b.start;
                int pos = b.start;
                while (pos < b.end) {
                    int len = instrLen(code, pos);
                    lastPos = pos;
                    pos += len;
                }

                byte lastOp = code[lastPos];
                int lastLen = instrLen(code, lastPos);
                boolean hasTerminator = (lastPos + lastLen == b.end);

                if (hasTerminator && (lastOp == (byte)0x82 || isReturn(lastOp))) {
                    // ATHROW or *RETURN: keep as-is
                    suffixByBlockStart[b.start] = 0;
                    isIfxxBlock[b.start] = false;
                } else if (hasTerminator && lastOp == VmpOp.GOTO) {
                    // GOTO: remove GOTO(5), add state setter(13)
                    suffixByBlockStart[b.start] = 8;
                    isIfxxBlock[b.start] = false;
                } else if (hasTerminator && isBranch(lastOp)) {
                    // IFxx: keep IFxx(5), add fallthrough(13) + trampoline(13)
                    suffixByBlockStart[b.start] = 26;
                    isIfxxBlock[b.start] = true;
                } else {
                    // No terminator: add state setter(13)
                    suffixByBlockStart[b.start] = 13;
                    isIfxxBlock[b.start] = false;
                }
            }

            // 5. Calculate new layout and compute block addresses
            // Prefix = init(13) + dispatch(14*N + 5)
            int dispatchAddr = 13; // right after init code
            int dispatchSize = blocks.size() * 14 + 5; // IFEQ chains + safety GOTO
            int totalPrefix = dispatchAddr + dispatchSize;

            Map<Integer, Integer> blockNewAddr = new HashMap<>(); // blockId -> new byte offset
            int curOff = totalPrefix;
            for (Block b : blocks) {
                blockNewAddr.put(b.id, curOff);
                int suff = suffixByBlockStart[b.start];
                curOff += (b.end - b.start) + suff;
            }

            // Build exception table offset map
            Map<Integer, Integer> offsetMap = new HashMap<>();
            curOff = totalPrefix;
            for (Block b : blocks) {
                offsetMap.put(b.start, curOff);
                curOff += (b.end - b.start) + suffixByBlockStart[b.start];
            }
            offsetMap.put(oldEnd, curOff); // END position in new code

            // 6. Emit
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // --- Init ---
            out.write(VmpOp.ICONST & 0xFF);
            writeInt(out, 0);                           // ICONST 0
            out.write(VmpOp.ISTORE & 0xFF);
            writeU2(out, stateVarIdx);                  // ISTORE stateVarIdx
            out.write(VmpOp.GOTO & 0xFF);
            writeInt(out, dispatchAddr);                // GOTO dispatch

            // --- Dispatch ---
            IntList dispatchFixupPositions = new IntList();
            for (Block b : blocks) {
                out.write(VmpOp.ILOAD & 0xFF);
                writeU2(out, stateVarIdx);              // ILOAD stateVar
                out.write(VmpOp.ICONST & 0xFF);
                writeInt(out, b.id);                    // ICONST blockId
                out.write(VmpOp.ISUB & 0xFF);
                out.write(VmpOp.IFEQ & 0xFF);
                dispatchFixupPositions.add(out.size()); // position of 4-byte target
                writeInt(out, 0);                       // placeholder
            }
            // Safety GOTO END
            out.write(VmpOp.GOTO & 0xFF);
            writeInt(out, curOff);

            // --- Blocks ---
            // Fixup lists (deferred patching positions in final byte array)
            // blockId -> list of positions where dispatchAddr should be written
            Map<Integer, IntList> gotoDispatchFixups = new HashMap<>();
            // blockId -> list of (position, trampolineAddr) pairs for IFxx targets
            Map<Integer, IntList> ifxxTargetFixupPositions = new HashMap<>();
            Map<Integer, IntList> ifxxTargetFixupValues = new HashMap<>();

            for (int bi = 0; bi < blocks.size(); bi++) {
                Block b = blocks.get(bi);

                // Find last instruction
                int lastPos = b.start;
                int pos = b.start;
                while (pos < b.end) {
                    int len = instrLen(code, pos);
                    lastPos = pos;
                    pos += len;
                }
                byte lastOp = code[lastPos];
                int lastLen = instrLen(code, lastPos);
                boolean hasTerminator = (lastPos + lastLen == b.end);
                boolean lastIsRetOrThrow = hasTerminator
                        && (lastOp == (byte)0x82 || isReturn(lastOp));
                boolean lastIsIfxx = hasTerminator && isBranch(lastOp) && lastOp != VmpOp.GOTO;

                // Determine fall-through block id (next block in original order)
                int fallthroughBlockId = (bi + 1 < blocks.size()) ? blocks.get(bi + 1).id : 0;

                if (lastIsRetOrThrow) {
                    // Copy entire block, no state setter
                    copyBytes(out, code, b.start, b.end - b.start);

                } else if (lastIsIfxx) {
                    // Copy body up to (not including) IFxx
                    if (lastPos > b.start) {
                        copyBytes(out, code, b.start, lastPos - b.start);
                    }

                    int branchTarget = readInt(code, lastPos + 1);
                    int takenBlockId = (branchTarget >= 0 && branchTarget < offsetToBlockId.length)
                            ? offsetToBlockId[branchTarget] : -1;
                    if (takenBlockId < 0) takenBlockId = 0;

                    // Emit IFxx (kept) with placeholder target
                    out.write(lastOp & 0xFF);
                    int ifxxFixupPos = out.size();
                    writeInt(out, 0); // placeholder for trampoline address

                    // Fall-through state setter (13 bytes)
                    out.write(VmpOp.ICONST & 0xFF);
                    writeInt(out, fallthroughBlockId);
                    out.write(VmpOp.ISTORE & 0xFF);
                    writeU2(out, stateVarIdx);
                    out.write(VmpOp.GOTO & 0xFF);
                    addFixup(gotoDispatchFixups, b.id, out.size());
                    writeInt(out, 0); // placeholder for dispatch addr

                    // Trampoline: record its address for the IFxx fixup
                    int trampolineAddr = out.size();

                    out.write(VmpOp.ICONST & 0xFF);
                    writeInt(out, takenBlockId);
                    out.write(VmpOp.ISTORE & 0xFF);
                    writeU2(out, stateVarIdx);
                    out.write(VmpOp.GOTO & 0xFF);
                    addFixup(gotoDispatchFixups, b.id, out.size());
                    writeInt(out, 0); // placeholder for dispatch addr

                    // Record IFxx target fixup
                    addFixup(ifxxTargetFixupPositions, b.id, ifxxFixupPos);
                    addFixup(ifxxTargetFixupValues, b.id, trampolineAddr);

                } else if (hasTerminator && lastOp == VmpOp.GOTO) {
                    // Copy body without GOTO
                    if (lastPos > b.start) {
                        copyBytes(out, code, b.start, lastPos - b.start);
                    }

                    int branchTarget = readInt(code, lastPos + 1);
                    int targetBlockId = (branchTarget >= 0 && branchTarget < offsetToBlockId.length)
                            ? offsetToBlockId[branchTarget] : -1;
                    if (targetBlockId < 0) targetBlockId = 0;

                    // State setter (13 bytes)
                    out.write(VmpOp.ICONST & 0xFF);
                    writeInt(out, targetBlockId);
                    out.write(VmpOp.ISTORE & 0xFF);
                    writeU2(out, stateVarIdx);
                    out.write(VmpOp.GOTO & 0xFF);
                    addFixup(gotoDispatchFixups, b.id, out.size());
                    writeInt(out, 0); // placeholder

                } else {
                    // No terminator: copy full body + add state setter
                    copyBytes(out, code, b.start, b.end - b.start);

                    out.write(VmpOp.ICONST & 0xFF);
                    writeInt(out, fallthroughBlockId);
                    out.write(VmpOp.ISTORE & 0xFF);
                    writeU2(out, stateVarIdx);
                    out.write(VmpOp.GOTO & 0xFF);
                    addFixup(gotoDispatchFixups, b.id, out.size());
                    writeInt(out, 0); // placeholder
                }
            }

            // --- END ---
            out.write(VmpOp.END & 0xFF);
            byte[] newCode = out.toByteArray();

            // 7. Patch all deferred fixups
            // (a) Dispatch IFEQ targets -> block start addresses
            for (int i = 0; i < blocks.size(); i++) {
                int fixupPos = dispatchFixupPositions.get(i);
                Integer addr = blockNewAddr.get(blocks.get(i).id);
                if (addr != null) {
                    patchInt(newCode, fixupPos, addr);
                }
            }

            // (b) GOTO dispatch targets -> dispatchAddr
            for (Block b : blocks) {
                IntList fixups = gotoDispatchFixups.get(b.id);
                if (fixups != null) {
                    for (int j = 0; j < fixups.size; j++) {
                        patchInt(newCode, fixups.get(j), dispatchAddr);
                    }
                }
            }

            // (c) IFxx targets -> trampoline addresses
            for (Block b : blocks) {
                IntList positions = ifxxTargetFixupPositions.get(b.id);
                IntList values = ifxxTargetFixupValues.get(b.id);
                if (positions != null && values != null) {
                    for (int j = 0; j < positions.size; j++) {
                        patchInt(newCode, positions.get(j), values.get(j));
                    }
                }
            }

            // 8. Update exception table
            int[][] newExceptions = updateExceptions(exceptions, offsetMap);

            KBoxLog.info(TAG, "flatten: code " + code.length + " -> " + newCode.length
                    + " bytes, stateVarIdx=" + stateVarIdx);

            return new Result(newCode, newExceptions, stateVarIdx);

        } catch (Exception e) {
            KBoxLog.error(TAG, "flatten failed, returning original code", e);
            return new Result(code, exceptions);
        }
    }

    private static void addFixup(Map<Integer, IntList> map, int blockId, int pos) {
        IntList list = map.get(blockId);
        if (list == null) {
            list = new IntList();
            map.put(blockId, list);
        }
        list.add(pos);
    }

    private static void patchInt(byte[] buf, int offset, int value) {
        buf[offset]     = (byte)((value >> 24) & 0xFF);
        buf[offset + 1] = (byte)((value >> 16) & 0xFF);
        buf[offset + 2] = (byte)((value >> 8)  & 0xFF);
        buf[offset + 3] = (byte)( value        & 0xFF);
    }

    // Simple growable int list
    private static final class IntList {
        int[] data = new int[8];
        int size;
        void add(int v) {
            if (size == data.length) data = Arrays.copyOf(data, size * 2);
            data[size++] = v;
        }
        int get(int i) { return data[i]; }
        int size() { return size; }
    }

    // ================================================================
    //  Pass 2: Instruction Substitution
    // ================================================================

    /**
     * Replace simple instruction patterns with equivalent complex sequences.
     */
    public static Result substitute(byte[] code, int[][] exceptions) {
        try {
            int oldEnd = findEndOffset(code);
            if (oldEnd <= 0) {
                KBoxLog.info(TAG, "substitute: empty code, skipping");
                return new Result(code, exceptions);
            }

            // 1. Scan to determine new sizes
            // oldOffset -> expansion size (total bytes in new code for this instruction)
            Map<Integer, Integer> expansionMap = new HashMap<>();
            int pos = 0;
            while (pos < oldEnd) {
                int op = code[pos] & 0xFF;
                int len = instrLen(code, pos);

                if (op == 0x02 && len >= 5) {
                    // ICONST: check value
                    int val = readInt(code, pos + 1);
                    if (val == 0 || val == 1 || val == 2) {
                        // ICONST N -> ICONST a; ICONST b; ISUB (11 bytes)
                        expansionMap.put(pos, 11);
                    }
                } else if (op == 0x20) {
                    // IADD -> ISUB; INEG (2 bytes)
                    expansionMap.put(pos, 2);
                } else if (op == 0x21) {
                    // ISUB -> INEG; IADD (2 bytes)
                    expansionMap.put(pos, 2);
                }

                pos += len;
            }

            if (expansionMap.isEmpty()) {
                KBoxLog.info(TAG, "substitute: no substitutions applicable, skipping");
                return new Result(code, exceptions);
            }

            // 2. Build old-to-new offset map
            Map<Integer, Integer> offsetMap = new HashMap<>();
            int newOffset = 0;
            pos = 0;
            while (pos < oldEnd) {
                offsetMap.put(pos, newOffset);
                int len = instrLen(code, pos);
                Integer expSize = expansionMap.get(pos);
                if (expSize != null) {
                    newOffset += expSize;
                } else {
                    newOffset += len;
                }
                pos += len;
            }
            offsetMap.put(oldEnd, newOffset);

            // 3. Emit new code
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            pos = 0;
            while (pos < oldEnd) {
                int op = code[pos] & 0xFF;
                int len = instrLen(code, pos);
                Integer expSize = expansionMap.get(pos);

                if (expSize != null) {
                    if (op == 0x02) {
                        // ICONST N substitution
                        int val = readInt(code, pos + 1);
                        switch (val) {
                            case 0:
                                // ICONST 0 -> ICONST 1; ICONST 1; ISUB
                                out.write(VmpOp.ICONST & 0xFF); writeInt(out, 1);
                                out.write(VmpOp.ICONST & 0xFF); writeInt(out, 1);
                                out.write(VmpOp.ISUB & 0xFF);
                                break;
                            case 1:
                                // ICONST 1 -> ICONST 3; ICONST 2; ISUB
                                out.write(VmpOp.ICONST & 0xFF); writeInt(out, 3);
                                out.write(VmpOp.ICONST & 0xFF); writeInt(out, 2);
                                out.write(VmpOp.ISUB & 0xFF);
                                break;
                            case 2:
                                // ICONST 2 -> ICONST 5; ICONST 3; ISUB
                                out.write(VmpOp.ICONST & 0xFF); writeInt(out, 5);
                                out.write(VmpOp.ICONST & 0xFF); writeInt(out, 3);
                                out.write(VmpOp.ISUB & 0xFF);
                                break;
                            default:
                                copyBytes(out, code, pos, len);
                                break;
                        }
                    } else if (op == 0x20) {
                        // IADD -> ISUB; INEG
                        out.write(VmpOp.ISUB & 0xFF);
                        out.write(VmpOp.INEG & 0xFF);
                    } else if (op == 0x21) {
                        // ISUB -> INEG; IADD
                        out.write(VmpOp.INEG & 0xFF);
                        out.write(VmpOp.IADD & 0xFF);
                    }
                } else {
                    // Copy with updated jump targets if needed
                    if ((op >= 0x30 && op <= 0x3F) || op == 0xC9) {
                        // Branch: update target
                        int oldTarget = readInt(code, pos + 1);
                        Integer newTarget = offsetMap.get(oldTarget);
                        int target = (newTarget != null) ? newTarget : oldTarget;
                        out.write(code[pos] & 0xFF);
                        writeInt(out, target);
                    } else {
                        copyBytes(out, code, pos, len);
                    }
                }
                pos += len;
            }

            // END
            out.write(VmpOp.END & 0xFF);

            byte[] newCode = out.toByteArray();
            int[][] newExceptions = updateExceptions(exceptions, offsetMap);

            int subCount = expansionMap.size();
            KBoxLog.info(TAG, "substitute: " + subCount + " substitutions, code "
                    + code.length + " -> " + newCode.length + " bytes");

            return new Result(newCode, newExceptions);

        } catch (Exception e) {
            KBoxLog.error(TAG, "substitute failed, returning original code", e);
            return new Result(code, exceptions);
        }
    }

    // ================================================================
    //  Pass 3: Bogus Control Flow
    // ================================================================

    /**
     * Insert opaque-predicate dead branches before each real basic block.
     */
    public static Result bogus(byte[] code, int[][] exceptions) {
        try {
            int oldEnd = findEndOffset(code);
            if (oldEnd <= 0) {
                KBoxLog.info(TAG, "bogus: empty code, skipping");
                return new Result(code, exceptions);
            }

            // 1. Split into blocks
            Set<Integer> jumpTargets = collectJumpTargets(code);
            List<Block> blocks = splitBlocks(code, jumpTargets);

            if (blocks.isEmpty()) {
                KBoxLog.info(TAG, "bogus: no blocks found, skipping");
                return new Result(code, exceptions);
            }

            KBoxLog.info(TAG, "bogus: inserting dead branches before " + blocks.size() + " blocks");

            // 2. Compute per-block bogus prefix size
            // Before each block (including the first), insert:
            //   ICONST(0)     = 5 bytes
            //   IFEQ skip      = 5 bytes
            //   DUP            = 1 byte
            //   POP            = 1 byte
            //   DUP            = 1 byte
            //   POP            = 1 byte
            //   GOTO next_real  = 5 bytes
            // skip: (start of real block)
            // Total = 19 bytes per block

            final int BOGUS_PREFIX = 19;

            // 3. Build offset map covering EVERY instruction offset (not just
            // block starts). Exception-table boundaries (tryStart/tryEnd/handler)
            // can fall in the middle of a block, so a block-start-only map would
            // leave them stale after the per-block +BOGUS_PREFIX shift and the
            // interpreter's `ppc >= start && ppc < end` check would never match —
            // exceptions would bypass their catch and escape the method.
            Map<Integer, Integer> offsetMap = new HashMap<>();
            int newOffset = 0;
            for (Block b : blocks) {
                int mapped;
                int pos = b.start;
                while (pos < b.end) {
                    int len = instrLen(code, pos);
                    offsetMap.put(pos, newOffset);
                    int m = newOffset + len;
                    // Guard against degenerate zero-length instructions.
                    if (m == newOffset) { offsetMap.put(pos, newOffset + 1); newOffset += 1; pos += 1; continue; }
                    newOffset = m;
                    pos += len;
                }
                mapped = newOffset + BOGUS_PREFIX;        // address of this block's body
                offsetMap.put(b.start, mapped - BOGUS_PREFIX);
                newOffset = mapped + (b.end - b.start) - (pos - b.start);
                newOffset += BOGUS_PREFIX;               // next block's bogus prefix is added below
            }
            // Correct finalization: ensure block bodies advance by BOGUS_PREFIX each.
            {
                Map<Integer, Integer> full = new HashMap<>();
                int off = 0;
                for (Block b : blocks) {
                    int prefixStart = off;
                    off += BOGUS_PREFIX;
                    int pos = b.start;
                    while (pos < b.end) {
                        int len = instrLen(code, pos);
                        if (len < 1) len = 1;
                        full.put(pos, off);
                        off += len;
                        pos += len;
                    }
                    full.put(b.start, prefixStart + BOGUS_PREFIX);
                }
                full.put(oldEnd, off);
                offsetMap.putAll(full);
            }
            offsetMap.put(oldEnd, newOffset);

            // 4. Emit new code
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            for (Block b : blocks) {
                // Calculate the address of the real block start (skip target)
                int realBlockAddr = out.size() + BOGUS_PREFIX;

                // Bogus prefix
                out.write(VmpOp.ICONST & 0xFF);
                writeInt(out, 0);                        // ICONST 0 (always 0)
                out.write(VmpOp.IFEQ & 0xFF);
                writeInt(out, realBlockAddr);            // IFEQ skip (always taken)
                // Dead code (never executed)
                out.write(VmpOp.DUP & 0xFF);
                out.write(VmpOp.POP & 0xFF);
                out.write(VmpOp.DUP & 0xFF);
                out.write(VmpOp.POP & 0xFF);
                out.write(VmpOp.GOTO & 0xFF);
                writeInt(out, realBlockAddr);            // GOTO next_real

                // Real block: copy with adjusted branch targets
                int pos = b.start;
                while (pos < b.end) {
                    int op = code[pos] & 0xFF;
                    int len = instrLen(code, pos);
                    if ((op >= 0x30 && op <= 0x3F) || op == 0xC9) {
                        // Branch: update target
                        int oldTarget = readInt(code, pos + 1);
                        Integer newTarget = offsetMap.get(oldTarget);
                        int target = (newTarget != null) ? newTarget : oldTarget;
                        out.write(code[pos] & 0xFF);
                        writeInt(out, target);
                    } else {
                        copyBytes(out, code, pos, len);
                    }
                    pos += len;
                }
            }

            // END
            out.write(VmpOp.END & 0xFF);

            byte[] newCode = out.toByteArray();
            int[][] newExceptions = updateExceptions(exceptions, offsetMap);

            KBoxLog.info(TAG, "bogus: code " + code.length + " -> " + newCode.length + " bytes");

            return new Result(newCode, newExceptions);

        } catch (Exception e) {
            KBoxLog.error(TAG, "bogus failed, returning original code", e);
            return new Result(code, exceptions);
        }
    }
}
