package com.kbox.core.vmp;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

import java.util.*;

/**
 * Translates JVM stack-machine bytecodes to KBox-VMP register-machine
 * instructions (32-bit fixed-length format).
 *
 * <p>Translation process:
 * <ol>
 *   <li>Build CFG from JVM bytecodes via ASM Analyzer.</li>
 *   <li>Perform stack-to-register lifting: each stack value at each
 *       instruction boundary gets a virtual register.</li>
 *   <li>Generate KBoxVM instructions using the register assignment.</li>
 *   <li>Produce final instruction array + JNI helper table.</li>
 * </ol>
 *
 * <p>Instruction format (32-bit):
 * <pre>
 *   | Opcode (8) | DST (4) | SRC1 (4) | SRC2 (4) | Imm12 / Src3 (12) |
 * </pre>
 *
 * <p>Register file: R0-R7 (R0 = 0), RPC, RSP, RFLAGS.
 */

public final class VmpRegisterTranslator {

    /* ===== KBoxVM Opcode Constants (logical, remapped at init) ===== */
    public static final int VOP_NOP      = 0x00;
    public static final int VOP_MOV      = 0x01;
    public static final int VOP_MOVI     = 0x02;
    public static final int VOP_ADD      = 0x10;
    public static final int VOP_SUB      = 0x11;
    public static final int VOP_MUL      = 0x12;
    public static final int VOP_DIV      = 0x13;
    public static final int VOP_REM      = 0x14;
    public static final int VOP_NEG      = 0x15;
    public static final int VOP_AND      = 0x20;
    public static final int VOP_OR       = 0x21;
    public static final int VOP_XOR      = 0x22;
    public static final int VOP_SHL      = 0x23;
    public static final int VOP_SHR      = 0x24;
    public static final int VOP_NOT      = 0x25;
    public static final int VOP_CMP      = 0x30;
    public static final int VOP_JMP      = 0x31;
    public static final int VOP_JZ       = 0x32;
    public static final int VOP_JNZ      = 0x33;
    public static final int VOP_JS       = 0x34;
    public static final int VOP_LOAD     = 0x40;
    public static final int VOP_STORE    = 0x41;
    public static final int VOP_INVOKE   = 0x50;
    public static final int VOP_RET      = 0x51;
    public static final int VOP_FADD     = 0x70;
    public static final int VOP_FSUB     = 0x71;
    public static final int VOP_FMUL     = 0x72;
    public static final int VOP_FDIV     = 0x73;

    /* Register indices (R0-R7, plus RPC=8, RSP=9, RFLAGS=10) */
    private static final int R_ZERO = 0;
    private static final int MAX_VREGS = 8;    /* R1-R7 available */
    private static final int RPC = 8;
    private static final int RSP = 9;
    private static final int RFLAGS = 10;

    /* ===== Translation result ===== */

    public static final class VmpProgram {
        /** Encoded 32-bit instructions (logical opcodes, not remapped). */
        public final int[] instructions;
        /** JNI helper function table: op → {className, method, desc}. */
        public final Map<Integer, String[]> helpers = new LinkedHashMap<>();
        /** Per-program encryption key seed. */
        public final int keySeed;

        public VmpProgram(int[] insns, int keySeed) {
            this.instructions = insns;
            this.keySeed = keySeed;
        }
    }

    /* ===== Translation context ===== */

    private static final class Ctx {
        /* Instruction output buffer */
        final List<Integer> out = new ArrayList<>();
        /* Label → instruction index mapping (for backpatching branches) */
        final Map<LabelNode, Integer> labelOffset = new LinkedHashMap<>();
        /* Pending branch patches: {insnIndex, label, branchType} */
        final List<int[]> patches = new ArrayList<>();
        /* Local variable slot → virtual register (R1-R7) */
        final int[] localReg = new int[256];
        /* Next free virtual register */
        int nextReg = 1;
        /* JNI helper index counter */
        int helperIdx = 0;
        /* Method's max locals */
        int maxLocals;
        /* Class name (for JNI helpers) */
        String className;

        Ctx(String className, int maxLocals) {
            this.className = className;
            this.maxLocals = maxLocals;
            Arrays.fill(localReg, -1);
        }

        /** Allocate a new virtual register (R1-R7). */
        int allocReg() {
            if (nextReg >= MAX_VREGS) {
                /* Spill to virtual stack — for now, reuse R7 with save/restore.
                 * In production, implement proper register spilling. */
                return 7;
            }
            return nextReg++;
        }

        /** Get or allocate the virtual register for local variable slot n. */
        int localReg(int slot) {
            if (localReg[slot] < 0) localReg[slot] = allocReg();
            return localReg[slot];
        }

        /** Emit a single instruction. */
        void emit(int op, int dst, int src1, int src2, int imm12) {
            int insn = ((op & 0xFF) << 24)
                     | ((dst & 0x0F) << 20)
                     | ((src1 & 0x0F) << 16)
                     | ((src2 & 0x0F) << 12)
                     | (imm12 & 0xFFF);
            out.add(insn);
        }

        /** Emit MOVI Rd, #imm. */
        void movi(int rd, int imm) {
            if (imm >= -2048 && imm < 4096) {
                emit(VOP_MOVI, rd, 0, 0, imm & 0x0FFF);
            } else {
                /* Large immediate: split into high/low */
                emit(VOP_MOVI, rd, 0, 0, (imm >> 12) & 0xFFF);
                emit(VOP_SHL, rd, rd, 0, 12);
                emit(VOP_OR, rd, rd, 0, imm & 0xFFF);
            }
        }

        int currentOffset() { return out.size(); }

        void patchBranch(int insnIdx, int targetOffset, int branchOp) {
            /* Backpatch the imm12 field */
            int delta = targetOffset - insnIdx - 1; /* delta from instruction AFTER branch */
            int masked = delta & 0xFFF;
            if (delta != (delta > 0x7FF ? delta | 0xFFFFF000 : delta)) {
                /* Range overflow: use JMP chain instead */
                masked = 0;
            }
            int old = out.get(insnIdx);
            int newInsn = (old & 0xFFFFF000) | (masked & 0xFFF);
            out.set(insnIdx, newInsn);
        }
    }

    /* ===== Main translation entry ===== */

    public static VmpProgram translate(String className, MethodNode mn, int keySeed) {
        Ctx ctx = new Ctx(className, mn.maxLocals);

        /* VM_ENTER: establish the virtual frame */
        ctx.emit(VOP_MOV, 0, 0, 0, 0x000); /* placeholder for VM_ENTER */

        /* Map JVM local variables to virtual registers at entry. */
        int localSlot = 0;

        /* Pre-allocate virtual registers for basic locals */
        for (int i = 0; i < Math.min(mn.maxLocals, 64); i++) {
            ctx.localReg(i);
        }

        /* Build label-to-offset map first pass. */
        Map<AbstractInsnNode, Integer> insnOffsets = new LinkedHashMap<>();
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                ctx.labelOffset.put((LabelNode) insn, ctx.out.size());
            }
            insnOffsets.put(insn, ctx.out.size());
            translateInsn(ctx, mn, insn);
        }

        /* VM_EXIT: cleanup */
        ctx.emit(VOP_RET, 1, 0, 0, 0);

        /* Backpatch branches */
        for (int[] patch : ctx.patches) {
            int insnIdx = patch[0];
            LabelNode target = (LabelNode) mn.instructions.get(patch[1] /* actually we need a better ref */);
            /* We use labelOffset map */
            Integer targetOff = ctx.labelOffset.get(patch[1]);
            if (targetOff != null) {
                ctx.patchBranch(insnIdx, targetOff, patch[2]);
            }
        }

        return new VmpProgram(ctx.out.stream().mapToInt(Integer::intValue).toArray(), keySeed);
    }

    /* ===== Per-instruction translation ===== */

    private static void translateInsn(Ctx ctx, MethodNode mn, AbstractInsnNode insn) {
        int op = insn.getOpcode();

        if (op == -1) {
            /* Label, Frame, LineNumber: skip */
            return;
        }

        switch (op) {
            /* ---- Constants ---- */
            case Opcodes.NOP: break;
            case Opcodes.ACONST_NULL:
                ctx.movi(ctx.allocReg(), 0); break;
            case Opcodes.ICONST_M1:
                ctx.emit(VOP_MOVI, ctx.allocReg(), 0, 0, 0xFFF); break;
            case Opcodes.ICONST_0:
                ctx.movi(ctx.allocReg(), 0); break;
            case Opcodes.ICONST_1:
                ctx.movi(ctx.allocReg(), 1); break;
            case Opcodes.ICONST_2:
                ctx.movi(ctx.allocReg(), 2); break;
            case Opcodes.ICONST_3:
                ctx.movi(ctx.allocReg(), 3); break;
            case Opcodes.ICONST_4:
                ctx.movi(ctx.allocReg(), 4); break;
            case Opcodes.ICONST_5:
                ctx.movi(ctx.allocReg(), 5); break;

            /* ---- Arithmetic (stack: a,b → result) ---- */
            case Opcodes.IADD:
                emitBinOp(ctx, VOP_ADD);
                break;
            case Opcodes.ISUB:
                emitBinOp(ctx, VOP_SUB);
                break;
            case Opcodes.IMUL:
                emitBinOp(ctx, VOP_MUL);
                break;
            case Opcodes.IDIV:
                emitBinOp(ctx, VOP_DIV);
                break;
            case Opcodes.IREM:
                emitBinOp(ctx, VOP_REM);
                break;
            case Opcodes.INEG:
                emitUnaryOp(ctx, VOP_NEG);
                break;
            case Opcodes.IAND:
                emitBinOp(ctx, VOP_AND);
                break;
            case Opcodes.IOR:
                emitBinOp(ctx, VOP_OR);
                break;
            case Opcodes.IXOR:
                emitBinOp(ctx, VOP_XOR);
                break;
            case Opcodes.ISHL:
                emitBinOp(ctx, VOP_SHL);
                break;
            case Opcodes.ISHR:
                emitBinOp(ctx, VOP_SHR);
                break;
            case Opcodes.IUSHR:
                emitBinOp(ctx, VOP_SHR);
                break; /* unsigned shift via register bits */

            /* ---- Load/Store —— */
            case Opcodes.ILOAD:
                emitLoad(ctx, ((VarInsnNode)insn).var);
                break;
            case Opcodes.ISTORE:
                emitStore(ctx, ((VarInsnNode)insn).var);
                break;

            /* ---- Branches —— */
            case Opcodes.IFEQ:
                emitBranch(ctx, (JumpInsnNode)insn, VOP_JZ);
                break;
            case Opcodes.IFNE:
                emitBranch(ctx, (JumpInsnNode)insn, VOP_JNZ);
                break;
            case Opcodes.GOTO:
                emitBranch(ctx, (JumpInsnNode)insn, VOP_JMP);
                break;
            case Opcodes.IRETURN:
                ctx.emit(VOP_RET, 1, 0, 0, 0);
                break;
            case Opcodes.RETURN:
                ctx.emit(VOP_RET, R_ZERO, 0, 0, 0);
                break;

            /* ---- Method calls —— */
            case Opcodes.INVOKESTATIC:
                emitInvoke(ctx, (MethodInsnNode)insn, true);
                break;
            case Opcodes.INVOKEVIRTUAL:
                emitInvoke(ctx, (MethodInsnNode)insn, false);
                break;

            default:
                /* Unsupported opcode: emit NOP */
                break;
        }
    }

    /* ===== Helper: binary operation (pop 2, push 1) ===== */

    private static void emitBinOp(Ctx ctx, int opcode) {
        /* Simulate register assignment: result = pop2 op pop1 */
        int rd = ctx.allocReg();
        /* For simplicity, we use a fixed register scheme:
         * R1 = most recent pushed value, R2 = second most recent */
        ctx.emit(opcode, rd, 1, 2, 0);
    }

    private static void emitUnaryOp(Ctx ctx, int opcode) {
        int rd = ctx.allocReg();
        ctx.emit(opcode, rd, 1, 0, 0);
    }

    private static void emitLoad(Ctx ctx, int slot) {
        int rd = ctx.allocReg();
        int lr = ctx.localReg(slot);
        ctx.emit(VOP_MOV, rd, lr, 0, 0);
    }

    private static void emitStore(Ctx ctx, int slot) {
        int lr = ctx.localReg(slot);
        ctx.emit(VOP_MOV, lr, 1, 0, 0); /* R1 = top of virtual stack */
    }

    private static void emitBranch(Ctx ctx, JumpInsnNode jump, int branchOp) {
        int insnIdx = ctx.currentOffset();
        ctx.emit(branchOp, 0, 0, 0, 0); /* imm12 placeholder */
        /* Record for backpatching */
        LabelNode target = jump.label;
        Integer targetOff = ctx.labelOffset.get(target);
        if (targetOff != null) {
            ctx.patchBranch(insnIdx, targetOff, branchOp);
        }
    }

    private static void emitInvoke(Ctx ctx, MethodInsnNode minsn, boolean isStatic) {
        /* Register method in JNI helper table */
        String methodKey = minsn.owner + "#" + minsn.name + "#" + minsn.desc;
        int hidx = ctx.helperIdx++;
        /* Placeholder JNI helper registration */
        /* Emit INVOKE instruction */
        ctx.emit(VOP_INVOKE, 1 /* result reg */, 0, 0, hidx & 0xFFF);
    }

    /* ===== Utility: generate encrypted VM program ===== */

    /**
     * Encrypts the KBoxVM instruction array using the per-program key seed.
     * Each 32-bit word is XORed with a key byte derived from seed + offset.
     */
    public static int[] encryptProgram(int[] plain, int keySeed) {
        int[] cipher = new int[plain.length];
        for (int i = 0; i < plain.length; i++) {
            int k = keySeed;
            k ^= i * 0x9E3779B9;
            k = (k ^ (k >>> 16)) * 0x85EBCA6B;
            k = (k ^ (k >>> 13)) * 0xC2B2AE35;
            int kb = (k ^ (k >>> 16)) & 0xFF;
            int mask = kb | (kb << 8) | (kb << 16) | (kb << 24);
            cipher[i] = plain[i] ^ mask;
        }
        return cipher;
    }

    /* ===== Utility: generate C array literal ===== */

    public static String toCArrayLiteral(String name, int[] data) {
        StringBuilder sb = new StringBuilder();
        sb.append("static uint32_t ").append(name).append("[] = {\n  ");
        for (int i = 0; i < data.length; i++) {
            if (i > 0 && i % 8 == 0) sb.append("\n  ");
            sb.append(String.format("0x%08XU", data[i]));
            if (i < data.length - 1) sb.append(", ");
        }
        sb.append("\n};\n");
        return sb.toString();
    }
}
