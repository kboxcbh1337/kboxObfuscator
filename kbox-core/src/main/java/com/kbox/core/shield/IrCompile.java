package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.List;

/**
 * IrCompile — IR → VM 字节码编译器（两个家族）。
 *
 * <p>本文件合并移植了两份同源 C++ 源码：</p>
 * <ul>
 *   <li>{@code kboXShield/packer/vm/ir_compile.cpp}（Family A 栈式目标）
 *       → {@link #irCompile(Ir.IrFunc)}</li>
 *   <li>{@code kboXShield/packer/vm/ir_compile_b.cpp}（Family B 寄存器式目标）
 *       → {@link #irCompileB(Ir.IrFunc)}</li>
 * </ul>
 *
 * <p><b>Family A 说明</b>（来源 ir_compile.cpp）：虚拟寄存器 → frame 槽：
 * 0..15 为 x86-64 通用寄存器 → vm_gpr_slot(v)（2v/2v+1）；
 * 16..31 为临时寄存器 → VM_TMP_SLOT0 起，每个 2 字。
 * 32 位结果写入时清高位（x86-64 的隐式零扩展语义），64 位结果写 lo/hi。
 * 跳转回填：先按 IR 顺序发射并记录 IR→VM 下标，再统一换算相对指令偏移
 * （VM 的 JMP/JZ/JNZ 立即数单位为「指令数，相对下一条」）。</p>
 *
 * <p><b>Family B 说明</b>（来源 ir_compile_b.cpp）：Family B 与 IR 同为寄存器式，
 * IR 的虚拟寄存器 0..31 直接作为 B 的寄存器号（0..15 = 机器 GPR，16..31 = 临时），
 * 无需像 Family A 那样做栈式降级，因此是一对一（少量一对多）转写。
 * 跳转立即数为「目标指令下标 × VM_B_INSN_SIZE」的绝对字节偏移。</p>
 *
 * <p><b>关于 VmBuilder.insn()</b>：C++ 中语义流指令由 vm_builder.h 的
 * {@code inline Insn insn(uint32_t sem, uint32_t imm = 0)} 构造（纯工厂函数）。
 * 当前源码树中尚无 Java 版 {@code VmBuilder}，为满足 {@code javac --release 8}
 * 可独立编译，这里用等价的私有工厂 {@link #insn(int, int)}
 * （{@code new VmIsa.Insn(sem, imm)}，与 C++ insn() 行为一致）替代；
 * 一旦 {@code VmBuilder} 就位，仅需将该方法体改为
 * {@code return VmBuilder.insn(sem, imm);}。</p>
 */
public final class IrCompile {

    private IrCompile() {
    }

    // ---- 语义流指令工厂（等价于 vm_builder.h 的 insn()）----
    private static VmIsa.Insn insn(int sem, int imm) {
        return new VmIsa.Insn(sem, imm);
    }

    // ---- 编译结果（对应 ir.h struct CompileResult / CompileResultB）----

    /** 来源：ir.h struct CompileResult。 */
    public static final class CompileResult {
        public boolean ok = false;
        /** VM_ERR_*。 */
        public int err = 0;
        /** 语义流（供 vm_build）。 */
        public List<VmIsa.Insn> program = new ArrayList<VmIsa.Insn>();
    }

    /** 来源：ir.h struct CompileResultB。 */
    public static final class CompileResultB {
        public boolean ok = false;
        /** VM_ERR_*。 */
        public int err = 0;
        public List<VmIsa.BInsn> program = new ArrayList<VmIsa.BInsn>();
    }

    // ---- Family A ----

    /** 来源：ir_compile.cpp vreg_slot()。 */
    private static int vregSlot(int v) {
        if (v < VmIsa.VM_MACH_GPRS) {
            return VmIsa.vmGprSlot(v);
        }
        return VmIsa.VM_TMP_SLOT0 + (v - VmIsa.VM_MACH_GPRS) * 2;
    }

    private static final int[] K_BIN_SEM = {
            VmIsa.SEM_ADD, VmIsa.SEM_SUB, VmIsa.SEM_MUL, VmIsa.SEM_AND, VmIsa.SEM_OR,
            VmIsa.SEM_XOR, VmIsa.SEM_SHL, VmIsa.SEM_SHR, VmIsa.SEM_SAR
    };
    private static final int[] K_UN_SEM = { VmIsa.SEM_NOT, VmIsa.SEM_NEG };
    private static final int[] K_CC_SEM = {
            VmIsa.SEM_EQ, VmIsa.SEM_NE, VmIsa.SEM_ULT, VmIsa.SEM_UGE, VmIsa.SEM_ULE,
            VmIsa.SEM_UGT, VmIsa.SEM_SLT, VmIsa.SEM_SGE, VmIsa.SEM_SLE, VmIsa.SEM_SGT
    };

    /** 来源：ir_compile.cpp struct Emitter。 */
    private static final class Emitter {
        final List<VmIsa.Insn> prog = new ArrayList<VmIsa.Insn>();
        /** IR 下标 -> VM 下标。 */
        int[] ir2vm = new int[0];
        /** (跳转指令 VM 下标, IR 目标)。 */
        final List<int[]> fixes = new ArrayList<int[]>();

        void e(int sem, int imm) {
            prog.add(insn(sem, imm));
        }

        void e(int sem) {
            e(sem, 0);
        }

        void loadv(int v) {
            e(VmIsa.SEM_LOAD, vregSlot(v));
        }

        void loadv64(int v) {
            e(VmIsa.SEM_LOAD, vregSlot(v));
            e(VmIsa.SEM_LOAD, vregSlot(v) + 1);
        }

        /** 栈顶为 32 位结果 → 写 lo 并清 hi。 */
        void storev32(int v) {
            e(VmIsa.SEM_PUSH, 0);
            e(VmIsa.SEM_STORE, vregSlot(v) + 1);
            e(VmIsa.SEM_STORE, vregSlot(v));
        }

        /** 栈顶为 (hi, lo)（hi 在顶）→ 写 lo/hi。 */
        void storev64(int v) {
            e(VmIsa.SEM_STORE, vregSlot(v) + 1);
            e(VmIsa.SEM_STORE, vregSlot(v));
        }
    }

    /**
     * IR → 栈式 VM 语义流。
     *
     * <p>来源：ir_compile.cpp ir_compile(const IrFunc&amp;)。</p>
     */
    public static CompileResult irCompile(Ir.IrFunc fn) {
        CompileResult res = new CompileResult();
        Emitter em = new Emitter();
        em.ir2vm = new int[fn.insns.size()];

        for (int k = 0; k < fn.insns.size(); k++) {
            final Ir.IrInsn in = fn.insns.get(k);
            em.ir2vm[k] = em.prog.size();
            final int w = in.width;
            switch (in.op) {
                case Ir.IR_MOVI:
                    em.e(VmIsa.SEM_PUSH, in.imm);
                    if (w == 64) {
                        // C++: 0xFFFFFFFFu : 0u
                        em.e(VmIsa.SEM_PUSH, in.imm < 0 ? -1 : 0);
                        em.storev64(in.dst);
                    } else {
                        em.storev32(in.dst);
                    }
                    break;
                case Ir.IR_MOV:
                    em.loadv(in.a);
                    em.storev32(in.dst);
                    break;
                case Ir.IR_BIN:
                    if (w == 64 || in.sub >= 9) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    em.loadv(in.a);
                    em.loadv(in.b);
                    em.e(K_BIN_SEM[in.sub]);
                    em.storev32(in.dst);
                    break;
                case Ir.IR_UN:
                    if (w == 64 || in.sub >= 2) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    em.loadv(in.a);
                    em.e(K_UN_SEM[in.sub]);
                    em.storev32(in.dst);
                    break;
                case Ir.IR_LEA:
                    if (w != 64) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    em.loadv64(in.a);
                    em.e(VmIsa.SEM_ADDREL, in.imm);
                    em.storev64(in.dst);
                    break;
                case Ir.IR_FLD:
                    em.e(VmIsa.SEM_LOAD, in.imm);
                    if (w == 64) {
                        em.e(VmIsa.SEM_LOAD, in.imm + 1);
                    }
                    if (w == 64) {
                        em.storev64(in.dst);
                    } else {
                        em.storev32(in.dst);
                    }
                    break;
                case Ir.IR_FST:
                    if (w == 64) {
                        em.loadv64(in.a);
                        em.e(VmIsa.SEM_STORE, in.imm + 1);
                        em.e(VmIsa.SEM_STORE, in.imm);
                    } else {
                        em.loadv(in.a);
                        em.e(VmIsa.SEM_STORE, in.imm);
                    }
                    break;
                case Ir.IR_LD:
                    if (w != 32) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    em.loadv64(in.a);
                    em.e(VmIsa.SEM_MEMRD, in.imm);
                    em.storev32(in.dst);
                    break;
                case Ir.IR_ST:
                    if (w != 32) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    em.loadv64(in.a);
                    em.loadv(in.b);
                    em.e(VmIsa.SEM_MEMWR, in.imm);
                    break;
                case Ir.IR_SETCC:
                    if (in.sub >= Ir.IRC_COUNT) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    em.loadv(in.a);
                    em.loadv(in.b);
                    em.e(K_CC_SEM[in.sub]);
                    em.storev32(in.dst);
                    break;
                case Ir.IR_JMP: {
                    em.e(VmIsa.SEM_JMP, 0);
                    em.fixes.add(new int[] { em.prog.size() - 1, in.target });
                    break;
                }
                case Ir.IR_JCC:
                    if (in.sub >= Ir.IRC_COUNT) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    em.loadv(in.a);
                    em.loadv(in.b);
                    em.e(K_CC_SEM[in.sub]);
                    em.e(VmIsa.SEM_JNZ, 0);
                    em.fixes.add(new int[] { em.prog.size() - 1, in.target });
                    break;
                case Ir.IR_RET:
                    // 结果 = 虚拟 rax 低 32 位
                    em.e(VmIsa.SEM_LOAD, VmIsa.vmGprSlot(VmIsa.GPR_RAX));
                    em.e(VmIsa.SEM_RET);
                    break;
                case Ir.IR_NATIVE:
                default:
                    // 原生片段表尚未接入镜像格式（见 Batch 5 说明）
                    res.err = VmIsa.VM_ERR_BAD_OPCODE;
                    return res;
            }
        }

        // 跳转回填
        for (int[] f : em.fixes) {
            // C++ 中为 uint32 与 size_t 的无符号比较
            if (Integer.compareUnsigned(f[1], em.ir2vm.length) >= 0) {
                res.err = VmIsa.VM_ERR_BAD_JUMP;
                return res;
            }
            final int dst = em.ir2vm[f[1]];
            final int src = f[0];
            em.prog.get(src).imm = (int) ((long) dst - ((long) src + 1L));
        }

        res.program = em.prog;
        res.ok = true;
        res.err = VmIsa.VM_OK;
        return res;
    }

    // ---- Family B ----

    private static final int[] K_BIN_OP = {
            VmIsa.REG_ADD, VmIsa.REG_SUB, VmIsa.REG_MUL, VmIsa.REG_AND, VmIsa.REG_OR,
            VmIsa.REG_XOR, VmIsa.REG_SHL, VmIsa.REG_SHR, VmIsa.REG_SAR
    };
    private static final int[] K_UN_OP = { VmIsa.REG_NOT, VmIsa.REG_NEG };

    /** 来源：ir_compile_b.cpp 中的 emit lambda。 */
    private static void emit(List<VmIsa.BInsn> p, int op, int rd, int ra, int rb, int imm) {
        VmIsa.BInsn b = new VmIsa.BInsn();
        b.op = op;
        b.rd = rd;
        b.ra = ra;
        b.rb = rb;
        b.imm = imm;
        p.add(b);
    }

    /**
     * IR → Family B（寄存器式）字节码。
     *
     * <p>来源：ir_compile_b.cpp ir_compile_b(const IrFunc&amp;)。</p>
     */
    public static CompileResultB irCompileB(Ir.IrFunc fn) {
        CompileResultB res = new CompileResultB();
        final List<VmIsa.BInsn> p = res.program;
        final int[] ir2b = new int[fn.insns.size()];
        // (B 下标, IR 目标)
        final List<int[]> fixes = new ArrayList<int[]>();

        for (int k = 0; k < fn.insns.size(); k++) {
            final Ir.IrInsn in = fn.insns.get(k);
            ir2b[k] = p.size();
            switch (in.op) {
                case Ir.IR_MOVI:
                    // 32 位：零扩展（hi = 0）；64 位：符号扩展
                    if (in.width == 64) {
                        emit(p, VmIsa.REG_SET64, in.dst, 0, 0, in.imm);
                    } else {
                        emit(p, VmIsa.REG_MOVI, in.dst, 0, 0, in.imm);
                    }
                    break;
                case Ir.IR_MOV:
                    emit(p, VmIsa.REG_MOV, in.dst, in.a, 0, 0);
                    break;
                case Ir.IR_BIN:
                    if (in.width == 64 || in.sub >= 9) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    emit(p, K_BIN_OP[in.sub], in.dst, in.a, in.b, 0);
                    break;
                case Ir.IR_UN:
                    if (in.width == 64 || in.sub >= 2) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    emit(p, K_UN_OP[in.sub], in.dst, in.a, 0, 0);
                    break;
                case Ir.IR_LEA:
                    if (in.width != 64) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    emit(p, VmIsa.REG_LEA, in.dst, in.a, 0, in.imm);
                    break;
                case Ir.IR_FLD:
                    if (in.width == 64) {
                        emit(p, VmIsa.REG_FLD64, in.dst, 0, 0, in.imm);
                    } else {
                        emit(p, VmIsa.REG_FLD, in.dst, 0, 0, in.imm);
                    }
                    break;
                case Ir.IR_FST:
                    if (in.width == 64) {
                        emit(p, VmIsa.REG_FST64, 0, in.a, 0, in.imm);
                    } else {
                        emit(p, VmIsa.REG_FST, 0, in.a, 0, in.imm);
                    }
                    break;
                case Ir.IR_LD:
                    if (in.width != 32) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    emit(p, VmIsa.REG_LD, in.dst, in.a, 0, in.imm);
                    break;
                case Ir.IR_ST:
                    if (in.width != 32) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    emit(p, VmIsa.REG_ST, 0, in.a, in.b, in.imm);
                    break;
                case Ir.IR_SETCC:
                    if (in.sub >= Ir.IRC_COUNT) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    emit(p, VmIsa.REG_SETCC, in.dst, in.a, in.b, in.sub);
                    break;
                case Ir.IR_JMP:
                    emit(p, VmIsa.REG_JMP, 0, 0, 0, 0);
                    fixes.add(new int[] { p.size() - 1, in.target });
                    break;
                case Ir.IR_JCC:
                    if (in.sub >= Ir.IRC_COUNT) {
                        res.err = VmIsa.VM_ERR_FAULT;
                        return res;
                    }
                    emit(p, VmIsa.REG_JCC, in.sub, in.a, in.b, 0);
                    fixes.add(new int[] { p.size() - 1, in.target });
                    break;
                case Ir.IR_RET:
                    // 结果 = 虚拟 rax 低 32 位
                    emit(p, VmIsa.REG_RET, 0, VmIsa.GPR_RAX, 0, 0);
                    break;
                case Ir.IR_NATIVE:
                default:
                    // 原生片段表尚未接入镜像格式（见 Batch 5 说明）
                    res.err = VmIsa.VM_ERR_BAD_OPCODE;
                    return res;
            }
        }

        // 跳转回填：绝对字节偏移 = 目标 B 下标 × 指令长度
        for (int[] f : fixes) {
            // C++ 中为 uint32 与 size_t 的无符号比较
            if (Integer.compareUnsigned(f[1], ir2b.length) >= 0) {
                res.err = VmIsa.VM_ERR_BAD_JUMP;
                return res;
            }
            p.get(f[0]).imm = ir2b[f[1]] * VmIsa.VM_B_INSN_SIZE;
        }

        res.ok = true;
        res.err = VmIsa.VM_OK;
        return res;
    }
}
