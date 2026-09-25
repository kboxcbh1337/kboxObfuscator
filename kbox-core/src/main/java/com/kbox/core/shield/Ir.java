package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.List;

/**
 * Ir — kboXShield 代码虚拟化编译器的中间表示（寄存器式 RISC 风格）。
 *
 * <p>来源：{@code kboXShield/packer/vm/ir.h}（逐行移植）。</p>
 *
 * <p>提升器（{@link LiftX64}）把 x86-64 机器码提升为本 IR，编译器
 * （{@link IrCompile}）再把 IR 降为栈式 VM 字节码。设计取舍（保留原注释）：</p>
 * <ul>
 *   <li>虚拟寄存器 vreg 0..15 与 x86-64 通用寄存器一一对应（ModRM 顺序），
 *       每个 vreg 在 VmCtx 的 frame 中占 2 个字（lo/hi）；16..31 为临时。</li>
 *   <li>被虚拟化函数的<b>栈帧静态分配</b>：[rbp/rsp ± disp] 映射为 frame 的
 *       静态帧槽（IR_FLD/IR_FST，imm = 槽号），不模拟 rsp/rbp 的运行时值。</li>
 *   <li>内存访问仅在基址为「非帧指针寄存器」时走真实内存（IR_LD/IR_ST）。</li>
 *   <li>条件求值不引入标志位状态：比较直接产生 0/1 值（IR_SETCC / IR_JCC）。</li>
 *   <li>无法提升的机器指令保留为 IR_NATIVE（指令级 exit-to-native）。</li>
 * </ul>
 *
 * <p>类型映射约定：C++ 的 {@code enum ... : uint8_t} 一律映射为与本类成员同名
 * 的 {@code public static final int} 常量，数值逐一对应（可直接用于数组下标与
 * {@code switch} 的 case 标签）；{@code uint8_t/uint16_t/uint32_t -> int}、
 * {@code int8_t/int16_t/int32_t -> int}、{@code int64_t/uint64_t -> long}、
 * {@code size_t -> int}、{@code std::vector<T> -> java.util.List<T>}。
 * C++ 的 {@code std::vector<uint8_t> native} 因 {@code native} 是 Java 关键字，
 * 字段名改为 {@code nativeBytes}。</p>
 */
public final class Ir {

    private Ir() {
    }

    // ---- 条件码（仅保留可用「值比较」求值的 10 种）----
    // 来源：ir.h enum IrCc : uint8_t
    public static final int IRC_EQ = 0;
    public static final int IRC_NE = 1;
    public static final int IRC_ULT = 2;
    public static final int IRC_UGE = 3;
    public static final int IRC_ULE = 4;
    public static final int IRC_UGT = 5;
    public static final int IRC_SLT = 6;
    public static final int IRC_SGE = 7;
    public static final int IRC_SLE = 8;
    public static final int IRC_SGT = 9;
    public static final int IRC_COUNT = 10;

    // ---- 二元/一元运算 ----
    // 来源：ir.h enum IrBin / IrUn
    public static final int IRB_ADD = 0;
    public static final int IRB_SUB = 1;
    public static final int IRB_MUL = 2;
    public static final int IRB_AND = 3;
    public static final int IRB_OR = 4;
    public static final int IRB_XOR = 5;
    public static final int IRB_SHL = 6;
    public static final int IRB_SHR = 7;
    public static final int IRB_SAR = 8;

    public static final int IRU_NOT = 0;
    public static final int IRU_NEG = 1;

    // ---- IR 操作码 ----
    // 来源：ir.h enum IrOp : uint8_t
    /** dst = imm（按 width 规范化：32 位结果清高位）。 */
    public static final int IR_MOVI = 0;
    /** dst = a。 */
    public static final int IR_MOV = 1;
    /** dst = a &lt;sub&gt; b（width 位）。 */
    public static final int IR_BIN = 2;
    /** dst = &lt;sub&gt; a（width 位）。 */
    public static final int IR_UN = 3;
    /** dst = a + imm（64 位地址运算）。 */
    public static final int IR_LEA = 4;
    /** dst = frame_slot[imm]（width 位，结果规范化）。 */
    public static final int IR_FLD = 5;
    /** frame_slot[imm] = a（width 位）。 */
    public static final int IR_FST = 6;
    /** dst = mem[a + imm]（width 位，结果规范化）。 */
    public static final int IR_LD = 7;
    /** mem[a + imm] = b（width 位）。 */
    public static final int IR_ST = 8;
    /** dst = (a &lt;cc&gt; b) ? 1 : 0。 */
    public static final int IR_SETCC = 9;
    /** 跳到 IR 下标 target。 */
    public static final int IR_JMP = 10;
    /** (a &lt;cc&gt; b) 成立则跳 target，否则顺序。 */
    public static final int IR_JCC = 11;
    /** 返回（结果取 rax 帧槽的低 32 位）。 */
    public static final int IR_RET = 12;
    /** 不可提升：原生片段（natOff/natLen 指向 IrFunc.nativeBytes）。 */
    public static final int IR_NATIVE = 13;

    /** 虚拟寄存器编号：0..15 = x86-64 通用寄存器；&gt;= 16 = 临时。 */
    public static final int IR_VREG_MAX = VmIsa.VM_MACH_GPRS + VmIsa.VM_TMP_VREGS; // 32

    // ---- 单条 IR 指令 ----
    // 来源：ir.h struct IrInsn
    public static final class IrInsn {
        public int op = IR_MOVI;
        /** 8/16/32/64。 */
        public int width = 32;
        public int dst = 0;
        public int a = 0;
        /** 或 IrCc（SETCC/JCC）。 */
        public int b = 0;
        /** IrBin / IrUn。 */
        public int sub = 0;
        public int imm = 0;
        /** IR 下标（JMP/JCC）。 */
        public int target = 0;
        /** NATIVE 原始字节在 IrFunc.nativeBytes 的偏移。 */
        public int natOff = 0;
        public int natLen = 0;
    }

    // ---- 一个被提升的函数 ----
    // 来源：ir.h struct IrFunc
    public static final class IrFunc {
        public List<IrInsn> insns = new ArrayList<IrInsn>();
        /** 不可提升指令的原始字节池（对应 C++ std::vector<uint8_t> native）。 */
        public List<Integer> nativeBytes = new ArrayList<Integer>();
        public int entry = 0;
        /** 静态帧槽用量（从 VM_STKFRM_SLOT0 起）。 */
        public int frameSlots = 0;
        /** 以原生片段保留的机器指令数。 */
        public int nativeInsns = 0;
    }

    // ---- 提升诊断 ----
    // 来源：ir.h struct LiftDiag（Java 侧名 IrDiag）
    public static final class IrDiag {
        public boolean ok = true;
        /** 首个无法解码的机器码偏移（相对 liftX64Func 的 off）。 */
        public int badOff = 0;
        public int frameSlots = 0;
        public int nativeInsns = 0;
    }
}
