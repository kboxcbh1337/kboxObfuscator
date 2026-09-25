package com.kbox.core.shield;

/**
 * VmIsa — kboXShield 多态虚拟机指令集架构（由 include/vm_isa.h 移植）。
 *
 * <p>三方共享契约：C++ 引擎（packer/vm/vm_engine）、字节码生成器（vm_builder）、
 * 汇编 stub 共同遵循此布局。Java 侧全部以 {@code int} 承载 uint32 语义
 * （Java int 的补码加减乘与 uint32 回绕一致），无符号比较/右移使用
 * {@link Integer#compareUnsigned} 与 {@code >>>}。</p>
 */
public final class VmIsa {

    private VmIsa() {
    }

    // ---- 魔数与版本 ----
    public static final int VM_IMAGE_VERSION = 2;

    /**
     * 内层镜像魔数（"KBVM"）。
     *
     * <p>上游快照中「方案B：魔数由密钥派生」的改造只完成了一半：packer 侧的
     * vm_builder.cpp / vm_engine.cpp 已改为派生魔数，而**随包发布的运行期汇编
     * 引擎**（stub/vm_engine_x64.S、vm_engine_x86.S 的 {@code IH_IV_MAGIC}）与
     * 内层解释器（packer/vm/meta_inner.cpp 的 {@code IV_MAGIC}）仍按固定常量
     * 校验。若按派生魔数产出镜像，运行期 kbox_vm_run 会以 VM_ERR_BAD_MAGIC 停机。</p>
     *
     * <p>本移植以运行期汇编引擎为准（它是被固化进被保护 PE 的安全边界，
     * 且已按字节复现原产物），统一使用固定魔数。若后续要恢复 F9.4 的
     * 「无固定魔数可扫描」加固，需同步改造两个 .S 引擎与 meta_inner 生成器。</p>
     */
    public static final int VM_IMAGE_MAGIC = 0x4D56424B;

    /** 镜像魔数由密钥派生（FNV-1a 变体 + 固定高位）。 */
    public static int vmMagicOf(int[] key) {
        int h = 0x6B6F4269;
        for (int i = 0; i < 4; i++) {
            h ^= key[i];
            h *= 0x9E3779B1;
            h ^= h >>> 16;
        }
        return (h & 0x7FFFFFFF) | 0x80000000;
    }

    // ---- 数据宽度 ----
    public static final int VM_WORD_BITS = 32;
    public static final int VM_WORD_BYTES = 4;

    // ---- 指令格式：固定 5 字节 ----
    public static final int VM_INSN_SIZE = 5;

    // ---- 语义编号（Family A，栈式） ----
    public static final int SEM_NOP = 0;
    public static final int SEM_PUSH = 1;
    public static final int SEM_LOAD = 2;
    public static final int SEM_STORE = 3;
    public static final int SEM_DUP = 4;
    public static final int SEM_SWAP = 5;
    public static final int SEM_POP = 6;
    public static final int SEM_ADD = 7;
    public static final int SEM_SUB = 8;
    public static final int SEM_MUL = 9;
    public static final int SEM_NEG = 10;
    public static final int SEM_AND = 11;
    public static final int SEM_OR = 12;
    public static final int SEM_XOR = 13;
    public static final int SEM_NOT = 14;
    public static final int SEM_SHL = 15;
    public static final int SEM_SHR = 16;
    public static final int SEM_SAR = 17;
    public static final int SEM_JMP = 18;
    public static final int SEM_JZ = 19;
    public static final int SEM_JNZ = 20;
    public static final int SEM_RET = 21;
    public static final int SEM_MEMRD = 22;
    public static final int SEM_MEMWR = 23;
    public static final int SEM_ADDREL = 24;
    public static final int SEM_NATIVE = 25;
    public static final int SEM_EQ = 26;
    public static final int SEM_NE = 27;
    public static final int SEM_ULT = 28;
    public static final int SEM_UGE = 29;
    public static final int SEM_ULE = 30;
    public static final int SEM_UGT = 31;
    public static final int SEM_SLT = 32;
    public static final int SEM_SGE = 33;
    public static final int SEM_SLE = 34;
    public static final int SEM_SGT = 35;
    public static final int SEM_COUNT = 36;

    // ---- x86-64 通用寄存器编号（ModRM 顺序） ----
    public static final int GPR_RAX = 0;
    public static final int GPR_RCX = 1;
    public static final int GPR_RDX = 2;
    public static final int GPR_RBX = 3;
    public static final int GPR_RSP = 4;
    public static final int GPR_RBP = 5;
    public static final int GPR_RSI = 6;
    public static final int GPR_RDI = 7;
    public static final int GPR_R8 = 8;
    public static final int GPR_R9 = 9;
    public static final int GPR_R10 = 10;
    public static final int GPR_R11 = 11;
    public static final int GPR_R12 = 12;
    public static final int GPR_R13 = 13;
    public static final int GPR_R14 = 14;
    public static final int GPR_R15 = 15;
    public static final int GPR_COUNT = 16;

    /** 每个通用寄存器占 2 个 frame 字：lo = 2g，hi = 2g + 1。 */
    public static int vmGprSlot(int g) {
        return g * 2;
    }

    public static final int VM_MACH_GPRS = GPR_COUNT;

    // ---- 操作数栈 / 局部帧深度 ----
    public static final int VM_STACK_WORDS = 32;
    public static final int VM_STACK_MASK = VM_STACK_WORDS - 1;
    public static final int VM_FRAME_WORDS = 128;
    public static final int VM_FRAME_MASK = VM_FRAME_WORDS - 1;
    public static final int VM_MAX_STEPS = 131072;
    public static final int VM_MACH_SLOTS = GPR_COUNT * 2;
    public static final int VM_STKFRM_SLOT0 = VM_MACH_SLOTS;
    public static final int VM_STKFRM_WORDS = 64;
    public static final int VM_STKFRM_BYTES = VM_STKFRM_WORDS * 4;
    public static final int VM_TMP_SLOT0 = VM_STKFRM_SLOT0 + VM_STKFRM_WORDS;
    public static final int VM_TMP_VREGS = 16;

    // ---- 调度器类型 ----
    public static final int DISPATCH_TABLE = 0;
    public static final int DISPATCH_SWITCH = 1;
    public static final int VM_DISPATCH_TYPES = 2;

    // ---- handler 变体数 ----
    public static final int VM_VARIANTS = 3;

    // ---- VM 家族 ----
    public static final int VM_FAMILY_STACK = 0;
    public static final int VM_FAMILY_REG = 1;
    public static final int VM_FAMILY_MASK = 0xFF;

    // ---- Family B 寄存器式 ISA ----
    public static final int VM_B_INSN_SIZE = 8;

    public static final int REG_NOP = 0;
    public static final int REG_MOVI = 1;
    public static final int REG_SET64 = 2;
    public static final int REG_MOV = 3;
    public static final int REG_ADD = 4;
    public static final int REG_SUB = 5;
    public static final int REG_MUL = 6;
    public static final int REG_AND = 7;
    public static final int REG_OR = 8;
    public static final int REG_XOR = 9;
    public static final int REG_SHL = 10;
    public static final int REG_SHR = 11;
    public static final int REG_SAR = 12;
    public static final int REG_NEG = 13;
    public static final int REG_NOT = 14;
    public static final int REG_FLD = 15;
    public static final int REG_FLD64 = 16;
    public static final int REG_FST = 17;
    public static final int REG_FST64 = 18;
    public static final int REG_LD = 19;
    public static final int REG_ST = 20;
    public static final int REG_LEA = 21;
    public static final int REG_SETCC = 22;
    public static final int REG_JCC = 23;
    public static final int REG_JMP = 24;
    public static final int REG_RET = 25;
    public static final int REG_NATIVE = 26;
    public static final int REG_COUNT = 27;

    // ---- 条件码 ----
    public static final int VCC_EQ = 0;
    public static final int VCC_NE = 1;
    public static final int VCC_ULT = 2;
    public static final int VCC_UGE = 3;
    public static final int VCC_ULE = 4;
    public static final int VCC_UGT = 5;
    public static final int VCC_SLT = 6;
    public static final int VCC_SGE = 7;
    public static final int VCC_SLE = 8;
    public static final int VCC_SGT = 9;
    public static final int VCC_COUNT = 10;

    // ---- 镜像内部偏移 ----
    public static final int VM_HEADER_SIZE = 64;
    public static final int VM_OFF_OPCODE_MAP = VM_HEADER_SIZE;
    public static final int VM_OFF_VARIANT_MAP = VM_OFF_OPCODE_MAP + SEM_COUNT;
    public static final int VM_OFF_BYTECODE = VM_OFF_VARIANT_MAP + SEM_COUNT;

    public static final int VM_B_OFF_OPCODE_MAP = VM_HEADER_SIZE;
    public static final int VM_B_OFF_BYTECODE = VM_B_OFF_OPCODE_MAP + REG_COUNT;

    // ---- 执行结果码 ----
    public static final int VM_OK = 0;
    public static final int VM_ERR_FAULT = 1;
    public static final int VM_ERR_STACK_OVER = 2;
    public static final int VM_ERR_STACK_UNDER = 3;
    public static final int VM_ERR_BAD_MAGIC = 4;
    public static final int VM_ERR_BAD_OPCODE = 5;
    public static final int VM_ERR_BAD_JUMP = 6;
    public static final int VM_ERR_TOO_DEEP = 7;

    // ---- keystream 派生 ----

    /** 由 header.key[4]（128-bit 会话密钥）派生 256-bit 加密密钥。 */
    public static int[] vmDeriveKey(int[] key) {
        int[] out = new int[8];
        out[0] = key[0];
        out[1] = key[1];
        out[2] = key[2];
        out[3] = key[3];
        out[4] = 0x6B626F58;
        out[5] = 0x6E67696E;
        out[6] = 0x203A6F44;
        out[7] = 0x2179654B;
        return out;
    }

    /** 方案B：加扰表第二密钥派生（与 vmDeriveKey 不同填充 + 混入 map_iv）。 */
    public static int[] vmDeriveKey2(int[] key, int iv) {
        int[] out = new int[8];
        out[0] = key[0] ^ (iv + 0x9E3779B9);
        out[1] = key[1] ^ (iv * 0x85EBCA77);
        out[2] = key[2] ^ ((iv << 13) | (iv >>> 19));
        out[3] = key[3] ^ ((iv >>> 5) | (iv << 27));
        out[4] = 0x4D646E41;
        out[5] = 0x6F6D4F75;
        out[6] = 0x7068434B;
        out[7] = 0x78696649;
        return out;
    }

    // ---- VmImageHeader 字段偏移 ----
    public static final int IH_MAGIC = 0;
    public static final int IH_VERSION = 4;
    public static final int IH_FLAGS = 8;
    public static final int IH_DISPATCH = 12;
    public static final int IH_TOTAL_SIZE = 16;
    public static final int IH_BC_SIZE = 20;
    public static final int IH_ENTRY = 24;
    public static final int IH_STACK_WORDS = 28;
    public static final int IH_KEY = 32;
    public static final int IH_RESERVED = 48;

    /** Family A 指令载体。 */
    public static final class Insn {
        public int sem;
        public int imm;

        public Insn() {
        }

        public Insn(int sem, int imm) {
            this.sem = sem;
            this.imm = imm;
        }
    }

    /** Family B 指令载体。 */
    public static final class BInsn {
        public int op;
        public int rd;
        public int ra;
        public int rb;
        public int imm;

        public BInsn() {
        }

        public BInsn(int op, int rd, int ra, int rb, int imm) {
            this.op = op;
            this.rd = rd;
            this.ra = ra;
            this.rb = rb;
            this.imm = imm;
        }
    }

    /** 条件码求值（与汇编 .Lmx_cceval 同语义）。 */
    public static int ccEval(int cc, int a, int b) {
        switch (cc) {
            case VCC_EQ:
                return a == b ? 1 : 0;
            case VCC_NE:
                return a != b ? 1 : 0;
            case VCC_ULT:
                return Integer.compareUnsigned(a, b) < 0 ? 1 : 0;
            case VCC_UGE:
                return Integer.compareUnsigned(a, b) >= 0 ? 1 : 0;
            case VCC_ULE:
                return Integer.compareUnsigned(a, b) <= 0 ? 1 : 0;
            case VCC_UGT:
                return Integer.compareUnsigned(a, b) > 0 ? 1 : 0;
            case VCC_SLT:
                return a < b ? 1 : 0;
            case VCC_SGE:
                return a >= b ? 1 : 0;
            case VCC_SLE:
                return a <= b ? 1 : 0;
            case VCC_SGT:
                return a > b ? 1 : 0;
            default:
                return 0;
        }
    }
}
