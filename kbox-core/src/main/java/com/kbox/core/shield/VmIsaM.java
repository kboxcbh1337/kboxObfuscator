package com.kbox.core.shield;

/**
 * VmIsaM — 外层 Meta VM（嵌套虚拟化的外层）指令集架构（由 include/vm_isa_m.h 移植）。
 *
 * <p>内层 VM（Family A 栈式 / Family B 寄存器式）的解释器本身不再以明文 native
 * 代码存在，而是被编译成 Meta VM 的字节码；Meta VM 解释器（kbox_meta_run）是
 * 唯一残留的明文 native 循环。</p>
 */
public final class VmIsaM {

    private VmIsaM() {
    }

    public static final int M_IMAGE_VERSION = 1;

    /** Meta 镜像魔数由密钥派生（构建期随机），无固定扫描值。 */
    public static int mMagicOf(int[] key) {
        int h = 0x4D56426D;
        for (int i = 0; i < 4; i++) {
            h ^= key[i];
            h *= 0x85EBCA6B;
            h ^= h >>> 15;
        }
        return (h & 0x7FFFFFFF) | 0x80000000;
    }

    // ---- 指令格式：定长 8 字节 ----
    public static final int M_INSN_SIZE = 8;

    // ---- 寄存器 ----
    public static final int M_REGS = 16;

    // ---- Meta 语义 ----
    public static final int M_NOP = 0;
    public static final int M_MOVI = 1;
    public static final int M_SET64 = 2;
    public static final int M_MOV = 3;
    public static final int M_ADD = 4;
    public static final int M_SUB = 5;
    public static final int M_MUL = 6;
    public static final int M_AND = 7;
    public static final int M_OR = 8;
    public static final int M_XOR = 9;
    public static final int M_SHL = 10;
    public static final int M_SHR = 11;
    public static final int M_SAR = 12;
    public static final int M_NEG = 13;
    public static final int M_NOT = 14;
    public static final int M_DIV = 15;
    public static final int M_MOD = 16;
    public static final int M_LD = 17;
    public static final int M_LD32 = 18;
    public static final int M_LD8 = 19;
    public static final int M_ST = 20;
    public static final int M_ST32 = 21;
    public static final int M_ST8 = 22;
    public static final int M_LEA = 23;
    public static final int M_SETCC = 24;
    public static final int M_JMP = 25;
    public static final int M_JCC = 26;
    public static final int M_CALL = 27;
    public static final int M_CALLR = 28;
    public static final int M_JMPR = 29;
    public static final int M_RET = 30;
    public static final int M_HOST = 31;
    public static final int M_HALT = 32;
    public static final int M_COUNT = 33;

    // ---- 条件码（数值沿用 VCC_*） ----
    public static final int M_CC_EQ = 0;
    public static final int M_CC_NE = 1;
    public static final int M_CC_ULT = 2;
    public static final int M_CC_UGE = 3;
    public static final int M_CC_ULE = 4;
    public static final int M_CC_UGT = 5;
    public static final int M_CC_SLT = 6;
    public static final int M_CC_SGE = 7;
    public static final int M_CC_SLE = 8;
    public static final int M_CC_SGT = 9;
    public static final int M_CC_COUNT = 10;

    // ---- 宿主逃逸原语 ----
    public static final int M_HOST_CHACHA = 0;
    public static final int M_HOST_INNER_NATIVE = 1;
    public static final int M_HOST_COUNT = 2;

    /** handler 偏移表所在寄存器（由 vm_meta_exec 置为解密后的表地址）。 */
    public static final int M_HT_REG = 5;

    // ---- Meta 指令载体 ----
    public static final class MInsn {
        public int op;
        public int dst;
        public int src;
        public int aux;
        public int imm;

        public MInsn() {
        }

        public MInsn(int op, int dst, int src, int aux, int imm) {
            this.op = op;
            this.dst = dst;
            this.src = src;
            this.aux = aux;
            this.imm = imm;
        }
    }

    // ---- Meta 镜像头（64 字节） ----
    public static final int M_HEADER_SIZE = 64;
    public static final int M_OFF_OPCODE_MAP = M_HEADER_SIZE;
    public static final int M_HANTAB_ENTRIES = 64;
    public static final int M_OFF_HANDLER_TAB = M_OFF_OPCODE_MAP + M_COUNT;
    public static final int M_OFF_BYTECODE = M_OFF_HANDLER_TAB + M_HANTAB_ENTRIES * 4;

    /** kbox_meta_run 侧常量（与 stub/vm_engine_*.S 一致）。 */
    public static final int MX_MAGIC = 0x4D56424D;
    public static final int MX_VERSION = 1;
    public static final int MX_INSN = 8;
    public static final int MX_HDRSZ = 64;
    public static final int MX_COUNT = 33;
    public static final int MX_OFF_OPMAP = 64;
    public static final int MX_HANTAB_N = 64;
    public static final int MX_OFF_HANTAB = 97;
    public static final int MX_OFF_BC = 353;
    public static final int MX_MAX_STEPS = 8388608;

    // ---- 执行状态码（与内层同值域） ----
    public static final int M_OK = 0;
    public static final int M_ERR_FAULT = 1;
    public static final int M_ERR_BAD_MAGIC = 4;
    public static final int M_ERR_BAD_OPCODE = 5;
    public static final int M_ERR_TOO_DEEP = 7;

    /** 密钥派生（内层 vmDeriveKey 的独立对照：不同固定填充）。 */
    public static int[] mDeriveKey(int[] key) {
        int[] out = new int[8];
        out[0] = key[0];
        out[1] = key[1];
        out[2] = key[2];
        out[3] = key[3];
        out[4] = 0x4D42564D;
        out[5] = 0x6174654D;
        out[6] = 0x6E72654B;
        out[7] = 0x00004C65;
        return out;
    }

    /** 方案B：Meta 加扰第二密钥派生（混入 map_iv）。 */
    public static int[] mDeriveKey2(int[] key, int iv) {
        int[] out = new int[8];
        out[0] = key[0] ^ (iv + 0x85EBCA6B);
        out[1] = key[1] ^ (iv * 0xC2B2AE35);
        out[2] = key[2] ^ ((iv << 17) | (iv >>> 15));
        out[3] = key[3] ^ ((iv >>> 7) | (iv << 25));
        out[4] = 0x656D614C;
        out[5] = 0x614D6162;
        out[6] = 0x65546369;
        out[7] = 0x00617250;
        return out;
    }

    /** Meta 镜像头字段偏移（MImageHeader）。 */
    public static final int MH_MAGIC = 0;
    public static final int MH_VERSION = 4;
    public static final int MH_FLAGS = 8;
    public static final int MH_RESERVED0 = 12;
    public static final int MH_TOTAL_SIZE = 16;
    public static final int MH_BC_SIZE = 20;
    public static final int MH_ENTRY = 24;
    public static final int MH_MAP_IV = 28;
    public static final int MH_KEY = 32;
    public static final int MH_RESERVED = 48;

    /** 内层镜像头 reserved[] 偏移（用于承载 Meta 镜像相对增量/大小）。 */
    public static final int IH_RESERVED = 48;
}
