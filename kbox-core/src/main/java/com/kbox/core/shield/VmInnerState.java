package com.kbox.core.shield;

/**
 * VmInnerState — 嵌套虚拟化的"内层执行状态"共享布局（由 include/vm_inner_state.h 移植）。
 *
 * <p>外层 Meta VM 执行的内层解释器程序以内存块保存内层引擎执行状态（内层
 * ip/sp/栈/帧/映射表/keystream 缓存等），该块由引导程序 kbox_vm_run 在栈上
 * 分配（IS_SIZE 字节），指针经 m-state 寄存器传给 Meta 程序。</p>
 *
 * <p>字段均为小端；这些偏移同时被 Meta 程序生成器（{@link MetaInner}）与
 * 汇编引导程序（stub/vm_engine_*.S）使用，两侧必须保持一致。</p>
 */
public final class VmInnerState {

    private VmInnerState() {
    }

    // ---- 内层指令长度/字节码偏移（与 VmIsa 一致） ----
    public static final int IS_INSN_A = 5;
    public static final int IS_INSN_B = 8;
    public static final int IS_BCOFF_A = 136;   // VM_OFF_BYTECODE
    public static final int IS_BCOFF_B = 91;    // VM_B_OFF_BYTECODE
    public static final int IS_SEM_A = 36;      // SEM_COUNT
    public static final int IS_SEM_B = 27;      // REG_COUNT
    public static final int IS_VERSION = 2;

    // ---- 内层状态块偏移 ----
    public static final int IS_IP = 0;
    public static final int IS_SP = 4;
    public static final int IS_RETVAL = 8;
    public static final int IS_STATUS = 12;
    public static final int IS_STEPS = 16;
    public static final int IS_FAMILY = 20;
    public static final int IS_BCSIZE = 24;
    public static final int IS_BCOFF = 28;
    public static final int IS_ILEN = 32;
    public static final int IS_STACKW = 36;
    public static final int IS_IPIMG = 40;
    public static final int IS_KSCNT = 44;
    public static final int IS_IMM = 48;
    public static final int IS_RD = 52;
    public static final int IS_RA = 56;
    public static final int IS_RB = 60;
    public static final int IS_SEM = 64;
    public static final int IS_JUMPED = 68;
    public static final int IS_NSEM = 72;
    public static final int IS_RETC = 76;
    public static final int IS_OPMAP = 128;     // u8[64]
    public static final int IS_REV = 192;       // u8[256]
    public static final int IS_KSBLK = 448;     // u8[64]
    public static final int IS_KS5 = 512;       // u8[8]
    public static final int IS_KEY = 520;       // u8[32]
    public static final int IS_NONCE = 552;     // u8[16]
    public static final int IS_KEY2 = 568;      // u8[32]
    public static final int IS_KSCNT2 = 600;
    public static final int IS_STACK = 604;     // u32[32]
    public static final int IS_FRAME = 732;     // u32[128]
    public static final int IS_SIZE = 1248;

    // ---- 内层 VM 头部字段偏移（与 VmIsa.VmImageHeader 一致） ----
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
    public static final int IH_MAGIC_VAL = 0x4D56424B;
    public static final int IH_SIZE = 64;
}
