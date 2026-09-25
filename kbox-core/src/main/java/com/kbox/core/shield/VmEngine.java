package com.kbox.core.shield;

/**
 * VmEngine — 自由态 VM 引擎（由 packer/vm/vm_engine.cpp 移植，头文件契约见 packer/vm/vm_engine.h）。
 *
 * <p>执行模型：</p>
 * <pre>
 *   镜像 = [VmImageHeader][加密 opcode_map][加密 variant_map][加密 bytecode]
 *   1. 校验 header。
 *   2. 一次性解密两张映射表到调用方栈上缓冲（VmCtx 内）。
 *   3. 建立 opcode -&gt; 语义 反向表。
 *   4. 进入调度循环：每次取指**就地**解密一条指令（[opcode][imm]，固定
 *      VM_INSN_SIZE 字节）到镜像缓冲，执行后立即用同一 keystream 回写密文，
 *      使运行期内存中任一时刻至多存在一条指令的明文（抗内存 dump）。
 *      因此镜像缓冲必须是可写的，引擎返回时其内容与进入时逐字节一致。
 * </pre>
 *
 * <p>自由态安全：无全局/静态可写状态，全部执行状态在 VmCtx（由调用方
 * 提供），可重入、可多实例并发。引擎不分配堆内存。</p>
 *
 * <p>多态机制在本文件的体现（同 vm_engine.cpp）：运行时解密取指；opcode 随机
 * 重排（decode 后经反向表映射到语义）；handler 多态（每语义多组等价变体，
 * variant_map 择一）；调度混淆（DISPATCH_TABLE / DISPATCH_SWITCH）。</p>
 *
 * <p>类型映射：uint8_t/uint16_t/uint32_t -&gt; {@code int}，uint64_t -&gt; {@code long}；
 * 逻辑右移用 {@code >>>}，无符号比较/除法用 Integer/Long 的无符号静态方法，
 * 32 位移位量 {@code & 31}。</p>
 */
public final class VmEngine {

    private VmEngine() {
    }

    // ==================== 公开类型 ====================

    /**
     * 原生片段执行器（混合模型 / 指令级 exit-to-native）。
     * C++: {@code typedef uint32_t (*VmNativeFn)(VmCtx*, uint32_t)}。
     *
     * <p>SEM_NATIVE / REG_NATIVE 触发时由引擎回调：imm 为镜像内原生片段序号，
     * 执行器负责在 VM 之外执行该片段并回写机器状态（frame 中的通用寄存器槽）。
     * 未提供执行器时返回 VM_ERR_FAULT。</p>
     */
    public interface VmNativeFn {
        int call(VmCtx ctx, int imm);
    }

    /**
     * handler 变体函数签名：返回 VM_OK 或错误码。
     * C++: {@code typedef uint32_t (*VmHandler)(VmCtx*, uint32_t)}。
     */
    public interface VmHandler {
        int call(VmCtx ctx, int imm);
    }

    /** 语义表条目（名称 + 变体 handler 数组；不足 VM_VARIANTS 的以 null 结尾）。 */
    public static final class VmSemInfo {
        public String name;
        public VmHandler[] variants;

        public VmSemInfo() {
        }

        public VmSemInfo(String name, VmHandler[] variants) {
            this.name = name;
            this.variants = variants;
        }
    }

    /**
     * 执行上下文（自由态，由调用方提供）。字段与 C++ {@code struct VmCtx} 一一对应。
     *
     * <p>image 必须可写（就地解密/回加密），返回时内容与进入时逐字节一致。</p>
     */
    public static final class VmCtx {
        /** 镜像基址。 */
        public byte[] image;
        /** 镜像大小。 */
        public int imageSize;
        /** 派生 256-bit 密钥。 */
        public int[] k8 = new int[8];
        /** 字节码在镜像内的偏移。 */
        public int bcOff;
        /** 字节码字节数。 */
        public int bcSize;
        /** 实际栈深（来自 header）。 */
        public int stackWords;
        /** 指令指针（字节偏移，相对 bc）。 */
        public int ip;
        /** 当前指令在镜像内的绝对偏移（取指时记录；回加密用）。 */
        public int insnOff;
        /** VM_FAMILY_*（来自 header.flags 低 8 位）。 */
        public int family;
        /** 指令长度（A=5，B=8）。 */
        public int insnLen;
        /** 栈指针。 */
        public int sp;
        /** RET 弹出值。 */
        public int retval;
        /** 已执行指令数（超限保护）。 */
        public int stepCount;
        /** 操作数栈。 */
        public int[] stack = new int[VmIsa.VM_STACK_WORDS];
        /** 局部帧。 */
        public int[] frame = new int[VmIsa.VM_FRAME_WORDS];

        // 混合模型：原生片段执行器（可为 null）
        public VmNativeFn nativeFn;
        /** C++: {@code void* native_arg}。 */
        public Object nativeArg;

        // 解密后的映射表（语义号 -> opcode；opcode -> 语义反查）
        public int[] opcodeMap = new int[VmIsa.SEM_COUNT];
        public int[] variantMap = new int[VmIsa.SEM_COUNT];

        // keystream 块缓存
        public byte[] ksBlock = new byte[64];
        /** 当前缓存块序号（0xFFFFFFFF = 未初始化）。 */
        public int ksCounter;
        /** 当前指令的 keystream（最长 8B，供回加密）。 */
        public byte[] ks5 = new byte[VmIsa.VM_B_INSN_SIZE];
    }

    // ==================== 栈操作辅助（带边界检查） ====================

    private static boolean vpush(VmCtx c, int v) {
        if (c.sp >= c.stackWords) return false;
        c.stack[c.sp] = v;
        c.sp = c.sp + 1;
        return true;
    }

    /** C++ 为引用出参，Java 以单元素数组承载。 */
    private static boolean vpop(VmCtx c, int[] out) {
        if (c.sp == 0) return false;
        c.sp = c.sp - 1;
        out[0] = c.stack[c.sp];
        return true;
    }

    private static boolean vpeek(VmCtx c, int[] out) {
        if (c.sp == 0) return false;
        out[0] = c.stack[c.sp - 1];
        return true;
    }

    /** 64 位值（地址/指针）在栈上按 lo, hi 顺序压入（hi 在栈顶）。 */
    private static boolean vpush64(VmCtx c, long v) {
        return vpush(c, (int) v) && vpush(c, (int) (v >>> 32));
    }

    private static boolean vpop64(VmCtx c, long[] out) {
        int[] t = new int[1];
        int hi, lo;
        if (!vpop(c, t)) return false;
        hi = t[0];
        if (!vpop(c, t)) return false;
        lo = t[0];
        out[0] = ((long) lo & 0xFFFFFFFFL) | (((long) hi & 0xFFFFFFFFL) << 32);
        return true;
    }

    /** 有符号 32 位位移（imm 字段语义）。Java 的 int 即 int32，故直接返回。 */
    private static long simm32(int imm) {
        return (long) imm;
    }

    // ---- Family B：寄存器号 -> frame 槽（lo；hi = lo+1）----
    //   r0..r15  = 机器 GPR（slot 2r）；r16..r31 = 临时（slot 2r+64）→ 96..127
    private static int rslot(int r) {
        return (r < 16) ? (r * 2) : (r * 2 + 64);
    }

    // ---- keystream 逐字节解密（镜像绝对偏移定位，块缓存）----
    private static byte ksByte(VmCtx c, int pos) {
        final int blk = pos >>> 6;
        if (blk != c.ksCounter) {
            VmKs.vmKsBlock(c.k8, blk, c.ksBlock);
            c.ksCounter = blk;
        }
        return c.ksBlock[pos & 63];
    }

    // ---- 取指：**就地**解密 [opcode][imm] 一条指令 ----
    // 解密结果写回镜像缓冲（明文），同时缓存这 5 字节的 keystream 供回加密。
    private static int fetchInsn(VmCtx c, int[] opcodeOut, int[] immOut) {
        if (Integer.compareUnsigned(c.ip, c.bcSize) > 0
                || Integer.compareUnsigned(c.ip + VmIsa.VM_INSN_SIZE, c.bcSize) > 0) {
            return VmIsa.VM_ERR_FAULT;
        }
        final int base = c.bcOff + c.ip;
        c.insnOff = base;              // 记录绝对偏移（跳转 handler 会改 ip）
        for (int i = 0; i < VmIsa.VM_INSN_SIZE; i++) {
            final byte k = ksByte(c, base + i);
            c.ks5[i] = k;
            c.image[base + i] ^= k;    // 密文 -> 明文（就地）
        }
        opcodeOut[0] = c.image[base] & 0xFF;
        int v = 0;
        for (int i = 0; i < 4; i++) {
            v |= (c.image[base + 1 + i] & 0xFF) << (8 * i);
        }
        immOut[0] = v;
        return VmIsa.VM_OK;
    }

    // ---- 回加密：把当前指令的明文用同一 keystream 写回密文 ----
    // 保证引擎返回时镜像与进入时逐字节一致（幂等、可多次调用）。
    private static void reencryptInsn(VmCtx c) {
        for (int i = 0; i < c.insnLen; i++) {
            c.image[c.insnOff + i] ^= c.ks5[i];
        }
    }

    // 步数上限（防恶意镜像死循环）复用 include/vm_isa.h 的 VM_MAX_STEPS——
    // 与 x86 汇编引擎、Meta 化内层解释器同一取值，保证打包期预演与运行期一致。
    // （常量取自 VmIsa.VM_MAX_STEPS）

    // 映射区加解密只叠加单 keystream（ks1）：与运行期汇编引擎
    // （stub/vm_engine_*.S 的单块 X_KSBLK 缓存）及 Meta 化的内层解释器
    // （packer/vm/meta_inner.cpp 的 L_ksbyte）保持一致。

    /** 读出 header.key[4]。 */
    private static int[] headerKey(byte[] image) {
        int[] key = new int[4];
        for (int i = 0; i < 4; i++) {
            key[i] = Bin.i32(image, VmIsa.IH_KEY + 4 * i);
        }
        return key;
    }

    // 解码映射表 + 建立反向表，返回错误码
    private static int decodeTables(VmCtx c, int[] opcodeRev) {
        for (int i = 0; i < 256; i++) {
            opcodeRev[i] = 0xFF;
        }
        for (int s = 0; s < VmIsa.SEM_COUNT; s++) {
            final int off = VmIsa.VM_OFF_OPCODE_MAP + s;
            c.opcodeMap[s] = (c.image[off] ^ ksByte(c, off)) & 0xFF;
            final int voff = VmIsa.VM_OFF_VARIANT_MAP + s;
            c.variantMap[s] = (c.image[voff] ^ ksByte(c, voff)) & 0xFF;
        }
        for (int s = 0; s < VmIsa.SEM_COUNT; s++) {
            final int op = c.opcodeMap[s];
            if (opcodeRev[op] != 0xFF) return VmIsa.VM_ERR_BAD_OPCODE; // 非排列
            opcodeRev[op] = s;
        }
        return VmIsa.VM_OK;
    }

    // 语义的实际变体数（表内连续非空项个数，保证 >= 1）
    private static int vcount(int sem) {
        int n = 0;
        for (; n < VmIsa.VM_VARIANTS; n++) {
            if (SEM_TABLE[sem].variants[n] == null) break;
        }
        return n;
    }

    // 取合法变体号（按该语义实际变体数取模）
    private static int pickVariant(VmCtx c, int sem) {
        return c.variantMap[sem] % vcount(sem);
    }

    // ==================== handler 变体实现 ====================
    // 约定：错误返回非 VM_OK；跳转类通过修改 ctx.ip 生效（主循环统一 +VM_INSN_SIZE）；
    // RET 弹出返回值到 ctx.retval。

    // ---- SEM_NOP ----
    private static int hNopV0(VmCtx c, int imm) {
        return VmIsa.VM_OK;
    }

    private static int hNopV1(VmCtx c, int imm) {
        return VmIsa.VM_OK;
    }

    // ---- SEM_PUSH ----
    private static int hPushV0(VmCtx c, int imm) {
        return vpush(c, imm) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hPushV1(VmCtx c, int imm) {
        final int v = imm;
        if (c.sp >= c.stackWords) return VmIsa.VM_ERR_STACK_OVER;
        c.stack[c.sp] = v;
        c.sp = c.sp + 1;
        return VmIsa.VM_OK;
    }

    // ---- SEM_LOAD ----
    private static int hLoadV0(VmCtx c, int imm) {
        return vpush(c, c.frame[imm & VmIsa.VM_FRAME_MASK]) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hLoadV1(VmCtx c, int imm) {
        final int idx = imm & VmIsa.VM_FRAME_MASK;
        final int v = c.frame[idx];
        return vpush(c, v) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    // ---- SEM_STORE ----
    private static int hStoreV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        c.frame[imm & VmIsa.VM_FRAME_MASK] = t[0];
        return VmIsa.VM_OK;
    }

    private static int hStoreV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int v = t[0];
        final int idx = imm & VmIsa.VM_FRAME_MASK;
        c.frame[idx] = v;
        return VmIsa.VM_OK;
    }

    // ---- SEM_DUP ----
    private static int hDupV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpeek(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        return vpush(c, t[0]) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hDupV1(VmCtx c, int imm) {
        if (c.sp == 0 || c.sp >= c.stackWords) {
            return (c.sp == 0) ? VmIsa.VM_ERR_STACK_UNDER : VmIsa.VM_ERR_STACK_OVER;
        }
        c.stack[c.sp] = c.stack[c.sp - 1];
        c.sp = c.sp + 1;
        return VmIsa.VM_OK;
    }

    // ---- SEM_SWAP ----
    private static int hSwapV0(VmCtx c, int imm) {
        if (c.sp < 2) return VmIsa.VM_ERR_STACK_UNDER;
        final int t = c.stack[c.sp - 1];
        c.stack[c.sp - 1] = c.stack[c.sp - 2];
        c.stack[c.sp - 2] = t;
        return VmIsa.VM_OK;
    }

    private static int hSwapV1(VmCtx c, int imm) {
        if (c.sp < 2) return VmIsa.VM_ERR_STACK_UNDER;
        c.stack[c.sp - 1] ^= c.stack[c.sp - 2];
        c.stack[c.sp - 2] ^= c.stack[c.sp - 1];
        c.stack[c.sp - 1] ^= c.stack[c.sp - 2];
        return VmIsa.VM_OK;
    }

    // ---- SEM_POP ----
    private static int hPopV0(VmCtx c, int imm) {
        if (c.sp == 0) return VmIsa.VM_ERR_STACK_UNDER;
        c.sp = c.sp - 1;
        return VmIsa.VM_OK;
    }

    // ---- 二元算术（对应 BINOP_H 宏生成的 v0/v1 写法变体，v2 为代数等价实现）----

    private static int hAddV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a + b) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hAddV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a + b;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** 加宽计算后截断（代数等价变体）。 */
    private static int hAddV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, (int) (((long) a & 0xFFFFFFFFL) + ((long) b & 0xFFFFFFFFL)))
                ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSubV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a - b) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSubV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a - b;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** a-b = a + ~b + 1（代数等价变体）。 */
    private static int hSubV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a + ~b + 1) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hMulV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a * b) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hMulV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a * b;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** 加宽计算后截断（代数等价变体）。 */
    private static int hMulV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, (int) (((long) a & 0xFFFFFFFFL) * ((long) b & 0xFFFFFFFFL)))
                ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hAndV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a & b) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hAndV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a & b;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** 德摩根：a&amp;b = ~(~a|~b)（代数等价变体）。 */
    private static int hAndV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, ~(~a | ~b)) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hOrV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a | b) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hOrV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a | b;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** 德摩根：a|b = ~(~a&amp;~b)（代数等价变体）。 */
    private static int hOrV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, ~(~a & ~b)) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hXorV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a ^ b) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hXorV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a ^ b;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** a^b = (a|b) - (a&amp;b)（代数等价变体）。 */
    private static int hXorV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, (a | b) - (a & b)) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hShlV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a << (b & 31)) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hShlV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a << (b & 31);
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** 显式位移量（代数等价变体）。 */
    private static int hShlV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int n = b & 31;
        return vpush(c, a << n) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hShrV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a >>> (b & 31)) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hShrV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a >>> (b & 31);
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** 显式位移量（代数等价变体）。 */
    private static int hShrV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int n = b & 31;
        return vpush(c, a >>> n) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSarV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a >> (b & 31)) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSarV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = a >> (b & 31);
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    /** 显式位移量（代数等价变体）。 */
    private static int hSarV2(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int n = b & 31;
        return vpush(c, a >> n) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    // ---- SEM_NEG ----
    private static int hNegV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, 0 - a) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hNegV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, ~a + 1) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    // ---- SEM_NOT ----
    private static int hNotV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, ~a) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hNotV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        return vpush(c, a ^ 0xFFFFFFFF) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    // ---- SEM_JMP ----
    // imm 单位为指令数（相对下一条），ip 以字节计，故乘 VM_INSN_SIZE
    private static int hJmpV0(VmCtx c, int imm) {
        c.ip = c.ip + imm * VmIsa.VM_INSN_SIZE;
        return VmIsa.VM_OK;
    }

    private static int hJmpV1(VmCtx c, int imm) {
        final int rel = imm * VmIsa.VM_INSN_SIZE;
        c.ip = c.ip + rel;
        return VmIsa.VM_OK;
    }

    // ---- SEM_JZ / SEM_JNZ ----
    private static int hJzV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int v = t[0];
        if (v == 0) c.ip = c.ip + imm * VmIsa.VM_INSN_SIZE;
        return VmIsa.VM_OK;
    }

    private static int hJzV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int v = t[0];
        final boolean taken = (v == 0);
        if (taken) c.ip = c.ip + imm * VmIsa.VM_INSN_SIZE;
        return VmIsa.VM_OK;
    }

    private static int hJnzV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int v = t[0];
        if (v != 0) c.ip = c.ip + imm * VmIsa.VM_INSN_SIZE;
        return VmIsa.VM_OK;
    }

    private static int hJnzV1(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int v = t[0];
        final boolean taken = (v != 0);
        if (taken) c.ip = c.ip + imm * VmIsa.VM_INSN_SIZE;
        return VmIsa.VM_OK;
    }

    // ---- SEM_RET ----
    private static int hRetV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        c.retval = t[0];
        return VmIsa.VM_OK;
    }

    private static int hRetV1(VmCtx c, int imm) {
        if (c.sp == 0) return VmIsa.VM_ERR_STACK_UNDER;
        c.sp = c.sp - 1;
        c.retval = c.stack[c.sp];
        return VmIsa.VM_OK;
    }

    // ---- Batch 5：内存 / 地址 / 原生逃逸 / 比较 ----
    // 移植偏差：C++ 对 base+disp 做宿主地址解引用（*(u32*)）；Java 无通用地址空间，
    // 无法对任意 64 位地址读写，故 SEM_MEMRD / SEM_MEMWR / REG_LD / REG_ST 返回
    // VM_ERR_FAULT（与「未提供原生执行器时 SEM_NATIVE 返回 VM_ERR_FAULT」的约定一致）。
    // 操作数的弹出顺序与地址计算保持与 C++ 完全一致。

    // SEM_MEMRD：弹 base(hi,lo)，读 *(u32*)(base + disp) 并零扩展压栈
    private static int hMemrdV0(VmCtx c, int imm) {
        long[] t = new long[1];
        if (!vpop64(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final long base = t[0];
        final long addr = base + simm32(imm);   // C++ 的有效地址（此处不可解引用）
        return VmIsa.VM_ERR_FAULT;
    }

    // SEM_MEMWR：弹 val、base(hi,lo)，写 *(u32*)(base + disp)
    private static int hMemwrV0(VmCtx c, int imm) {
        int[] t = new int[1];
        long[] t64 = new long[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int v = t[0];
        if (!vpop64(c, t64)) return VmIsa.VM_ERR_STACK_UNDER;
        final long base = t64[0];
        final long addr = base + simm32(imm);   // C++ 的有效地址（此处不可解引用）
        return VmIsa.VM_ERR_FAULT;
    }

    // SEM_ADDREL：弹 base(hi,lo)，压 (base + disp) 的 (lo,hi)
    private static int hAddrelV0(VmCtx c, int imm) {
        long[] t = new long[1];
        if (!vpop64(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final long base = t[0];
        return vpush64(c, base + simm32(imm)) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    // SEM_NATIVE：退出到原生执行（由调用方注入的执行器负责）
    private static int hNativeV0(VmCtx c, int imm) {
        if (c.nativeFn == null) return VmIsa.VM_ERR_FAULT;
        return c.nativeFn.call(c, imm);
    }

    // 比较类：弹 b、弹 a，压 0/1
    private static int hEqV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (a == b) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hNeV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (a != b) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hUltV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (Integer.compareUnsigned(a, b) < 0) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hUgeV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (Integer.compareUnsigned(a, b) >= 0) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hUleV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (Integer.compareUnsigned(a, b) <= 0) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hUgtV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (Integer.compareUnsigned(a, b) > 0) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSltV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (a < b) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSgeV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (a >= b) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSleV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (a <= b) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    private static int hSgtV0(VmCtx c, int imm) {
        int[] t = new int[1];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int b = t[0];
        if (!vpop(c, t)) return VmIsa.VM_ERR_STACK_UNDER;
        final int a = t[0];
        final int r = (a > b) ? 1 : 0;
        return vpush(c, r) ? VmIsa.VM_OK : VmIsa.VM_ERR_STACK_OVER;
    }

    // ==================== 语义表 ====================
    // 对应 C++ extern const VmSemInfo kSemTable[SEM_COUNT]（顺序即语义号）。
    private static final VmSemInfo[] SEM_TABLE = {
            new VmSemInfo("NOP", new VmHandler[]{VmEngine::hNopV0, VmEngine::hNopV1, null}),
            new VmSemInfo("PUSH", new VmHandler[]{VmEngine::hPushV0, VmEngine::hPushV1, null}),
            new VmSemInfo("LOAD", new VmHandler[]{VmEngine::hLoadV0, VmEngine::hLoadV1, null}),
            new VmSemInfo("STORE", new VmHandler[]{VmEngine::hStoreV0, VmEngine::hStoreV1, null}),
            new VmSemInfo("DUP", new VmHandler[]{VmEngine::hDupV0, VmEngine::hDupV1, null}),
            new VmSemInfo("SWAP", new VmHandler[]{VmEngine::hSwapV0, VmEngine::hSwapV1, null}),
            new VmSemInfo("POP", new VmHandler[]{VmEngine::hPopV0, null, null}),
            new VmSemInfo("ADD", new VmHandler[]{VmEngine::hAddV0, VmEngine::hAddV1, VmEngine::hAddV2}),
            new VmSemInfo("SUB", new VmHandler[]{VmEngine::hSubV0, VmEngine::hSubV1, VmEngine::hSubV2}),
            new VmSemInfo("MUL", new VmHandler[]{VmEngine::hMulV0, VmEngine::hMulV1, VmEngine::hMulV2}),
            new VmSemInfo("NEG", new VmHandler[]{VmEngine::hNegV0, VmEngine::hNegV1, null}),
            new VmSemInfo("AND", new VmHandler[]{VmEngine::hAndV0, VmEngine::hAndV1, VmEngine::hAndV2}),
            new VmSemInfo("OR", new VmHandler[]{VmEngine::hOrV0, VmEngine::hOrV1, VmEngine::hOrV2}),
            new VmSemInfo("XOR", new VmHandler[]{VmEngine::hXorV0, VmEngine::hXorV1, VmEngine::hXorV2}),
            new VmSemInfo("NOT", new VmHandler[]{VmEngine::hNotV0, VmEngine::hNotV1, null}),
            new VmSemInfo("SHL", new VmHandler[]{VmEngine::hShlV0, VmEngine::hShlV1, VmEngine::hShlV2}),
            new VmSemInfo("SHR", new VmHandler[]{VmEngine::hShrV0, VmEngine::hShrV1, VmEngine::hShrV2}),
            new VmSemInfo("SAR", new VmHandler[]{VmEngine::hSarV0, VmEngine::hSarV1, VmEngine::hSarV2}),
            new VmSemInfo("JMP", new VmHandler[]{VmEngine::hJmpV0, VmEngine::hJmpV1, null}),
            new VmSemInfo("JZ", new VmHandler[]{VmEngine::hJzV0, VmEngine::hJzV1, null}),
            new VmSemInfo("JNZ", new VmHandler[]{VmEngine::hJnzV0, VmEngine::hJnzV1, null}),
            new VmSemInfo("RET", new VmHandler[]{VmEngine::hRetV0, VmEngine::hRetV1, null}),
            new VmSemInfo("MEMRD", new VmHandler[]{VmEngine::hMemrdV0, null, null}),
            new VmSemInfo("MEMWR", new VmHandler[]{VmEngine::hMemwrV0, null, null}),
            new VmSemInfo("ADDREL", new VmHandler[]{VmEngine::hAddrelV0, null, null}),
            new VmSemInfo("NATIVE", new VmHandler[]{VmEngine::hNativeV0, null, null}),
            new VmSemInfo("EQ", new VmHandler[]{VmEngine::hEqV0, null, null}),
            new VmSemInfo("NE", new VmHandler[]{VmEngine::hNeV0, null, null}),
            new VmSemInfo("ULT", new VmHandler[]{VmEngine::hUltV0, null, null}),
            new VmSemInfo("UGE", new VmHandler[]{VmEngine::hUgeV0, null, null}),
            new VmSemInfo("ULE", new VmHandler[]{VmEngine::hUleV0, null, null}),
            new VmSemInfo("UGT", new VmHandler[]{VmEngine::hUgtV0, null, null}),
            new VmSemInfo("SLT", new VmHandler[]{VmEngine::hSltV0, null, null}),
            new VmSemInfo("SGE", new VmHandler[]{VmEngine::hSgeV0, null, null}),
            new VmSemInfo("SLE", new VmHandler[]{VmEngine::hSleV0, null, null}),
            new VmSemInfo("SGT", new VmHandler[]{VmEngine::hSgtV0, null, null}),
    };

    /** 语义表（对应 C++ extern const VmSemInfo kSemTable[SEM_COUNT]）。 */
    public static VmSemInfo[] semTable() {
        return SEM_TABLE;
    }

    // ==================== Family A 主循环（栈式） ====================

    // ---- 主循环（表驱动 / 集中式 switch 两种分发）----
    private static int vmRun(byte[] image, VmCtx ctx, int[] out) {
        final int dispatch = Bin.i32(image, VmIsa.IH_DISPATCH);
        int[] opcodeRev = new int[256];
        final int rc0 = decodeTables(ctx, opcodeRev);
        if (rc0 != VmIsa.VM_OK) return rc0;

        // 表驱动分发：按 opcode 组装运行期分发表（内容仅本次构建可见）
        VmHandler[] disp = new VmHandler[256];
        for (int s = 0; s < VmIsa.SEM_COUNT; s++) {
            final int op = ctx.opcodeMap[s];
            disp[op] = SEM_TABLE[s].variants[pickVariant(ctx, s)];
        }

        int[] opcodeOut = new int[1];
        int[] immOut = new int[1];
        for (;;) {
            ctx.stepCount = ctx.stepCount + 1;
            if (Integer.compareUnsigned(ctx.stepCount, VmIsa.VM_MAX_STEPS) > 0) {
                return VmIsa.VM_ERR_TOO_DEEP;
            }
            final int rc = fetchInsn(ctx, opcodeOut, immOut);
            if (rc != VmIsa.VM_OK) return rc;
            final int opcode = opcodeOut[0];
            final int imm = immOut[0];

            final int sem = opcodeRev[opcode];
            if (sem >= VmIsa.SEM_COUNT) {
                reencryptInsn(ctx);
                return VmIsa.VM_ERR_BAD_OPCODE;
            }

            int hrc;
            if (dispatch == VmIsa.DISPATCH_SWITCH) {
                // 集中式 switch 分发（按语义号，不经分发表）
                switch (sem) {
                    case VmIsa.SEM_NOP:
                        hrc = SEM_TABLE[VmIsa.SEM_NOP].variants[pickVariant(ctx, VmIsa.SEM_NOP)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_PUSH:
                        hrc = SEM_TABLE[VmIsa.SEM_PUSH].variants[pickVariant(ctx, VmIsa.SEM_PUSH)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_LOAD:
                        hrc = SEM_TABLE[VmIsa.SEM_LOAD].variants[pickVariant(ctx, VmIsa.SEM_LOAD)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_STORE:
                        hrc = SEM_TABLE[VmIsa.SEM_STORE].variants[pickVariant(ctx, VmIsa.SEM_STORE)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_DUP:
                        hrc = SEM_TABLE[VmIsa.SEM_DUP].variants[pickVariant(ctx, VmIsa.SEM_DUP)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SWAP:
                        hrc = SEM_TABLE[VmIsa.SEM_SWAP].variants[pickVariant(ctx, VmIsa.SEM_SWAP)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_POP:
                        hrc = SEM_TABLE[VmIsa.SEM_POP].variants[pickVariant(ctx, VmIsa.SEM_POP)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_ADD:
                        hrc = SEM_TABLE[VmIsa.SEM_ADD].variants[pickVariant(ctx, VmIsa.SEM_ADD)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SUB:
                        hrc = SEM_TABLE[VmIsa.SEM_SUB].variants[pickVariant(ctx, VmIsa.SEM_SUB)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_MUL:
                        hrc = SEM_TABLE[VmIsa.SEM_MUL].variants[pickVariant(ctx, VmIsa.SEM_MUL)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_NEG:
                        hrc = SEM_TABLE[VmIsa.SEM_NEG].variants[pickVariant(ctx, VmIsa.SEM_NEG)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_AND:
                        hrc = SEM_TABLE[VmIsa.SEM_AND].variants[pickVariant(ctx, VmIsa.SEM_AND)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_OR:
                        hrc = SEM_TABLE[VmIsa.SEM_OR].variants[pickVariant(ctx, VmIsa.SEM_OR)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_XOR:
                        hrc = SEM_TABLE[VmIsa.SEM_XOR].variants[pickVariant(ctx, VmIsa.SEM_XOR)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_NOT:
                        hrc = SEM_TABLE[VmIsa.SEM_NOT].variants[pickVariant(ctx, VmIsa.SEM_NOT)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SHL:
                        hrc = SEM_TABLE[VmIsa.SEM_SHL].variants[pickVariant(ctx, VmIsa.SEM_SHL)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SHR:
                        hrc = SEM_TABLE[VmIsa.SEM_SHR].variants[pickVariant(ctx, VmIsa.SEM_SHR)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SAR:
                        hrc = SEM_TABLE[VmIsa.SEM_SAR].variants[pickVariant(ctx, VmIsa.SEM_SAR)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_JMP:
                        hrc = SEM_TABLE[VmIsa.SEM_JMP].variants[pickVariant(ctx, VmIsa.SEM_JMP)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_JZ:
                        hrc = SEM_TABLE[VmIsa.SEM_JZ].variants[pickVariant(ctx, VmIsa.SEM_JZ)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_JNZ:
                        hrc = SEM_TABLE[VmIsa.SEM_JNZ].variants[pickVariant(ctx, VmIsa.SEM_JNZ)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_RET:
                        hrc = SEM_TABLE[VmIsa.SEM_RET].variants[pickVariant(ctx, VmIsa.SEM_RET)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_MEMRD:
                        hrc = SEM_TABLE[VmIsa.SEM_MEMRD].variants[pickVariant(ctx, VmIsa.SEM_MEMRD)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_MEMWR:
                        hrc = SEM_TABLE[VmIsa.SEM_MEMWR].variants[pickVariant(ctx, VmIsa.SEM_MEMWR)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_ADDREL:
                        hrc = SEM_TABLE[VmIsa.SEM_ADDREL].variants[pickVariant(ctx, VmIsa.SEM_ADDREL)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_NATIVE:
                        hrc = SEM_TABLE[VmIsa.SEM_NATIVE].variants[pickVariant(ctx, VmIsa.SEM_NATIVE)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_EQ:
                        hrc = SEM_TABLE[VmIsa.SEM_EQ].variants[pickVariant(ctx, VmIsa.SEM_EQ)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_NE:
                        hrc = SEM_TABLE[VmIsa.SEM_NE].variants[pickVariant(ctx, VmIsa.SEM_NE)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_ULT:
                        hrc = SEM_TABLE[VmIsa.SEM_ULT].variants[pickVariant(ctx, VmIsa.SEM_ULT)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_UGE:
                        hrc = SEM_TABLE[VmIsa.SEM_UGE].variants[pickVariant(ctx, VmIsa.SEM_UGE)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_ULE:
                        hrc = SEM_TABLE[VmIsa.SEM_ULE].variants[pickVariant(ctx, VmIsa.SEM_ULE)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_UGT:
                        hrc = SEM_TABLE[VmIsa.SEM_UGT].variants[pickVariant(ctx, VmIsa.SEM_UGT)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SLT:
                        hrc = SEM_TABLE[VmIsa.SEM_SLT].variants[pickVariant(ctx, VmIsa.SEM_SLT)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SGE:
                        hrc = SEM_TABLE[VmIsa.SEM_SGE].variants[pickVariant(ctx, VmIsa.SEM_SGE)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SLE:
                        hrc = SEM_TABLE[VmIsa.SEM_SLE].variants[pickVariant(ctx, VmIsa.SEM_SLE)].call(ctx, imm);
                        break;
                    case VmIsa.SEM_SGT:
                        hrc = SEM_TABLE[VmIsa.SEM_SGT].variants[pickVariant(ctx, VmIsa.SEM_SGT)].call(ctx, imm);
                        break;
                    default:
                        reencryptInsn(ctx);
                        return VmIsa.VM_ERR_BAD_OPCODE;
                }
            } else {
                // 表驱动分发：直接经 opcode 查运行期分发表
                final VmHandler hd = disp[opcode];
                if (hd == null) {
                    reencryptInsn(ctx);
                    return VmIsa.VM_ERR_BAD_OPCODE;
                }
                hrc = hd.call(ctx, imm);
            }
            reencryptInsn(ctx);            // 执行后立即回写密文（成功/失败都回写）
            if (hrc != VmIsa.VM_OK) return hrc;

            if (sem == VmIsa.SEM_RET) {
                out[0] = ctx.retval;
                return VmIsa.VM_OK;
            }
            ctx.ip += VmIsa.VM_INSN_SIZE;
        }
    }

    // ==================== Family B 主循环（寄存器式） ====================
    // 8 字节定长，绝对跳转偏移。
    private static int vmRunB(byte[] image, VmCtx ctx, int[] out) {
        int[] opcodeRev = new int[256];
        for (int i = 0; i < 256; i++) {
            opcodeRev[i] = 0xFF;
        }
        for (int s = 0; s < VmIsa.REG_COUNT; s++) {
            final int off = VmIsa.VM_B_OFF_OPCODE_MAP + s;
            ctx.opcodeMap[s] = (image[off] ^ ksByte(ctx, off)) & 0xFF;
        }
        for (int s = 0; s < VmIsa.REG_COUNT; s++) {
            final int op = ctx.opcodeMap[s];
            if (opcodeRev[op] != 0xFF) return VmIsa.VM_ERR_BAD_OPCODE; // 非排列
            opcodeRev[op] = s;
        }

        // RB(r) = F[rslot(r)]；RBH(r) = F[rslot(r)+1]
        final int[] F = ctx.frame;

        for (;;) {
            ctx.stepCount = ctx.stepCount + 1;
            if (Integer.compareUnsigned(ctx.stepCount, VmIsa.VM_MAX_STEPS) > 0) {
                return VmIsa.VM_ERR_TOO_DEEP;
            }
            // 取指（就地解密 8 字节）
            if (Integer.compareUnsigned(ctx.ip, ctx.bcSize) > 0
                    || Integer.compareUnsigned(ctx.ip + VmIsa.VM_B_INSN_SIZE, ctx.bcSize) > 0) {
                return VmIsa.VM_ERR_FAULT;
            }
            final int base = VmIsa.VM_B_OFF_BYTECODE + ctx.ip;
            ctx.insnOff = base;
            for (int i = 0; i < VmIsa.VM_B_INSN_SIZE; i++) {
                final byte k = ksByte(ctx, base + i);
                ctx.ks5[i] = k;
                image[base + i] ^= k;
            }
            final int opc = image[base] & 0xFF;
            final int rd = image[base + 1] & 0xFF;
            final int ra = image[base + 2] & 0xFF;
            final int rb = image[base + 3] & 0xFF;
            int imm = 0;
            for (int i = 0; i < 4; i++) imm |= (image[base + 4 + i] & 0xFF) << (8 * i);

            final int sem = opcodeRev[opc];
            if (sem >= VmIsa.REG_COUNT) {
                reencryptInsn(ctx);
                return VmIsa.VM_ERR_BAD_OPCODE;
            }

            int hrc = VmIsa.VM_OK;
            boolean isRet = false;
            boolean jumped = false;
            switch (sem) {
                case VmIsa.REG_NOP:
                    break;
                case VmIsa.REG_MOVI:
                    F[rslot(rd)] = imm;
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_SET64:
                    F[rslot(rd)] = imm;
                    F[rslot(rd) + 1] = ((imm & 0x80000000) != 0) ? 0xFFFFFFFF : 0;
                    break;
                case VmIsa.REG_MOV:
                    F[rslot(rd)] = F[rslot(ra)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_ADD:
                    F[rslot(rd)] = F[rslot(ra)] + F[rslot(rb)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_SUB:
                    F[rslot(rd)] = F[rslot(ra)] - F[rslot(rb)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_MUL:
                    F[rslot(rd)] = F[rslot(ra)] * F[rslot(rb)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_AND:
                    F[rslot(rd)] = F[rslot(ra)] & F[rslot(rb)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_OR:
                    F[rslot(rd)] = F[rslot(ra)] | F[rslot(rb)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_XOR:
                    F[rslot(rd)] = F[rslot(ra)] ^ F[rslot(rb)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_SHL:
                    F[rslot(rd)] = F[rslot(ra)] << (F[rslot(rb)] & 31);
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_SHR:
                    F[rslot(rd)] = F[rslot(ra)] >>> (F[rslot(rb)] & 31);
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_SAR:
                    F[rslot(rd)] = F[rslot(ra)] >> (F[rslot(rb)] & 31);
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_NEG:
                    F[rslot(rd)] = 0 - F[rslot(ra)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_NOT:
                    F[rslot(rd)] = ~F[rslot(ra)];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_FLD:
                    F[rslot(rd)] = F[imm & VmIsa.VM_FRAME_MASK];
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_FLD64:
                    F[rslot(rd)] = F[imm & VmIsa.VM_FRAME_MASK];
                    F[rslot(rd) + 1] = F[(imm + 1) & VmIsa.VM_FRAME_MASK];
                    break;
                case VmIsa.REG_FST:
                    F[imm & VmIsa.VM_FRAME_MASK] = F[rslot(ra)];
                    break;
                case VmIsa.REG_FST64:
                    F[imm & VmIsa.VM_FRAME_MASK] = F[rslot(ra)];
                    F[(imm + 1) & VmIsa.VM_FRAME_MASK] = F[rslot(ra) + 1];
                    break;
                case VmIsa.REG_LD: {
                    // C++: 读 *(u32*)(ra + imm)；Java 无通用地址空间 -> VM_ERR_FAULT
                    final long b64 = ((long) F[rslot(ra)] & 0xFFFFFFFFL)
                            | (((long) F[rslot(ra) + 1] & 0xFFFFFFFFL) << 32);
                    final long addr = b64 + simm32(imm);
                    hrc = VmIsa.VM_ERR_FAULT;
                    break;
                }
                case VmIsa.REG_ST: {
                    // C++: 写 *(u32*)(ra + imm) = rb；Java 无通用地址空间 -> VM_ERR_FAULT
                    final long b64 = ((long) F[rslot(ra)] & 0xFFFFFFFFL)
                            | (((long) F[rslot(ra) + 1] & 0xFFFFFFFFL) << 32);
                    final long addr = b64 + simm32(imm);
                    hrc = VmIsa.VM_ERR_FAULT;
                    break;
                }
                case VmIsa.REG_LEA: {
                    final long b64 = ((long) F[rslot(ra)] & 0xFFFFFFFFL)
                            | (((long) F[rslot(ra) + 1] & 0xFFFFFFFFL) << 32);
                    final long v = b64 + simm32(imm);
                    F[rslot(rd)] = (int) v;
                    F[rslot(rd) + 1] = (int) (v >>> 32);
                    break;
                }
                case VmIsa.REG_SETCC:
                    F[rslot(rd)] = VmIsa.ccEval(imm & 0xFF, F[rslot(ra)], F[rslot(rb)]);
                    F[rslot(rd) + 1] = 0;
                    break;
                case VmIsa.REG_JCC:
                    if (VmIsa.ccEval(rd, F[rslot(ra)], F[rslot(rb)]) != 0) {
                        ctx.ip = imm;
                        jumped = true;
                    }
                    break;
                case VmIsa.REG_JMP:
                    ctx.ip = imm;
                    jumped = true;
                    break;
                case VmIsa.REG_RET:
                    ctx.retval = F[rslot(ra)];
                    isRet = true;
                    break;
                case VmIsa.REG_NATIVE:
                    if (ctx.nativeFn == null) hrc = VmIsa.VM_ERR_FAULT;
                    else hrc = ctx.nativeFn.call(ctx, imm);
                    break;
                default:
                    hrc = VmIsa.VM_ERR_BAD_OPCODE;
                    break;
            }
            reencryptInsn(ctx);
            if (hrc != VmIsa.VM_OK) return hrc;
            if (isRet) {
                out[0] = ctx.retval;
                return VmIsa.VM_OK;
            }
            // 未跳转（含 JCC 未命中）时顺序推进
            if (!jumped) ctx.ip += VmIsa.VM_B_INSN_SIZE;
        }
    }

    // 镜像头校验（vm_exec / vm_exec_mach 共用；按家族校验布局与指令长度）
    private static int vmCheckHeader(byte[] image, int imageSize) {
        if (Integer.compareUnsigned(imageSize, VmIsa.VM_HEADER_SIZE) < 0) return VmIsa.VM_ERR_BAD_MAGIC;
        // 魔数：固定值（见 VmIsa.VM_IMAGE_MAGIC 说明）
        final int magic = Bin.i32(image, VmIsa.IH_MAGIC);
        final int version = Bin.i32(image, VmIsa.IH_VERSION);
        if (magic != VmIsa.VM_IMAGE_MAGIC || version != VmIsa.VM_IMAGE_VERSION) {
            return VmIsa.VM_ERR_BAD_MAGIC;
        }
        final int flags = Bin.i32(image, VmIsa.IH_FLAGS);
        final int family = flags & VmIsa.VM_FAMILY_MASK;
        if (Integer.compareUnsigned(family, VmIsa.VM_FAMILY_REG) > 0) return VmIsa.VM_ERR_BAD_MAGIC;
        final long totalSize = Bin.u32(image, VmIsa.IH_TOTAL_SIZE);
        if (totalSize != 0 && totalSize > (long) imageSize) return VmIsa.VM_ERR_FAULT;
        final int dispatch = Bin.i32(image, VmIsa.IH_DISPATCH);
        if (Integer.compareUnsigned(dispatch, VmIsa.VM_DISPATCH_TYPES) >= 0) return VmIsa.VM_ERR_BAD_OPCODE;
        final int stackWords = Bin.i32(image, VmIsa.IH_STACK_WORDS);
        if (stackWords == 0 || Integer.compareUnsigned(stackWords, VmIsa.VM_STACK_WORDS) > 0) {
            return VmIsa.VM_ERR_FAULT;
        }
        final int ilen = (family == VmIsa.VM_FAMILY_REG) ? VmIsa.VM_B_INSN_SIZE : VmIsa.VM_INSN_SIZE;
        final int boff = (family == VmIsa.VM_FAMILY_REG) ? VmIsa.VM_B_OFF_BYTECODE : VmIsa.VM_OFF_BYTECODE;
        final int bcSize = Bin.i32(image, VmIsa.IH_BC_SIZE);
        if (Integer.remainderUnsigned(bcSize, ilen) != 0) return VmIsa.VM_ERR_FAULT;
        // C++: boff + h->bc_size 先按 uint32 回绕，再提升为 size_t 与 image_size 比较
        final long reach = ((long) (int) (boff + bcSize)) & 0xFFFFFFFFL;
        if (reach > (long) imageSize) return VmIsa.VM_ERR_FAULT;
        final int entry = Bin.i32(image, VmIsa.IH_ENTRY);
        if (Integer.compareUnsigned(entry * ilen, bcSize) >= 0) return VmIsa.VM_ERR_FAULT;
        return VmIsa.VM_OK;
    }

    // ==================== 镜像执行入口 ====================

    /**
     * 机器模型执行：gprs 为 16 × u64 通用寄存器块（rax..r15），入参载入 frame 的
     * 寄存器槽、出参写回（rax 槽 0 即 frame[0]，与 vmExec 的 arg0 约定一致）。
     * nativeFn 非空时可用于 SEM_NATIVE。
     *
     * <p>image 必须可写（就地解密/回加密），返回时内容与进入时一致。</p>
     */
    public static int vmExecMach(byte[] image, int imageSize, long[] gprs, int[] out, VmNativeFn nativeFn) {
        final int rc = vmCheckHeader(image, imageSize);
        if (rc != VmIsa.VM_OK) return rc;

        VmCtx ctx = new VmCtx();
        ctx.image = image;
        ctx.imageSize = imageSize;
        ctx.k8 = VmIsa.vmDeriveKey(headerKey(image));
        final int flags = Bin.i32(image, VmIsa.IH_FLAGS);
        ctx.family = flags & VmIsa.VM_FAMILY_MASK;
        ctx.insnLen = (ctx.family == VmIsa.VM_FAMILY_REG) ? VmIsa.VM_B_INSN_SIZE : VmIsa.VM_INSN_SIZE;
        ctx.bcOff = (ctx.family == VmIsa.VM_FAMILY_REG) ? VmIsa.VM_B_OFF_BYTECODE : VmIsa.VM_OFF_BYTECODE;
        ctx.bcSize = Bin.i32(image, VmIsa.IH_BC_SIZE);
        ctx.stackWords = Bin.i32(image, VmIsa.IH_STACK_WORDS);
        ctx.ip = Bin.i32(image, VmIsa.IH_ENTRY) * ctx.insnLen;
        ctx.insnOff = 0;
        ctx.sp = 0;
        ctx.retval = 0;
        ctx.stepCount = 0;
        ctx.ksCounter = 0xFFFFFFFF;
        ctx.nativeFn = nativeFn;
        ctx.nativeArg = null;
        // stack / frame 由 VmCtx 构造时零初始化（对应 C++ memset）
        // 机器模型：通用寄存器载入 frame 槽（lo = 2g，hi = 2g+1）
        if (gprs != null) {
            for (int g = 0; g < VmIsa.VM_MACH_GPRS; g++) {
                ctx.frame[VmIsa.vmGprSlot(g) + 0] = (int) gprs[g];
                ctx.frame[VmIsa.vmGprSlot(g) + 1] = (int) (gprs[g] >>> 32);
            }
        }

        final int r = (ctx.family == VmIsa.VM_FAMILY_REG) ? vmRunB(image, ctx, out) : vmRun(image, ctx, out);

        if (gprs != null) {
            for (int g = 0; g < VmIsa.VM_MACH_GPRS; g++) {
                gprs[g] = ((long) ctx.frame[VmIsa.vmGprSlot(g) + 0] & 0xFFFFFFFFL)
                        | (((long) ctx.frame[VmIsa.vmGprSlot(g) + 1] & 0xFFFFFFFFL) << 32);
            }
        }
        return r;
    }

    /**
     * 执行镜像。arg0 写入 frame[0]（参数约定），成功返回 VM_OK 且 out[0] 为
     * RET 弹出的值；失败返回错误码，out 不变。
     *
     * <p>image 必须可写（引擎就地解密/回加密指令），返回时内容与进入时一致。</p>
     */
    public static int vmExec(byte[] image, int imageSize, int arg0, int[] out) {
        long[] gprs = new long[VmIsa.VM_MACH_GPRS];
        gprs[VmIsa.GPR_RAX] = arg0 & 0xFFFFFFFFL; // 与历史约定一致：frame[0] = arg0
        return vmExecMach(image, imageSize, gprs, out, null);
    }

    // ---- 测试辅助：单条指令解密 ----
    public static void vmFetchInsn(byte[] image, int imageSize, int ip, int[] key,
                                   int[] opcodeOut, int[] immOut) {
        if (Integer.compareUnsigned(imageSize, VmIsa.VM_HEADER_SIZE) < 0
                || Bin.i32(image, VmIsa.IH_MAGIC) != VmIsa.VM_IMAGE_MAGIC
                || Integer.compareUnsigned(ip + VmIsa.VM_INSN_SIZE, Bin.i32(image, VmIsa.IH_BC_SIZE)) > 0) {
            if (opcodeOut != null) opcodeOut[0] = 0;
            if (immOut != null) immOut[0] = 0;
            return;
        }
        final int[] k8 = VmIsa.vmDeriveKey(key);
        final int base = VmIsa.VM_OFF_BYTECODE + ip;
        final int blk = base >>> 6;
        byte[] ks = new byte[64];
        VmKs.vmKsBlock(k8, blk, ks);
        final int k = base & 63;
        if (opcodeOut != null) opcodeOut[0] = (image[base] ^ ks[k]) & 0xFF;
        if (immOut != null) {
            int v = 0;
            for (int i = 0; i < 4; i++) {
                v |= ((image[base + 1 + i] ^ ks[k + 1 + i]) & 0xFF) << (8 * i);
            }
            immOut[0] = v;
        }
    }

    // ---- 测试辅助：区域解密 ----
    public static void vmDecryptRegion(byte[] image, int imageSize, int offset, byte[] out, int outOff, int len) {
        if (Integer.compareUnsigned(imageSize, VmIsa.VM_HEADER_SIZE) < 0
                || Bin.i32(image, VmIsa.IH_MAGIC) != VmIsa.VM_IMAGE_MAGIC
                || (((long) offset & 0xFFFFFFFFL) + (long) len) > (long) imageSize) {
            for (int i = 0; i < len; i++) {
                out[outOff + i] = 0;
            }
            return;
        }
        final int[] k8 = VmIsa.vmDeriveKey(headerKey(image));
        int pos = offset;
        int done = 0;
        while (done < len) {
            final int blk = pos >>> 6;
            byte[] ks = new byte[64];
            VmKs.vmKsBlock(k8, blk, ks);
            final int inOff = pos & 63;
            final int take = 64 - inOff;
            final int n = (take < len - done) ? take : (len - done);
            for (int i = 0; i < n; i++) {
                out[outOff + done + i] = (byte) (image[offset + done + i] ^ ks[inOff + i]);
            }
            done += n;
            pos = offset + done;
        }
    }
}
