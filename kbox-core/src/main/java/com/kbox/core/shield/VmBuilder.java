package com.kbox.core.shield;

import java.util.List;

/**
 * VmBuilder — VM 镜像构建器（语义流 → 加密镜像），由 packer/vm/vm_builder.cpp 移植。
 *
 * <p>多态机制在生成期的体现（保留原 C++ 头注释）：
 * <ul>
 *   <li>opcode 随机重排：语义号到 opcode 的排列每次构建随机。</li>
 *   <li>handler 多态：variant_map 每语义随机选变体号（引擎按实际变体数取模）。</li>
 *   <li>调度混淆：镜像内选择 DISPATCH_TABLE / DISPATCH_SWITCH。</li>
 *   <li>字节码加密：映射区与指令流按绝对偏移与 keystream 逐字节 XOR。</li>
 * </ul>
 *
 * <h3>随机数（std::mt19937 + std::shuffle）复刻依据</h3>
 * C++ 侧 {@code std::mt19937 rng(opt.seed)} 承担全部随机化：opcode_map 的
 * {@code std::shuffle}、variant_map 的 {@code rng() % variant_cap}、无 imm 语义的
 * 立即数填充、会话密钥 key[4]、reserved[2]（map_iv）。为保持产物逐字节一致，
 * 本类用 {@link Mt19937} 与 {@link #shuffle} 复刻 libstdc++ 的实现：
 * <ul>
 *   <li><b>MT19937</b>：624 字状态、种子展开
 *       {@code mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i}（32 位回绕）、
 *       twist（{@code mt[i] = mt[i+397] ^ (y>>1) ^ (y&1 ? 0x9908B0DF : 0)}）与
 *       temper，与 libstdc++ {@code bits/random.h} 的 {@code _M_gen_rand}/结果
 *       生成逐位一致；{@code min()=0, max()=0xFFFFFFFF}。</li>
 *   <li><b>std::shuffle</b>：libstdc++ {@code bits/stl_algo.h} 的 {@code __shuffle}。
 *       对 mt19937（{@code __urngrange = 2^32-1}）与短序列
 *       （{@code __urange = n} ≤ 36），条件
 *       {@code __urngrange / __urange >= __urange} 成立，走「一次分发产生两个交换
 *       位置」的快路径：先按 {@code __urange % 2 == 0} 做一次 {@code [0,1]} 交换，
 *       随后每轮以 {@code __gen_two_uniform_ints(i+1, i+2)} 生成一对位置并连续交换
 *       两次；不满足该条件时退化为前向 Fisher-Yates 单次交换（见 {@link #shuffle}
 *       末段）。</li>
 *   <li><b>uniform_int_distribution&lt;unsigned long long&gt;</b>
 *       （{@code __ud_type = make_unsigned<ptrdiff_t>}，64 位平台即 unsigned long long）：
 *       libstdc++ {@code bits/uniform_int_dist.h}。{@code __urngrange(=2^32-1) > __urange}
 *       时走「下采样」分支，且因 {@code __urngrange == __UINT32_MAX__} 而使用
 *       Lemire 无除法算法 {@code _S_nd}：
 *       {@code product = (u64)g() * range; low = (u32)product;
 *       if (low < range) { threshold = (u32)(-range % range);
 *       while (low < threshold) 重新取样; } return product >> 32;}。</li>
 * </ul>
 * 复刻依据：本机 MSYS2 GCC 16.1.0 与 Qt MinGW GCC 13.1.0 的
 * {@code include/c++/16.1.0/bits/{random.h,stl_algo.h,uniform_int_dist.h}}、
 * {@code .../13.1.0/include/c++/bits/...} 实际源码；两者对同一批种子/长度
 * 输出逐位一致（移植期参照转储 ref_g16.txt 与 ref_g13.txt 完全相同）。
 */
public final class VmBuilder {

    private VmBuilder() {
    }

    // ================= 公开 API =================

    /** 便捷发射器：vm_gen 指令发射（对应 vm_builder.h 的 insn()）。 */
    public static VmIsa.Insn insn(int sem, int imm) {
        return new VmIsa.Insn(sem, imm);
    }

    /** 语义是否携带立即数（PUSH/LOAD/STORE/跳转类）。 */
    public static boolean semHasImm(int sem) {
        switch (sem) {
            case VmIsa.SEM_PUSH:
            case VmIsa.SEM_LOAD:
            case VmIsa.SEM_STORE:
            case VmIsa.SEM_JMP:
            case VmIsa.SEM_JZ:
            case VmIsa.SEM_JNZ:
            case VmIsa.SEM_MEMRD:
            case VmIsa.SEM_MEMWR:
            case VmIsa.SEM_ADDREL:
            case VmIsa.SEM_NATIVE:
                return true;
            default:
                return false;
        }
    }

    /** 构建选项。 */
    public static final class VmBuildOpt {
        public int dispatch = VmIsa.DISPATCH_TABLE;
        /** 随机种子（可复现）。 */
        public int seed = 0x4B4F5801;
        public int stackWords = VmIsa.VM_STACK_WORDS;
        /**
         * handler 变体上限：variant_map[s] = rng() % variant_cap。
         * 运行期汇编引擎与 C++ 引擎均实现全部等价变体，打包默认置满（VM_VARIANTS）。
         */
        public int variantCap = VmIsa.VM_VARIANTS;
    }

    /** 构建结果。 */
    public static final class VmBuildResult {
        public boolean ok;
        /** 失败原因（VM_ERR_*）。 */
        public int err = VmIsa.VM_OK;
        /** 加密镜像。 */
        public byte[] image;
    }

    // ================= Family A（栈式）=================

    /** 构建：语义流 → 加密镜像。校验语义号/跳转目标/栈深。 */
    public static VmBuildResult vmBuild(List<VmIsa.Insn> program, VmBuildOpt opt) {
        VmBuildResult res = new VmBuildResult();
        final int n = program.size();
        if (n == 0) {
            res.err = VmIsa.VM_ERR_FAULT;
            return res;
        }
        if (opt.stackWords == 0 || Integer.compareUnsigned(opt.stackWords, VmIsa.VM_STACK_WORDS) > 0) {
            res.err = VmIsa.VM_ERR_FAULT;
            return res;
        }

        // ---- 校验 ----
        for (int i = 0; i < n; ++i) {
            if (!semValid(program.get(i).sem)) {
                res.err = VmIsa.VM_ERR_BAD_OPCODE;
                return res;
            }
            if (!checkJumpTarget(program, i)) {
                res.err = VmIsa.VM_ERR_BAD_JUMP;
                return res;
            }
        }
        if (Integer.compareUnsigned(maxStackDepth(program), opt.stackWords) > 0) {
            res.err = VmIsa.VM_ERR_STACK_OVER;
            return res;
        }
        if (opt.variantCap == 0 || Integer.compareUnsigned(opt.variantCap, VmIsa.VM_VARIANTS) > 0) {
            res.err = VmIsa.VM_ERR_FAULT;
            return res;
        }

        Mt19937 rng = new Mt19937(opt.seed);

        // ---- opcode 随机重排（0..SEM_COUNT-1 排列）----
        byte[] opcodeMap = new byte[VmIsa.SEM_COUNT];
        for (int s = 0; s < VmIsa.SEM_COUNT; ++s) {
            opcodeMap[s] = (byte) s;
        }
        shuffle(opcodeMap, VmIsa.SEM_COUNT, rng);

        // ---- variant 随机（引擎按实际变体数取模；variant_cap=1 时强制 v0）----
        byte[] variantMap = new byte[VmIsa.SEM_COUNT];
        for (int s = 0; s < VmIsa.SEM_COUNT; ++s) {
            variantMap[s] = (byte) Integer.remainderUnsigned(rng.next(), opt.variantCap);
        }

        // ---- 汇编指令流 ----
        final int mapOff = VmIsa.VM_OFF_OPCODE_MAP;
        final int bcOff = VmIsa.VM_OFF_BYTECODE;
        final int bcSize = n * VmIsa.VM_INSN_SIZE;
        byte[] bc = new byte[bcSize];
        int p = 0;
        for (int k = 0; k < n; ++k) {
            VmIsa.Insn in = program.get(k);
            final int op = opcodeMap[in.sem] & 0xFF;
            final int imm = semHasImm(in.sem) ? in.imm : rng.next();
            bc[p++] = (byte) op;
            for (int b = 0; b < 4; ++b) {
                bc[p++] = (byte) (imm >>> (8 * b));
            }
        }

        // ---- 组装（映射区 + 字节码明文）----
        final int total = bcOff + bcSize;
        byte[] img = new byte[total];

        Bin.w32(img, VmIsa.IH_VERSION, VmIsa.VM_IMAGE_VERSION);
        Bin.w32(img, VmIsa.IH_FLAGS, 0);
        Bin.w32(img, VmIsa.IH_DISPATCH, opt.dispatch);
        Bin.w32(img, VmIsa.IH_TOTAL_SIZE, total);
        Bin.w32(img, VmIsa.IH_BC_SIZE, bcSize);
        Bin.w32(img, VmIsa.IH_ENTRY, 0);
        Bin.w32(img, VmIsa.IH_STACK_WORDS, opt.stackWords);
        // 会话密钥（构建期随机）
        int[] key = new int[4];
        for (int i = 0; i < 4; ++i) {
            key[i] = rng.next();
            Bin.w32(img, VmIsa.IH_KEY + 4 * i, key[i]);
        }
        // 魔数：与运行期汇编引擎 / meta_inner 内层解释器一致的固定值
        Bin.w32(img, VmIsa.IH_MAGIC, VmIsa.VM_IMAGE_MAGIC);
        final int mapIv = rng.next();
        Bin.w32(img, VmIsa.IH_RESERVED + 8, mapIv);

        System.arraycopy(opcodeMap, 0, img, mapOff, VmIsa.SEM_COUNT);
        System.arraycopy(variantMap, 0, img, mapOff + VmIsa.SEM_COUNT, VmIsa.SEM_COUNT);
        System.arraycopy(bc, 0, img, bcOff, bcSize);

        // ---- 加密（映射区 + 字节码，绝对偏移定位 keystream）----
        // 注：运行期汇编引擎（stub/vm_engine_*.S，仅含单块 X_KSBLK 缓存）与 Meta 化的
        // 内层解释器（packer/vm/meta_inner.cpp 的 L_ksbyte）都只实现单 keystream；
        // 上游快照仅在 packer 侧引入了「方案B：明文 ^ ks1 ^ ks2」加扰。本移植以运行期
        // 引擎为准，映射区只叠加 ks1，否则运行期反查表解密错位会令 VM 以 BAD_OPCODE 停机。
        int[] k8 = VmIsa.vmDeriveKey(key);
        encryptRegion(img, mapOff, total, k8);

        res.ok = true;
        res.err = VmIsa.VM_OK;
        res.image = img;
        return res;
    }

    // ================= Family B（寄存器式）镜像构建 =================

    /**
     * 构建 Family B（寄存器式）镜像：BInsn 流 → 加密镜像（header.flags = REG）。
     * 密文布局：[header][opcode_map(REG_COUNT)][bytecode(n × 8)]，绝对偏移定位 keystream。
     */
    public static VmBuildResult vmBuildB(List<VmIsa.BInsn> program, VmBuildOpt opt) {
        VmBuildResult res = new VmBuildResult();
        final int n = program.size();
        if (n == 0) {
            res.err = VmIsa.VM_ERR_FAULT;
            return res;
        }
        if (opt.stackWords == 0 || Integer.compareUnsigned(opt.stackWords, VmIsa.VM_STACK_WORDS) > 0) {
            res.err = VmIsa.VM_ERR_FAULT;
            return res;
        }

        // ---- 校验 ----
        final int bcTotal = n * VmIsa.VM_B_INSN_SIZE;
        for (int i = 0; i < n; ++i) {
            VmIsa.BInsn in = program.get(i);
            if (Integer.compareUnsigned(in.op, VmIsa.REG_COUNT) >= 0) {
                res.err = VmIsa.VM_ERR_BAD_OPCODE;
                return res;
            }
            if (in.op == VmIsa.REG_JMP || in.op == VmIsa.REG_JCC) {
                if (Integer.compareUnsigned(in.imm, bcTotal) >= 0
                        || (in.imm % VmIsa.VM_B_INSN_SIZE) != 0) {
                    res.err = VmIsa.VM_ERR_BAD_JUMP;
                    return res;
                }
            }
        }

        Mt19937 rng = new Mt19937(opt.seed);

        // ---- opcode 随机重排（0..REG_COUNT-1 排列）----
        byte[] opcodeMap = new byte[VmIsa.REG_COUNT];
        for (int s = 0; s < VmIsa.REG_COUNT; ++s) {
            opcodeMap[s] = (byte) s;
        }
        shuffle(opcodeMap, VmIsa.REG_COUNT, rng);

        // ---- 汇编指令流（8 字节定长）----
        byte[] bc = new byte[bcTotal];
        int p = 0;
        for (int k = 0; k < n; ++k) {
            VmIsa.BInsn in = program.get(k);
            bc[p++] = opcodeMap[in.op];
            bc[p++] = (byte) in.rd;
            bc[p++] = (byte) in.ra;
            bc[p++] = (byte) in.rb;
            for (int b = 0; b < 4; ++b) {
                bc[p++] = (byte) (in.imm >>> (8 * b));
            }
        }

        final int bcOff = VmIsa.VM_B_OFF_BYTECODE;
        final int bcSize = bc.length;
        final int total = bcOff + bcSize;
        byte[] img = new byte[total];

        Bin.w32(img, VmIsa.IH_VERSION, VmIsa.VM_IMAGE_VERSION);
        Bin.w32(img, VmIsa.IH_FLAGS, VmIsa.VM_FAMILY_REG);        // 家族标记（低 8 位）
        Bin.w32(img, VmIsa.IH_DISPATCH, opt.dispatch);
        Bin.w32(img, VmIsa.IH_TOTAL_SIZE, total);
        Bin.w32(img, VmIsa.IH_BC_SIZE, bcSize);
        Bin.w32(img, VmIsa.IH_ENTRY, 0);
        Bin.w32(img, VmIsa.IH_STACK_WORDS, opt.stackWords);
        int[] key = new int[4];
        for (int i = 0; i < 4; ++i) {
            key[i] = rng.next();
            Bin.w32(img, VmIsa.IH_KEY + 4 * i, key[i]);
        }
        // 魔数统一使用固定常量：运行期汇编引擎按 IH_IV_MAGIC 固定值校验
        Bin.w32(img, VmIsa.IH_MAGIC, VmIsa.VM_IMAGE_MAGIC);
        final int mapIv = rng.next();
        Bin.w32(img, VmIsa.IH_RESERVED + 8, mapIv);

        System.arraycopy(opcodeMap, 0, img, VmIsa.VM_B_OFF_OPCODE_MAP, VmIsa.REG_COUNT);
        System.arraycopy(bc, 0, img, bcOff, bcSize);

        // 同 A 族：只叠加 ks1（运行期引擎未实现 ks2）
        int[] k8 = VmIsa.vmDeriveKey(key);
        encryptRegion(img, VmIsa.VM_B_OFF_OPCODE_MAP, total, k8);

        res.ok = true;
        res.err = VmIsa.VM_OK;
        res.image = img;
        return res;
    }

    // ================= 内部工具（对应 vm_builder.cpp 的匿名命名空间）=================

    /** 检查语义号合法性。 */
    private static boolean semValid(int sem) {
        return Integer.compareUnsigned(sem, VmIsa.SEM_COUNT) < 0;
    }

    /** 检查跳转目标（imm 为相对下一条指令数的有符号偏移）。 */
    private static boolean checkJumpTarget(List<VmIsa.Insn> prog, int i) {
        final int sem = prog.get(i).sem;
        if (sem != VmIsa.SEM_JMP && sem != VmIsa.SEM_JZ && sem != VmIsa.SEM_JNZ) {
            return true;
        }
        final long rel = prog.get(i).imm;
        final long target = (long) (i + 1) + rel;
        return target >= 0 && target < (long) prog.size();
    }

    /** 线性栈模拟：统计程序任意点（顺序路径）最大栈深。 */
    private static int maxStackDepth(List<VmIsa.Insn> prog) {
        int sp = 0;
        int maxsp = 0;
        final int n = prog.size();
        for (int k = 0; k < n; ++k) {
            switch (prog.get(k).sem) {
                case VmIsa.SEM_PUSH:
                case VmIsa.SEM_LOAD:
                case VmIsa.SEM_DUP:
                    ++sp;
                    break;
                case VmIsa.SEM_POP:
                case VmIsa.SEM_RET:
                    --sp;
                    break;
                case VmIsa.SEM_STORE:
                case VmIsa.SEM_ADD:
                case VmIsa.SEM_SUB:
                case VmIsa.SEM_MUL:
                case VmIsa.SEM_AND:
                case VmIsa.SEM_OR:
                case VmIsa.SEM_XOR:
                case VmIsa.SEM_SHL:
                case VmIsa.SEM_SHR:
                case VmIsa.SEM_SAR:
                    --sp;
                    break;
                case VmIsa.SEM_SWAP:
                    break; // 深度不变
                case VmIsa.SEM_NEG:
                case VmIsa.SEM_NOT:
                case VmIsa.SEM_JMP:
                case VmIsa.SEM_JZ:
                case VmIsa.SEM_JNZ:
                    break;
                // Batch 5：64 位值占 2 个字（lo, hi）
                case VmIsa.SEM_MEMRD:   // -2 +1
                    --sp;
                    break;
                case VmIsa.SEM_MEMWR:   // -1 -2
                    sp -= 3;
                    break;
                case VmIsa.SEM_ADDREL:  // -2 +2
                    break;
                case VmIsa.SEM_NATIVE:
                    break;
                case VmIsa.SEM_EQ:
                case VmIsa.SEM_NE:
                case VmIsa.SEM_ULT:
                case VmIsa.SEM_UGE:
                case VmIsa.SEM_ULE:
                case VmIsa.SEM_UGT:
                case VmIsa.SEM_SLT:
                case VmIsa.SEM_SGE:
                case VmIsa.SEM_SLE:
                case VmIsa.SEM_SGT:     // -2 +1
                    --sp;
                    break;
                default:
                    break;
            }
            if (sp > maxsp) {
                maxsp = sp;
            }
        }
        return maxsp < 0 ? 0 : maxsp;
    }

    /**
     * 按绝对偏移逐块 XOR keystream 加密 [from, total) 区域。
     * （XOR 自逆，同一函数亦用于解密；VmMeta 构建同此逻辑。）
     */
    static void encryptRegion(byte[] img, int from, int total, int[] k8) {
        int pos = from;
        while (pos < total) {
            final int blk = pos >>> 6;
            byte[] ks = new byte[64];
            VmKs.vmKsBlock(k8, blk, ks, 0);
            final int inOff = pos & 63;
            final int take = 64 - inOff;
            final int n = (take < total - pos) ? take : (total - pos);
            for (int i = 0; i < n; ++i) {
                img[pos + i] ^= ks[inOff + i];
            }
            pos += n;
        }
    }

    // ================= MT19937 / std::shuffle 复刻 =================

    /**
     * std::mt19937 复刻（libstdc++ bits/random.h）。
     *
     * <p>包级可见：{@link VmMeta} 的 Meta 镜像构建使用同一实现（C++ 侧同为
     * {@code std::mt19937 rng(seed)} + {@code std::shuffle}），故不重复实现。</p>
     */
    static final class Mt19937 {

        private static final int N = 624;
        private static final int M = 397;
        private static final int MATRIX_A = 0x9908B0DF;
        private static final int UPPER_MASK = 0x80000000;
        private static final int LOWER_MASK = 0x7FFFFFFF;

        private final int[] mt = new int[N];
        private int idx = N;

        Mt19937(int seed) {
            mt[0] = seed;
            for (int i = 1; i < N; ++i) {
                mt[i] = 1812433253 * (mt[i - 1] ^ (mt[i - 1] >>> 30)) + i;
            }
        }

        /** 生成一个 32 位无符号随机数（result_type = uint32_t）。 */
        int next() {
            if (idx >= N) {
                twist();
            }
            int y = mt[idx++];
            y ^= (y >>> 11);
            y ^= (y << 7) & 0x9D2C5680;
            y ^= (y << 15) & 0xEFC60000;
            y ^= (y >>> 18);
            return y;
        }

        private void twist() {
            for (int i = 0; i < N; ++i) {
                final int y = (mt[i] & UPPER_MASK) | (mt[(i + 1) % N] & LOWER_MASK);
                mt[i] = mt[(i + M) % N] ^ (y >>> 1) ^ ((y & 1) != 0 ? MATRIX_A : 0);
            }
            idx = 0;
        }
    }

    /**
     * libstdc++ {@code uniform_int_distribution<unsigned long long>} 的下采样内部例程
     * {@code _S_nd<unsigned long long, unsigned int>}（Lemire 无除法算法）。
     *
     * @param range 目标区间上界（含），即 C++ 的 {@code __uerange = __urange + 1}
     * @return [0, range) 上的均匀随机数（无符号 32 位，Java int 承载）
     */
    private static int sNd32(Mt19937 g, int range) {
        long product = (g.next() & 0xFFFFFFFFL) * (range & 0xFFFFFFFFL);
        int low = (int) product;
        if (Integer.compareUnsigned(low, range) < 0) {
            // threshold = (uint32)(-range % range)；-range 取 32 位回绕补码
            final int threshold = Integer.remainderUnsigned(-range, range);
            while (Integer.compareUnsigned(low, threshold) < 0) {
                product = (g.next() & 0xFFFFFFFFL) * (range & 0xFFFFFFFFL);
                low = (int) product;
            }
        }
        return (int) (product >>> 32);
    }

    /**
     * libstdc++ {@code uniform_int_distribution<unsigned long long>(a, b)} 的
     * {@code operator()(mt19937&)} 复刻（bits/uniform_int_dist.h）。
     *
     * <p>mt19937 的 {@code __urngrange = 2^32-1}：区间宽度 &lt; 2^32-1 时走下采样
     * （{@code __urngrange == __UINT32_MAX__} → Lemire 例程）；宽度更大时走升采样
     * 分支（本构建器的区间均远小于 2^32-1，升采样分支仅为忠实复刻保留）。</p>
     *
     * @return 区间 [a, b] 上的均匀随机数（无符号 64 位）
     */
    private static long uniformU64(Mt19937 g, long a, long b) {
        final long urngrange = 0xFFFFFFFFL;      // mt19937::max() - mt19937::min()
        final long urange = b - a;               // __urange
        if (urngrange > urange) {
            // downscaling：__uerange = __urange + 1
            final long uerange = urange + 1;
            if (urngrange == 0xFFFFFFFFL) {
                // __urngrange == __UINT32_MAX__ → _S_nd<__UINT64_TYPE__>（32 位下采样）
                final int r32 = sNd32(g, (int) uerange);
                return (r32 & 0xFFFFFFFFL) + a;
            }
            // fallback（两次除法）；本构建器不达此分支
            final long scaling = urngrange / uerange;
            final long past = uerange * scaling;
            long ret;
            do {
                ret = g.next() & 0xFFFFFFFFL;
            } while (ret >= past);
            return ret / scaling + a;
        } else if (urngrange < urange) {
            // upscaling：高位递归取样 (urngrange+1)*high，低位一次取样
            final long uerngrange = urngrange + 1;
            long tmp;
            long ret;
            do {
                tmp = uerngrange * uniformU64(g, 0, urange / uerngrange);
                ret = tmp + (g.next() & 0xFFFFFFFFL);
            } while (ret > urange || ret < tmp);
            return ret + a;
        }
        return (g.next() & 0xFFFFFFFFL) + a;
    }

    /**
     * libstdc++ {@code std::shuffle} 复刻（bits/stl_algo.h 前向版本 {@code __shuffle}）。
     *
     * <p>{@code _DistanceType = ptrdiff_t}（64 位平台），
     * {@code __ud_type = unsigned long long}，{@code __uc_type = unsigned long long}。</p>
     */
    static void shuffle(byte[] a, int len, Mt19937 g) {
        if (len == 0) {
            return;
        }
        final long urngrange = 0xFFFFFFFFL;
        final long urange = len;
        if (urngrange / urange >= urange) {
            // 快路径：一次分发产生两个交换位置（__gen_two_uniform_ints）
            int i = 1;
            // 偶数长度时交换次数为奇数，先单独做一次 [0,1] 的交换
            if ((urange % 2) == 0) {
                int j = (int) uniformU64(g, 0, 1);
                swap(a, i, j);
                ++i;
            }
            // 此后剩余元素个数为偶数，两两成对处理
            while (i != len) {
                final long swapRange = (long) i + 1;
                // __gen_two_uniform_ints(swapRange, swapRange + 1)：
                // x = uniform{0, swapRange * (swapRange + 1) - 1}
                // pair(x / (swapRange + 1), x % (swapRange + 1))
                final long x = uniformU64(g, 0, swapRange * (swapRange + 1) - 1);
                final int j0 = (int) (x / (swapRange + 1));
                final int j1 = (int) (x % (swapRange + 1));
                swap(a, i, j0);
                ++i;
                swap(a, i, j1);
                ++i;
            }
            return;
        }
        // 通用分支：前向 Fisher-Yates（每次一个交换位置）
        for (int i = 1; i != len; ++i) {
            final int j = (int) uniformU64(g, 0, i);
            swap(a, i, j);
        }
    }

    private static void swap(byte[] a, int i, int j) {
        final byte t = a[i];
        a[i] = a[j];
        a[j] = t;
    }
}
