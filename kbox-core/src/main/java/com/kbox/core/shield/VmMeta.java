package com.kbox.core.shield;

import java.util.List;

/**
 * VmMeta — 外层 Meta VM（嵌套虚拟化）构建器与解释器，由 packer/vm/vm_meta.cpp 移植。
 *
 * <p>镜像布局：[MImageHeader 64B][opcode_map(M_COUNT)][handler_tab(64×u32)][bytecode]。
 * 后三区整体加密（绝对偏移定位 keystream，密钥 = m_derive_key(header.key)）。
 * 定长 8 字节指令；取指<b>就地</b>解密当前指令，执行后立即用同一 keystream
 * 回写密文（抗内存 dump，幂等：返回时镜像逐字节不变）。</p>
 *
 * <p>随机数：C++ 用 {@code std::mt19937 rng(opt.seed)} + {@code std::shuffle}
 * 重排 opcode_map 并生成 key[4]；Java 侧复用 {@link VmBuilder} 内复刻的
 * MT19937 与 libstdc++ std::shuffle（复刻依据见 VmBuilder 类注释）。</p>
 *
 * <p>{@code vm_build_inner_meta} / {@code vm_exec_inner_nested} 由 MetaInner.java
 * 负责，本类不实现。</p>
 *
 * <p>魔数说明：vm_meta.cpp 写入/校验的是 {@code M_IMAGE_MAGIC}（该符号在当前
 * vm_isa_m.h 中已不存在，属"方案B 派生魔数"重构未落地的残留）。其取值由两侧
 * 外部契约确认：stub/vm_engine_x64.S / vm_engine_x86.S 的 {@code MX_MAGIC}
 * 与 scripts/adversarial/common.py 的 {@code M_IMAGE_MAGIC} 均为 0x4D56424D，
 * 故 Java 侧取 {@link VmIsaM#MX_MAGIC}（= 0x4D56424D），以保证产物可被随包
 * 的汇编 Meta 引擎接受。</p>
 */
public final class VmMeta {

    private VmMeta() {
    }

    /** Meta 步数上限（防失控）。 */
    public static final int M_MAX_STEPS = 8 * 1024 * 1024;

    /** 镜像魔数（见类注释；等于 stub 侧 MX_MAGIC）。 */
    private static final int M_IMAGE_MAGIC = VmIsaM.MX_MAGIC;

    /** Meta 字节码内偏移表条目数（= VmIsaM.M_HANTAB_ENTRIES）。 */
    private static final int M_HANTAB_ENTRIES = VmIsaM.M_HANTAB_ENTRIES;

    // ================= 构建 =================

    /** 构建选项。 */
    public static final class MetaBuildOpt {
        /** 随机种子（"META"）。 */
        public int seed = 0x4D455441;
        /** 起始指令下标。 */
        public int entry = 0;
    }

    /** 构建结果。 */
    public static final class MetaBuildResult {
        public boolean ok;
        public int err = VmIsaM.M_OK;
        public byte[] image;
    }

    /**
     * 构建 Meta 镜像。program 为 Meta 指令流；handlerTab 为 N 个"字节码内绝对
     * 偏移"（供 M_CALLR 分派；不足处补 0）。校验 opcode/跳转/调用目标。
     */
    public static MetaBuildResult vmBuildM(List<VmIsaM.MInsn> program, int[] handlerTab,
                                          MetaBuildOpt opt) {
        MetaBuildResult res = new MetaBuildResult();
        final int n = program.size();
        if (n == 0) {
            res.err = VmIsaM.M_ERR_FAULT;
            return res;
        }
        if (Integer.compareUnsigned(opt.entry, n) >= 0) {
            res.err = VmIsaM.M_ERR_FAULT;
            return res;
        }

        final int bcTotal = n * VmIsaM.M_INSN_SIZE;

        // ---- 校验 ----
        for (int i = 0; i < n; ++i) {
            VmIsaM.MInsn in = program.get(i);
            if (Integer.compareUnsigned(in.op, VmIsaM.M_COUNT) >= 0) {
                res.err = VmIsaM.M_ERR_BAD_OPCODE;
                return res;
            }
            switch (in.op) {
                case VmIsaM.M_JMP:
                case VmIsaM.M_JCC:
                case VmIsaM.M_CALL:
                    if (Integer.compareUnsigned(in.imm, bcTotal) >= 0
                            || (in.imm % VmIsaM.M_INSN_SIZE) != 0) {
                        res.err = VmIsaM.M_ERR_FAULT;
                        return res;
                    }
                    break;
                default:
                    break;
            }
            // 寄存器字段约束：M_JCC 的 dst 承载条件码，其余语义的 dst 为寄存器
            if (Integer.compareUnsigned(in.src, VmIsaM.M_REGS) >= 0
                    || Integer.compareUnsigned(in.aux, VmIsaM.M_REGS) >= 0) {
                res.err = VmIsaM.M_ERR_BAD_OPCODE;
                return res;
            }
            if (in.op == VmIsaM.M_JCC) {
                if (Integer.compareUnsigned(in.dst, VmIsaM.M_CC_COUNT) >= 0) {
                    res.err = VmIsaM.M_ERR_BAD_OPCODE;
                    return res;
                }
            } else if (Integer.compareUnsigned(in.dst, VmIsaM.M_REGS) >= 0) {
                res.err = VmIsaM.M_ERR_BAD_OPCODE;
                return res;
            }
            if (in.op == VmIsaM.M_SETCC && Integer.compareUnsigned(in.imm & 0xFF, VmIsaM.M_CC_COUNT) >= 0) {
                res.err = VmIsaM.M_ERR_BAD_OPCODE;
                return res;
            }
        }
        final int tabLen = (handlerTab == null) ? 0 : handlerTab.length;
        for (int i = 0; i < tabLen; ++i) {
            final int t = handlerTab[i];
            if (t == 0) {
                continue;
            }
            if (Integer.compareUnsigned(t, bcTotal) >= 0 || (t % VmIsaM.M_INSN_SIZE) != 0) {
                res.err = VmIsaM.M_ERR_FAULT;
                return res;
            }
        }

        VmBuilder.Mt19937 rng = new VmBuilder.Mt19937(opt.seed);

        // ---- opcode 随机重排（0..M_COUNT-1 排列）----
        byte[] opcodeMap = new byte[VmIsaM.M_COUNT];
        for (int s = 0; s < VmIsaM.M_COUNT; ++s) {
            opcodeMap[s] = (byte) s;
        }
        VmBuilder.shuffle(opcodeMap, VmIsaM.M_COUNT, rng);

        // ---- 汇编字节码 ----
        byte[] bc = new byte[bcTotal];
        int p = 0;
        for (int k = 0; k < n; ++k) {
            VmIsaM.MInsn in = program.get(k);
            bc[p++] = opcodeMap[in.op];
            bc[p++] = (byte) in.dst;
            bc[p++] = (byte) in.src;
            bc[p++] = (byte) in.aux;
            for (int b = 0; b < 4; ++b) {
                bc[p++] = (byte) (in.imm >>> (8 * b));
            }
        }

        final int bcSize = bc.length;
        final int total = VmIsaM.M_OFF_BYTECODE + bcSize;
        byte[] img = new byte[total];

        Bin.w32(img, VmIsaM.MH_MAGIC, M_IMAGE_MAGIC);
        Bin.w32(img, VmIsaM.MH_VERSION, VmIsaM.M_IMAGE_VERSION);
        Bin.w32(img, VmIsaM.MH_FLAGS, 0);
        Bin.w32(img, VmIsaM.MH_TOTAL_SIZE, total);
        Bin.w32(img, VmIsaM.MH_BC_SIZE, bcSize);
        Bin.w32(img, VmIsaM.MH_ENTRY, opt.entry);
        int[] key = new int[4];
        for (int i = 0; i < 4; ++i) {
            key[i] = rng.next();
            Bin.w32(img, VmIsaM.MH_KEY + 4 * i, key[i]);
        }

        System.arraycopy(opcodeMap, 0, img, VmIsaM.M_OFF_OPCODE_MAP, VmIsaM.M_COUNT);
        for (int i = 0; i < M_HANTAB_ENTRIES; ++i) {
            final int v = (i < tabLen) ? handlerTab[i] : 0;
            Bin.w32(img, VmIsaM.M_OFF_HANDLER_TAB + i * 4, v);
        }
        System.arraycopy(bc, 0, img, VmIsaM.M_OFF_BYTECODE, bcSize);

        int[] k8 = VmIsaM.mDeriveKey(key);
        VmBuilder.encryptRegion(img, VmIsaM.M_OFF_OPCODE_MAP, total, k8);

        res.ok = true;
        res.err = VmIsaM.M_OK;
        res.image = img;
        return res;
    }

    // ================= 执行上下文 =================

    /** 执行上下文（自由态，调用方分配；对应 C++ MetaCtx）。 */
    public static final class MetaCtx {
        public byte[] image;
        public int imageSize;
        /** 派生密钥。 */
        public int[] k8 = new int[8];
        public int bcOff;
        public int bcSize;
        /** 相对 bc 的字节偏移。 */
        public int ip;
        /** 当前指令在镜像内绝对偏移（回加密用）。 */
        public int insnOff;
        public int stepCount;
        public int retval;
        /** Meta 通用寄存器。 */
        public long[] m = new long[VmIsaM.M_REGS];
        public long[] callstack = new long[64];
        public int csp;
        public MHostFn hostFn;
        public Object hostArg;
        /** opcode -> 内层语义号（0xFF = 无效）。 */
        public int[] rev = new int[256];
        public int[] handlerTab = new int[M_HANTAB_ENTRIES];
        /** Meta 自身 keystream 块缓存（就地解密其指令流）。 */
        public byte[] ksBlock = new byte[64];
        public int ksCounter = 0xFFFFFFFF;
        public byte[] ks8 = new byte[VmIsaM.M_INSN_SIZE];
    }

    /**
     * 宿主逃逸回调：prim = M_HOST_*，经 m[11..15] 收参、m[12] 回结果；
     * 返回非 0 表示失败（解释器以该码停机）。
     */
    public interface MHostFn {
        int call(Object hostArg, int prim, long[] m);
    }

    // ================= 执行 =================

    /**
     * 执行 Meta 镜像。image 必须可写（就地解密/回加密），返回时逐字节不变。
     * 成功返回 M_OK 且 out[0] 为 M_HALT 的 retval。
     */
    public static int vmMetaExec(byte[] image, int imageSize, int entry, long[] m,
                                 MHostFn hostFn, Object hostArg, int[] out) {
        if (imageSize < VmIsaM.M_HEADER_SIZE) {
            return VmIsaM.M_ERR_BAD_MAGIC;
        }
        if (Bin.i32(image, VmIsaM.MH_MAGIC) != M_IMAGE_MAGIC
                || Bin.i32(image, VmIsaM.MH_VERSION) != VmIsaM.M_IMAGE_VERSION) {
            return VmIsaM.M_ERR_BAD_MAGIC;
        }
        final int totalSize = Bin.i32(image, VmIsaM.MH_TOTAL_SIZE);
        if (totalSize != 0 && Integer.compareUnsigned(totalSize, imageSize) > 0) {
            return VmIsaM.M_ERR_FAULT;
        }
        final int bcSize = Bin.i32(image, VmIsaM.MH_BC_SIZE);
        if ((bcSize % VmIsaM.M_INSN_SIZE) != 0) {
            return VmIsaM.M_ERR_FAULT;
        }
        if ((long) VmIsaM.M_OFF_BYTECODE + (bcSize & 0xFFFFFFFFL) > (long) imageSize) {
            return VmIsaM.M_ERR_FAULT;
        }
        if (Integer.compareUnsigned(entry * VmIsaM.M_INSN_SIZE, bcSize) >= 0) {
            return VmIsaM.M_ERR_FAULT;
        }

        MetaCtx c = new MetaCtx();
        c.image = image;
        c.imageSize = imageSize;
        int[] hkey = new int[4];
        for (int i = 0; i < 4; ++i) {
            hkey[i] = Bin.i32(image, VmIsaM.MH_KEY + i * 4);
        }
        c.k8 = VmIsaM.mDeriveKey(hkey);
        c.bcOff = VmIsaM.M_OFF_BYTECODE;
        c.bcSize = bcSize;
        c.ip = entry * VmIsaM.M_INSN_SIZE;
        c.stepCount = 0;
        c.csp = 0;
        c.hostFn = hostFn;
        c.hostArg = hostArg;
        System.arraycopy(m, 0, c.m, 0, VmIsaM.M_REGS);

        for (int i = 0; i < 256; ++i) {
            c.rev[i] = 0xFF;
        }
        for (int s = 0; s < VmIsaM.M_COUNT; ++s) {
            final int op = (image[VmIsaM.M_OFF_OPCODE_MAP + s] & 0xFF)
                    ^ ksByte(c, VmIsaM.M_OFF_OPCODE_MAP + s);
            if (op >= VmIsaM.M_COUNT) {
                continue;
            }
            if (c.rev[op] != 0xFF) {
                return VmIsaM.M_ERR_BAD_OPCODE; // 非排列
            }
            c.rev[op] = s;
        }
        for (int i = 0; i < M_HANTAB_ENTRIES; ++i) {
            final int pos = VmIsaM.M_OFF_HANDLER_TAB + i * 4;
            int v = (image[pos] & 0xFF) ^ ksByte(c, pos);
            v |= ((image[pos + 1] & 0xFF) ^ ksByte(c, pos + 1)) << 8;
            v |= ((image[pos + 2] & 0xFF) ^ ksByte(c, pos + 2)) << 16;
            v |= ((image[pos + 3] & 0xFF) ^ ksByte(c, pos + 3)) << 24;
            c.handlerTab[i] = v;
        }
        // 供内层解释器程序经 m5 访问 handler 偏移表。
        // Java 侧无指针：handler 表是 MetaCtx 内的 int[]，不在扁平地址空间内，
        // 故 m5 置 0（C++ 置表地址；两侧内层 Meta 程序均未读取 m5）。
        c.m[VmIsaM.M_HT_REG] = 0;

        for (;;) {
            if (++c.stepCount > M_MAX_STEPS) {
                return VmIsaM.M_ERR_TOO_DEEP;
            }
            if (Integer.compareUnsigned(c.ip, c.bcSize) > 0
                    || Integer.compareUnsigned(c.ip + VmIsaM.M_INSN_SIZE, c.bcSize) > 0) {
                return VmIsaM.M_ERR_FAULT;
            }
            final int base = c.bcOff + c.ip;
            c.insnOff = base;
            for (int i = 0; i < VmIsaM.M_INSN_SIZE; ++i) {
                final int k = ksByte(c, base + i);
                c.ks8[i] = (byte) k;
                image[base + i] = (byte) (image[base + i] ^ k);
            }
            final int opc = image[base] & 0xFF;
            final int dst = image[base + 1] & 0xFF;
            final int src = image[base + 2] & 0xFF;
            final int aux = image[base + 3] & 0xFF;
            int imm = 0;
            for (int i = 0; i < 4; ++i) {
                imm |= (image[base + 4 + i] & 0xFF) << (8 * i);
            }

            final int sem = c.rev[opc];
            if (sem >= VmIsaM.M_COUNT) {
                for (int i = 0; i < VmIsaM.M_INSN_SIZE; ++i) {
                    image[c.insnOff + i] = (byte) (image[c.insnOff + i] ^ c.ks8[i]);
                }
                return VmIsaM.M_ERR_BAD_OPCODE;
            }

            boolean jumped = false;
            boolean halted = false;
            int haltStatus = VmIsaM.M_OK;
            int hrc = VmIsaM.M_OK;
            long[] R = c.m;
            switch (sem) {
                case VmIsaM.M_NOP:
                    break;
                case VmIsaM.M_MOVI:
                    R[dst] = imm & 0xFFFFFFFFL;
                    break;
                case VmIsaM.M_SET64:
                    R[dst] = imm;
                    break;
                case VmIsaM.M_MOV:
                    R[dst] = R[src];
                    break;
                case VmIsaM.M_ADD:
                    R[dst] = R[src] + R[aux];
                    break;
                case VmIsaM.M_SUB:
                    R[dst] = R[src] - R[aux];
                    break;
                case VmIsaM.M_MUL:
                    R[dst] = R[src] * R[aux];
                    break;
                case VmIsaM.M_AND:
                    R[dst] = R[src] & R[aux];
                    break;
                case VmIsaM.M_OR:
                    R[dst] = R[src] | R[aux];
                    break;
                case VmIsaM.M_XOR:
                    R[dst] = R[src] ^ R[aux];
                    break;
                case VmIsaM.M_SHL:
                    R[dst] = R[src] << (int) (R[aux] & 63L);
                    break;
                case VmIsaM.M_SHR:
                    R[dst] = R[src] >>> (int) (R[aux] & 63L);
                    break;
                case VmIsaM.M_SAR:
                    R[dst] = R[src] >> (int) (R[aux] & 63L);
                    break;
                case VmIsaM.M_NEG:
                    R[dst] = 0L - R[src];
                    break;
                case VmIsaM.M_NOT:
                    R[dst] = ~R[src];
                    break;
                case VmIsaM.M_DIV:
                    if (R[aux] == 0) {
                        hrc = VmIsaM.M_ERR_FAULT;
                        break;
                    }
                    R[dst] = Long.divideUnsigned(R[src], R[aux]);
                    break;
                case VmIsaM.M_MOD:
                    if (R[aux] == 0) {
                        hrc = VmIsaM.M_ERR_FAULT;
                        break;
                    }
                    R[dst] = Long.remainderUnsigned(R[src], R[aux]);
                    break;
                case VmIsaM.M_LD:
                    R[dst] = Bin.i64(image, addrOf(R[src], imm));
                    break;
                case VmIsaM.M_LD32:
                    R[dst] = Bin.i32(image, addrOf(R[src], imm)) & 0xFFFFFFFFL;
                    break;
                case VmIsaM.M_LD8:
                    R[dst] = image[addrOf(R[src], imm)] & 0xFF;
                    break;
                case VmIsaM.M_ST:
                    Bin.w64(image, addrOf(R[dst], imm), R[src]);
                    break;
                case VmIsaM.M_ST32:
                    Bin.w32(image, addrOf(R[dst], imm), (int) R[src]);
                    break;
                case VmIsaM.M_ST8:
                    image[addrOf(R[dst], imm)] = (byte) R[src];
                    break;
                case VmIsaM.M_LEA:
                    R[dst] = R[src] + imm;
                    break;
                case VmIsaM.M_SETCC:
                    R[dst] = mCcEval(imm & 0xFF, R[src], R[aux]);
                    break;
                case VmIsaM.M_JMP:
                    c.ip = imm;
                    jumped = true;
                    break;
                case VmIsaM.M_JCC:
                    if (mCcEval(dst, R[src], R[aux]) != 0) {
                        c.ip = imm;
                        jumped = true;
                    }
                    break;
                case VmIsaM.M_CALL:
                    if (c.csp >= 64) {
                        hrc = VmIsaM.M_ERR_TOO_DEEP;
                        break;
                    }
                    c.callstack[c.csp++] = (long) (c.ip + VmIsaM.M_INSN_SIZE);
                    c.ip = imm;
                    jumped = true;
                    break;
                case VmIsaM.M_CALLR: {
                    final int t = (int) R[src];
                    if (Integer.compareUnsigned(t, c.bcSize) >= 0) {
                        hrc = VmIsaM.M_ERR_FAULT;
                        break;
                    }
                    if (c.csp >= 64) {
                        hrc = VmIsaM.M_ERR_TOO_DEEP;
                        break;
                    }
                    c.callstack[c.csp++] = (long) (c.ip + VmIsaM.M_INSN_SIZE);
                    c.ip = t;
                    jumped = true;
                    break;
                }
                case VmIsaM.M_JMPR: {
                    final int t = (int) R[src];
                    if (Integer.compareUnsigned(t, c.bcSize) >= 0) {
                        hrc = VmIsaM.M_ERR_FAULT;
                        break;
                    }
                    c.ip = t;
                    jumped = true;
                    break;
                }
                case VmIsaM.M_RET:
                    if (c.csp == 0) {
                        hrc = VmIsaM.M_ERR_FAULT;
                        break;
                    }
                    c.ip = (int) c.callstack[--c.csp];
                    jumped = true;
                    break;
                case VmIsaM.M_HOST:
                    if (c.hostFn == null) {
                        hrc = VmIsaM.M_ERR_FAULT;
                        break;
                    }
                    hrc = c.hostFn.call(c.hostArg, imm, c.m);
                    break;
                case VmIsaM.M_HALT:
                    c.retval = (int) R[src];
                    haltStatus = (int) R[dst];
                    halted = true;
                    break;
                default:
                    hrc = VmIsaM.M_ERR_BAD_OPCODE;
                    break;
            }

            for (int i = 0; i < VmIsaM.M_INSN_SIZE; ++i) {
                image[c.insnOff + i] = (byte) (image[c.insnOff + i] ^ c.ks8[i]);
            }

            if (halted) {
                System.arraycopy(c.m, 0, m, 0, VmIsaM.M_REGS);
                if (out != null && out.length > 0) {
                    out[0] = c.retval;
                }
                return haltStatus;
            }
            if (hrc != VmIsaM.M_OK) {
                return hrc;
            }
            if (!jumped) {
                c.ip += VmIsaM.M_INSN_SIZE;
            }
        }
    }

    /** keystream 逐字节（块缓存；对应 m_ks_byte）。 */
    private static int ksByte(MetaCtx c, int pos) {
        final int blk = pos >>> 6;
        if (blk != c.ksCounter) {
            VmKs.vmKsBlock(c.k8, blk, c.ksBlock, 0);
            c.ksCounter = blk;
        }
        return c.ksBlock[pos & 63] & 0xFF;
    }

    /** 条件码求值（对应 m_cc_eval；无符号比较用 compareUnsigned）。 */
    private static int mCcEval(int cc, long a, long b) {
        switch (cc) {
            case VmIsaM.M_CC_EQ:
                return a == b ? 1 : 0;
            case VmIsaM.M_CC_NE:
                return a != b ? 1 : 0;
            case VmIsaM.M_CC_ULT:
                return Long.compareUnsigned(a, b) < 0 ? 1 : 0;
            case VmIsaM.M_CC_UGE:
                return Long.compareUnsigned(a, b) >= 0 ? 1 : 0;
            case VmIsaM.M_CC_ULE:
                return Long.compareUnsigned(a, b) <= 0 ? 1 : 0;
            case VmIsaM.M_CC_UGT:
                return Long.compareUnsigned(a, b) > 0 ? 1 : 0;
            case VmIsaM.M_CC_SLT:
                return a < b ? 1 : 0;
            case VmIsaM.M_CC_SGE:
                return a >= b ? 1 : 0;
            case VmIsaM.M_CC_SLE:
                return a <= b ? 1 : 0;
            case VmIsaM.M_CC_SGT:
                return a > b ? 1 : 0;
            default:
                return 0;
        }
    }

    /**
     * 内存操作数地址：{@code m[reg] + simm32(imm)}。
     * Java 侧无指针，地址 = 传入 {@code vmMetaExec} 的 image 数组下标
     * （与 MetaInner 的扁平地址模型一致），故取 64 位和的低 32 位。
     */
    private static int addrOf(long reg, int imm) {
        return (int) (reg + (long) imm);
    }
}
