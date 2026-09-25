package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * LiftX64 — x86-64 子集解码器 + IR 提升器。
 *
 * <p>来源：{@code kboXShield/packer/vm/lift_x64.cpp}（逐行移植）。</p>
 *
 * <p>覆盖范围（Batch 5 首批）：
 * mov / movzx / movsx / lea / add sub and or xor (含 cmp test) / shl shr sar
 * / imul / inc dec / neg not / setcc / jcc / jmp / ret / push pop
 * / [rbp±disp] [rsp±disp]（静态帧槽）/ [reg±disp]（真实内存，32 位）</p>
 *
 * <p>静态栈帧模型：被虚拟化函数不改动真实 rsp/rbp，而是把 [rsp/rbp ± disp]
 * 静态分配到 VmCtx.frame 的帧槽区间（VM_STKFRM_SLOT0 起）。因此提升器需
 * 跟踪 rsp 相对入口的偏移与 rbp 的建立点，用于把两种基址归一到同一个
 * 帧偏移基准（函数入口 rsp）。</p>
 *
 * <p>标志位模型：不引入标志位寄存器。cmp/test 记录「待定比较」，jcc/setcc
 * 直接消费它生成比较语义；被 ALU 覆盖后仅保留 ZF 语义（EQ/NE）。
 * 任何超出模型的情况（RIP 相对、索引寻址、8/16 位内存、未支持指令、
 * call/间接跳转等）→ 整体判定函数不可提升（diag.ok = false）。</p>
 *
 * <p><b>偏移形式说明</b>（对应 C++ 的 {@code const uint8_t* code, size_t len}）：
 * C++ 以裸指针 {@code p_[i_]} 随机访问，Java 改为
 * {@code liftX64Func(byte[] code, int off, int size, Ir.IrDiag diag)}：
 * 机器码为 {@code code[off .. off + size)}，内部游标 {@code i} 始终相对 {@code off}。
 * 因此 {@code IrDiag.badOff}、JMP/JCC 的 {@code imm}（目标机器码偏移）以及
 * 内部 src_off 表均与 C++ 一致地为「相对函数体起始」的偏移。</p>
 */
public final class LiftX64 {

    private LiftX64() {
    }

    // 来源：lift_x64.cpp 匿名命名空间常量
    private static final int RSP = 4;
    private static final int RBP = 5;

    // 来源：lift_x64.cpp struct Opnd::K
    private static final int K_NONE = 0;
    private static final int K_REG = 1;
    private static final int K_FRAME = 2;
    private static final int K_MEM = 3;

    // 来源：lift_x64.cpp 各函数内的 static const uint8_t bins[8]
    private static final int[] BINS_ALU = {
            Ir.IRB_ADD, Ir.IRB_OR, 0, 0, Ir.IRB_AND, Ir.IRB_SUB, Ir.IRB_XOR, 0
    };
    private static final int[] BINS_SHIFT = {
            0, 0, 0, 0, Ir.IRB_SHL, Ir.IRB_SHR, 0, Ir.IRB_SAR
    };

    /** 来源：lift_x64.cpp struct Opnd。 */
    private static final class Opnd {
        int k = K_NONE;
        /** REG: 寄存器号；FRAME/MEM: 基址寄存器号。 */
        int reg = 0;
        /** FRAME/MEM: 位移（字节）。 */
        int disp = 0;
    }

    /** 来源：lift_x64.cpp struct Pending（待定比较：cmp/test 或经 ALU 结果）。 */
    private static final class Pending {
        boolean valid = false;
        /** 仅 EQ/NE 可信（ALU 结果比较）。 */
        boolean zfOnly = false;
        int a = 0;
        int b = 0;
    }

    /**
     * x86 cc（0..15）→ IR 条件码；返回 -1 表示不支持。
     *
     * <p>来源：lift_x64.cpp map_cc()。0=O 1=NO 2=B 3=AE 4=E 5=NE 6=BE 7=A
     * 8=S 9=NS A=P B=NP C=L D=GE E=LE F=G</p>
     */
    private static int mapCc(int cc, boolean zfOnly) {
        int r;
        switch (cc) {
            case 4:
                r = Ir.IRC_EQ;
                break;
            case 5:
                r = Ir.IRC_NE;
                break;
            case 2:
                r = Ir.IRC_ULT;
                break;
            case 3:
                r = Ir.IRC_UGE;
                break;
            case 6:
                r = Ir.IRC_ULE;
                break;
            case 7:
                r = Ir.IRC_UGT;
                break;
            case 12:
                r = Ir.IRC_SLT;
                break;
            case 13:
                r = Ir.IRC_SGE;
                break;
            case 14:
                r = Ir.IRC_SLE;
                break;
            case 15:
                r = Ir.IRC_SGT;
                break;
            default:
                return -1;
        }
        if (zfOnly && r != Ir.IRC_EQ && r != Ir.IRC_NE) {
            return -1;
        }
        return r;
    }

    /**
     * 把一段 x86-64 机器码提升为 IR。
     *
     * <p>来源：lift_x64.cpp lift_x64_func()。约束：函数体自包含（不含 call 目标
     * 在体外的调用、不含间接跳转/表跳转、不含 RIP 相对寻址）；不满足者保留为
     * IR_NATIVE 或整体判定失败。</p>
     *
     * @param code 机器码缓冲
     * @param off  函数体起始偏移（C++ 中为指针 code）
     * @param size 函数体长度（C++ 中为 size_t len）
     * @param diag 提升诊断输出（可为 null）
     * @return 提升结果；失败时返回空 IrFunc 且 diag.ok = false
     */
    public static Ir.IrFunc liftX64Func(byte[] code, int off, int size, Ir.IrDiag diag) {
        Ir.IrDiag d = new Ir.IrDiag();
        Lifter lifter = new Lifter(code, off, size, d);
        Ir.IrFunc fn = new Ir.IrFunc();
        if (!lifter.run(fn)) {
            fn = new Ir.IrFunc();
            d.ok = false;
        }
        if (diag != null) {
            diag.ok = d.ok;
            diag.badOff = d.badOff;
            diag.frameSlots = d.frameSlots;
            diag.nativeInsns = d.nativeInsns;
        }
        return fn;
    }

    /** 来源：lift_x64.cpp class Lifter。 */
    private static final class Lifter {

        private final byte[] code;
        private final int base;
        private final int n;
        private final Ir.IrDiag d;
        private int i = 0;
        private final Ir.IrFunc fn = new Ir.IrFunc();

        /** 帧偏移 -> 槽号（对应 std::map<int32_t,uint32_t>）。 */
        private final Map<Integer, Integer> frameMap = new TreeMap<Integer, Integer>();
        /** IR 下标 -> 机器码指令起始偏移。 */
        private final List<Integer> srcOff = new ArrayList<Integer>();
        /** 当前机器指令起始偏移。 */
        private int curStart = 0;

        /** rsp 相对入口 rsp。 */
        private long rspOff = 0;
        /** rbp 相对入口 rsp（未知 = 未建立）。 */
        private long rbpOff = Long.MIN_VALUE;
        private final Pending pend = new Pending();

        // ---- 前缀 ----
        private boolean rexW = false;
        private boolean opsz16 = false;
        private int rexR = 0;
        private int rexX = 0;
        private int rexB = 0;

        // ---- IR 发射 ----
        /** 对应 C++ uint8_t tmp_next_。 */
        private int tmpNext = 0;

        Lifter(byte[] code, int off, int size, Ir.IrDiag diag) {
            this.code = code;
            this.base = off;
            this.n = size;
            this.d = diag;
            this.fn.entry = 0;
        }

        // ---- 解码游标 ----
        private boolean avail(int k) {
            return i + k <= n;
        }

        private int rdU8() {
            return code[base + i++] & 0xFF;
        }

        private int rdS8() {
            return code[base + i++];
        }

        private int rdS32() {
            int v = Bin.i32(code, base + i);
            i += 4;
            return v;
        }

        // ---- 前缀 ----
        private boolean parsePrefixes() {
            rexW = false;
            opsz16 = false;
            rexR = 0;
            rexX = 0;
            rexB = 0;
            for (;;) {
                if (!avail(1)) {
                    return false;
                }
                final int b = code[base + i] & 0xFF;
                if (b == 0x66) {
                    opsz16 = true;
                    i++;
                    continue;
                }
                if (b == 0xF2 || b == 0xF3 || b == 0x67) {
                    return false;
                }
                if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26
                        || b == 0x64 || b == 0x65) {
                    i++;
                    continue;
                }
                if (b >= 0x40 && b <= 0x4F) {
                    rexW = (b & 8) != 0;
                    rexR = (b >> 2) & 1;
                    rexX = (b >> 1) & 1;
                    rexB = b & 1;
                    i++;
                    continue;
                }
                return true;
            }
        }

        /** 操作数位宽（字节）：默认 4；REX.W → 8；0x66 → 2。 */
        private int opndWidth() {
            return rexW ? 8 : (opsz16 ? 2 : 4);
        }

        /** 读取 r/m 操作数（含 ModRM/SIB/位移）。 */
        private boolean readRm(Opnd o, int[] regField) {
            if (!avail(1)) {
                return false;
            }
            final int modrm = rdU8();
            final int mod = modrm >> 6;
            final int reg = (modrm >> 3) & 7;
            final int rm = modrm & 7;
            if (regField != null) {
                regField[0] = (reg + rexR * 8) & 0xFF;
            }

            if (mod == 3) {
                o.k = K_REG;
                o.reg = (rm + rexB * 8) & 0xFF;
                return true;
            }
            int baseR = (rm + rexB * 8) & 0xFF;
            int disp = 0;
            if (rm == 4) {                       // SIB
                if (!avail(1)) {
                    return false;
                }
                final int sib = rdU8();
                final int index = (sib >> 3) & 7;
                final int sb = sib & 7;
                if (index != 4) {
                    return false;                // 不支持带索引寻址
                }
                if (mod == 0 && sb == 5) {
                    return false;                // disp32 绝对
                }
                baseR = (sb + rexB * 8) & 0xFF;
            } else if (rm == 5 && mod == 0) {
                return false;                    // RIP 相对
            }
            if (mod == 1) {
                if (!avail(1)) {
                    return false;
                }
                disp = rdS8();
            } else if (mod == 2) {
                if (!avail(4)) {
                    return false;
                }
                disp = rdS32();
            }
            o.disp = disp;
            if (baseR == RSP || baseR == RBP) {
                o.k = K_FRAME;
                o.reg = baseR;
            } else {
                o.k = K_MEM;
                o.reg = baseR;
            }
            return true;
        }

        private int tmp() {
            final int v = VmIsa.VM_MACH_GPRS + (tmpNext % VmIsa.VM_TMP_VREGS);
            tmpNext = (tmpNext + 1) & 0xFF;      // C++ 为 uint8_t，自增按 8 位回绕
            return v;
        }

        private void add(Ir.IrInsn in) {
            fn.insns.add(in);
            srcOff.add(curStart);
        }

        private Ir.IrInsn mk(int op, int width, int dst, int a, int b) {
            Ir.IrInsn in = new Ir.IrInsn();
            in.op = op;
            in.width = width;
            in.dst = dst & 0xFF;
            in.a = a & 0xFF;
            in.b = b & 0xFF;
            return in;
        }

        /** 帧偏移 -> 槽号（静态分配）；失败返回 -1（合法槽号恒 &gt;= VM_STKFRM_SLOT0）。 */
        private int frameSlot(long fo) {
            if (fo % 4 != 0) {
                return -1;
            }
            Integer hit = frameMap.get((int) fo);
            if (hit != null) {
                return hit.intValue();
            }
            if (fn.frameSlots >= VmIsa.VM_STKFRM_WORDS) {
                return -1;
            }
            final int s = VmIsa.VM_STKFRM_SLOT0 + (fn.frameSlots++);
            frameMap.put((int) fo, s);
            return s;
        }

        /** 解析帧基址操作数 -> 帧偏移。 */
        private boolean frameOffset(Opnd o, long[] fo) {
            if (o.reg == RSP) {
                fo[0] = rspOff + o.disp;
                return true;
            }
            if (o.reg == RBP) {
                if (rbpOff == Long.MIN_VALUE) {
                    return false;
                }
                fo[0] = rbpOff + o.disp;
                return true;
            }
            return false;
        }

        // ---- 各指令族 ----

        /** 取操作数的「值 vreg」；REG 直接复用寄存器 vreg。 */
        private boolean valueOf(Opnd o, int w, int[] v) {
            if (w == 8 || w == 2) {
                return false;   // 8/16 位寄存器语义不在首批范围
            }
            switch (o.k) {
                case K_REG:
                    if (o.reg == RSP || o.reg == RBP) {
                        return false;  // rsp/rbp 不作值使用
                    }
                    v[0] = o.reg;
                    return true;
                case K_FRAME: {
                    long[] fo = new long[1];
                    if (!frameOffset(o, fo)) {
                        return false;
                    }
                    final int slot = frameSlot(fo[0]);
                    if (slot < 0) {
                        return false;
                    }
                    final int t = tmp();
                    Ir.IrInsn in = mk(Ir.IR_FLD, w, t, 0, 0);
                    in.imm = slot;
                    add(in);
                    v[0] = t;
                    return true;
                }
                case K_MEM: {
                    if (w != 4) {
                        return false;         // 首批仅支持 32 位真实内存读
                    }
                    final int t = tmp();
                    Ir.IrInsn in = mk(Ir.IR_LD, w, t, o.reg, 0);
                    in.imm = o.disp;
                    add(in);
                    v[0] = t;
                    return true;
                }
                default:
                    return false;
            }
        }

        /** 把值写回操作数。 */
        private boolean storeTo(Opnd o, int w, int v) {
            if (w == 8 || w == 2) {
                return false;
            }
            switch (o.k) {
                case K_REG:
                    if (o.reg == RSP || o.reg == RBP) {
                        return false;  // 见 run() 中的专门处理
                    }
                    add(mk(Ir.IR_MOV, w, o.reg, v, 0));
                    return true;
                case K_FRAME: {
                    long[] fo = new long[1];
                    if (!frameOffset(o, fo)) {
                        return false;
                    }
                    final int slot = frameSlot(fo[0]);
                    if (slot < 0) {
                        return false;
                    }
                    Ir.IrInsn in = mk(Ir.IR_FST, w, 0, v, 0);
                    in.imm = slot;
                    add(in);
                    return true;
                }
                case K_MEM: {
                    if (w != 4) {
                        return false;         // 首批仅支持 32 位真实内存写
                    }
                    Ir.IrInsn in = mk(Ir.IR_ST, w, 0, o.reg, v);
                    in.imm = o.disp;
                    add(in);
                    return true;
                }
                default:
                    return false;
            }
        }

        private boolean emitFld(int dst, long fo, int w, int[] outSlot) {
            final int slot = frameSlot(fo);
            if (slot < 0) {
                return false;
            }
            Ir.IrInsn in = mk(Ir.IR_FLD, w, dst, 0, 0);
            in.imm = slot;
            add(in);
            if (outSlot != null) {
                outSlot[0] = slot;
            }
            return true;
        }

        private boolean emitFst(long fo, int w, int v) {
            final int slot = frameSlot(fo);
            if (slot < 0) {
                return false;
            }
            Ir.IrInsn in = mk(Ir.IR_FST, w, 0, v, 0);
            in.imm = slot;
            add(in);
            return true;
        }

        // ---- mov r/m, r（0x88/0x89）----
        private boolean doMovRmReg(int w) {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int reg = regOut[0];
            // mov rbp, rsp：建立帧基准（rsp/rbp 不落 IR）
            if (o.k == K_REG && o.reg == RBP && reg == RSP) {
                rbpOff = rspOff;
                return true;
            }
            if (!storeTo(o, w, reg)) {
                return false;
            }
            return true;
        }

        // ---- mov r, r/m（0x8A/0x8B）----
        private boolean doMovRegRm(int w) {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int reg = regOut[0];
            // mov rsp, rbp：恢复帧基准
            if (reg == RSP && o.k == K_REG && o.reg == RBP) {
                if (rbpOff == Long.MIN_VALUE) {
                    return false;
                }
                rspOff = rbpOff;
                return true;
            }
            int[] v = new int[1];
            if (!valueOf(o, w, v)) {
                return false;
            }
            add(mk(Ir.IR_MOV, w, reg, v[0], 0));
            return true;
        }

        // ---- mov 立即数族（0xB0-BF / 0xC6 / 0xC7）----
        private boolean doMovImm(int op) {
            final int w;
            Opnd o = new Opnd();
            long imm = 0;
            if (op >= 0xB0 && op <= 0xB7) {          // mov r8, imm8
                w = 1;
                o.k = K_REG;
                o.reg = ((op - 0xB0) + rexB * 8) & 0xFF;
                if (!avail(1)) {
                    return false;
                }
                imm = rdU8();
            } else if (op >= 0xB8 && op <= 0xBF) {   // mov r32/64, imm
                w = opndWidth();
                o.k = K_REG;
                o.reg = ((op - 0xB8) + rexB * 8) & 0xFF;
                if (w == 8) {
                    if (!avail(8)) {
                        return false;
                    }
                    long lo = rdS32();
                    imm = lo;
                } else {
                    if (!avail(4)) {
                        return false;
                    }
                    imm = rdS32();
                }
            } else {                                  // C6/C7: mov r/m, imm
                w = (op == 0xC6) ? 1 : opndWidth();
                if (!readRm(o, null)) {
                    return false;
                }
                if (w == 1) {
                    if (!avail(1)) {
                        return false;
                    }
                    imm = rdU8();
                } else if (w == 8) {
                    if (!avail(4)) {
                        return false;
                    }
                    imm = rdS32();
                } else {
                    if (!avail(4)) {
                        return false;
                    }
                    imm = rdS32();
                }
            }
            if (w == 1) {
                return false;                // 8 位写入不在首批范围
            }
            final int t = tmp();
            Ir.IrInsn in = mk(Ir.IR_MOVI, w, t, 0, 0);
            in.imm = (int) imm;
            add(in);
            return storeTo(o, w, t);
        }

        // ---- ALU /r（0x00-0x3D）----
        private boolean doAluRmReg(int op) {
            final int fam = (op >> 3) & 7;   // 0=add 1=or 2=adc 3=sbb 4=and 5=sub 6=xor 7=cmp
            final boolean dirRmDst = (op & 2) == 0;  // 0/2: r/m = r/m op r；1/3: r = r op r/m
            final int w = ((op & 1) != 0) ? opndWidth() : 1;
            if (w == 1) {
                return false;
            }
            if (fam == 2 || fam == 3) {
                return false;                 // adc/sbb 需进位
            }
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int reg = regOut[0];

            int a;
            int b;
            if (dirRmDst) {
                int[] av = new int[1];
                if (!valueOf(o, w, av)) {
                    return false;
                }
                a = av[0];
                b = reg;
            } else {
                a = reg;
                int[] bv = new int[1];
                if (!valueOf(o, w, bv)) {
                    return false;
                }
                b = bv[0];
            }

            final int t = tmp();
            if (fam == 7) {                                // cmp：记录待定比较
                pend.valid = true;
                pend.zfOnly = false;
                pend.a = a;
                pend.b = b;
                return true;
            }
            Ir.IrInsn in = mk(Ir.IR_BIN, w, t, a, b);
            in.sub = BINS_ALU[fam];
            add(in);
            // ALU 结果的标志位与 cmp(dst, 0) 仅在 ZF 上等价（CF/OF 不同），故只允许 EQ/NE
            pend.valid = true;
            pend.zfOnly = true;
            pend.a = t;
            pend.b = 0;
            if (dirRmDst) {
                // r/m = r/m op r：结果写回 r/m 操作数
                return storeTo(o, w, t);
            }
            // r = r op r/m（0x01/0x03 等）：结果写回寄存器 reg，而非 r/m 操作数
            // （旧实现误写回 o：如 `xor eax,[rbp+0x18]` 的结果落进帧槽，eax 保持旧值）
            add(mk(Ir.IR_MOV, w, reg, t, 0));
            return true;
        }

        // ---- ALU r/m, imm（0x80/0x81/0x83）----
        private boolean doAluRmImm(int op) {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int fam = regOut[0] & 7;
            final int w = (op == 0x80) ? 1 : opndWidth();
            if (w == 1) {
                return false;
            }
            if (fam == 2 || fam == 3) {
                return false;                 // adc/sbb
            }
            long imm;
            if (op == 0x83) {
                if (!avail(1)) {
                    return false;
                }
                imm = rdS8();
            } else if (w == 8) {
                if (!avail(4)) {
                    return false;
                }
                imm = rdS32();
            } else {
                if (!avail(4)) {
                    return false;
                }
                imm = rdS32();
            }

            // sub/add rsp, imm：仅调整帧基准，不生成 IR
            if (o.k == K_REG && o.reg == RSP && (fam == 0 || fam == 5) && w == 8) {
                return doRspAdjust(fam == 0 ? imm : -imm);
            }

            int[] av = new int[1];
            if (!valueOf(o, w, av)) {
                return false;
            }
            final int a = av[0];
            final int c = tmp();
            Ir.IrInsn ci = mk(Ir.IR_MOVI, w, c, 0, 0);
            ci.imm = (int) imm;
            add(ci);

            if (fam == 7) {                               // cmp r/m, imm
                pend.valid = true;
                pend.zfOnly = false;
                pend.a = a;
                pend.b = c;
                return true;
            }
            final int t = tmp();
            Ir.IrInsn in = mk(Ir.IR_BIN, w, t, a, c);
            in.sub = BINS_ALU[fam];
            add(in);
            pend.valid = true;
            pend.zfOnly = true;
            pend.a = t;
            pend.b = 0;
            return storeTo(o, w, t);
        }

        // ---- ALU AL/eAX, imm（0x04/0x05/.../0x3C/0x3D）----
        private boolean doAluAccImm(int op) {
            final int fam = (op >> 3) & 7;
            final int w = ((op & 1) != 0) ? opndWidth() : 1;
            if (w == 1) {
                return false;
            }
            if (fam == 2 || fam == 3) {
                return false;
            }
            long imm;
            if (w == 8) {
                if (!avail(4)) {
                    return false;
                }
                imm = rdS32();
            } else {
                if (!avail(4)) {
                    return false;
                }
                imm = rdS32();
            }
            final int a = VmIsa.GPR_RAX;
            final int c = tmp();
            Ir.IrInsn ci = mk(Ir.IR_MOVI, w, c, 0, 0);
            ci.imm = (int) imm;
            add(ci);
            if (fam == 7) {
                pend.valid = true;
                pend.zfOnly = false;
                pend.a = a;
                pend.b = c;
                return true;
            }
            Ir.IrInsn in = mk(Ir.IR_BIN, w, VmIsa.GPR_RAX, a, c);
            in.sub = BINS_ALU[fam];
            add(in);
            pend.valid = true;
            pend.zfOnly = true;
            pend.a = VmIsa.GPR_RAX;
            pend.b = 0;
            return true;
        }

        // ---- 移位（0xC0/0xC1/0xD0-D3）----
        private boolean doShift(int op) {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int fam = regOut[0] & 7;                // 4=shl 5=shr 7=sar
            if (fam != 4 && fam != 5 && fam != 7) {
                return false;
            }
            final int w = (op == 0xC0 || op == 0xD0 || op == 0xD2) ? 1 : opndWidth();
            if (w == 1) {
                return false;
            }

            final int b;
            if (op == 0xC0 || op == 0xC1) {               // 立即数
                if (!avail(1)) {
                    return false;
                }
                final long imm = rdU8();
                if (imm == 0) {
                    pend.valid = false;
                    return true;
                }
                b = tmp();
                Ir.IrInsn ci = mk(Ir.IR_MOVI, 32, b, 0, 0);
                ci.imm = (int) imm;
                add(ci);
            } else {                                      // cl
                b = VmIsa.GPR_RCX;
            }
            int[] av = new int[1];
            if (!valueOf(o, w, av)) {
                return false;
            }
            final int a = av[0];
            final int t = tmp();
            Ir.IrInsn in = mk(Ir.IR_BIN, w, t, a, b);
            in.sub = BINS_SHIFT[fam];
            add(in);
            pend.valid = false;                          // 移位后的标志位不在模型内
            return storeTo(o, w, t);
        }

        // ---- test（0x84/0x85/0xA8/0xA9）----
        private boolean doTest(int op) {
            final int w;
            final int a;
            final int b;
            if (op == 0x84 || op == 0x85) {
                w = (op == 0x84) ? 1 : opndWidth();
                if (w == 1) {
                    return false;
                }
                Opnd o = new Opnd();
                int[] regOut = new int[1];
                if (!readRm(o, regOut)) {
                    return false;
                }
                int[] av = new int[1];
                if (!valueOf(o, w, av)) {
                    return false;
                }
                a = av[0];
                b = regOut[0];
            } else {
                w = (op == 0xA8) ? 1 : opndWidth();
                if (w == 1) {
                    return false;
                }
                if (!avail(4)) {
                    return false;
                }
                final long imm = rdS32();
                a = VmIsa.GPR_RAX;
                b = tmp();
                Ir.IrInsn ci = mk(Ir.IR_MOVI, w, b, 0, 0);
                ci.imm = (int) imm;
                add(ci);
            }
            // test 的 ZF/SF 等价于 (a & b) 与 0 比较；CF/OF 恒为 0，与 cmp(x,0) 一致
            final int t = tmp();
            Ir.IrInsn in = mk(Ir.IR_BIN, w, t, a, b);
            in.sub = Ir.IRB_AND;
            add(in);
            pend.valid = true;
            pend.zfOnly = false;
            pend.a = t;
            pend.b = 0;
            return true;
        }

        // ---- F6/F7 组（test/not/neg/imul 等）----
        private boolean doUnaryGroup3(int op) {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int fam = regOut[0] & 7;
            final int w = (op == 0xF6) ? 1 : opndWidth();
            if (w == 1) {
                return false;
            }
            switch (fam) {
                case 0:                                       // test r/m, imm
                case 1: {
                    if (fam == 0) {
                        if (!avail(4)) {
                            return false;
                        }
                        final long imm = rdS32();
                        int[] av = new int[1];
                        if (!valueOf(o, w, av)) {
                            return false;
                        }
                        final int a = av[0];
                        final int c = tmp();
                        Ir.IrInsn ci = mk(Ir.IR_MOVI, w, c, 0, 0);
                        ci.imm = (int) imm;
                        add(ci);
                        final int t = tmp();
                        Ir.IrInsn in = mk(Ir.IR_BIN, w, t, a, c);
                        in.sub = Ir.IRB_AND;
                        add(in);
                        pend.valid = true;
                        pend.zfOnly = false;
                        pend.a = t;
                        pend.b = 0;
                        return true;
                    }
                    return false;                             // F7 /1 保留
                }
                case 2: {                                     // not（不影响标志位）
                    int[] av = new int[1];
                    if (!valueOf(o, w, av)) {
                        return false;
                    }
                    final int t = tmp();
                    Ir.IrInsn in = mk(Ir.IR_UN, w, t, av[0], 0);
                    in.sub = Ir.IRU_NOT;
                    add(in);
                    return storeTo(o, w, t);
                }
                case 3: {                                     // neg
                    int[] av = new int[1];
                    if (!valueOf(o, w, av)) {
                        return false;
                    }
                    final int t = tmp();
                    Ir.IrInsn in = mk(Ir.IR_UN, w, t, av[0], 0);
                    in.sub = Ir.IRU_NEG;
                    add(in);
                    pend.valid = true;
                    pend.zfOnly = true;
                    pend.a = t;
                    pend.b = 0;
                    return storeTo(o, w, t);
                }
                case 5: {                                     // imul r, r/m（单操作数形式）
                    if (o.k != K_REG) {
                        return false;
                    }
                    int[] av = new int[1];
                    if (!valueOf(o, w, av)) {
                        return false;
                    }
                    final int t = tmp();
                    Ir.IrInsn in = mk(Ir.IR_BIN, w, t, av[0], o.reg);
                    in.sub = Ir.IRB_MUL;
                    add(in);
                    pend.valid = false;
                    return storeTo(o, w, t);
                }
                default:
                    return false;                             // div/idiv 等不在首批范围
            }
        }

        // ---- imul r, r/m, imm（0x69/0x6B）----
        private boolean doImulImm(int op) {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int reg = regOut[0];
            final int w = opndWidth();
            if (w == 1) {
                return false;
            }
            long imm;
            if (op == 0x6B) {
                if (!avail(1)) {
                    return false;
                }
                imm = rdS8();
            } else {
                if (!avail(4)) {
                    return false;
                }
                imm = rdS32();
            }
            int[] av = new int[1];
            if (!valueOf(o, w, av)) {
                return false;
            }
            final int c = tmp();
            Ir.IrInsn ci = mk(Ir.IR_MOVI, w, c, 0, 0);
            ci.imm = (int) imm;
            add(ci);
            final int t = tmp();
            Ir.IrInsn in = mk(Ir.IR_BIN, w, t, av[0], c);
            in.sub = Ir.IRB_MUL;
            add(in);
            pend.valid = false;
            add(mk(Ir.IR_MOV, w, reg, t, 0));
            return true;
        }

        // ---- lea（0x8D）----
        private boolean doLea() {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int reg = regOut[0];
            final int w = opndWidth();
            if (w == 4) {
                return false;                     // lea 的地址为 64 位
            }
            if (o.k == K_REG) {
                return false;
            }
            // lea rsp, [rsp ± disp]：仅调整帧基准
            if (reg == RSP && o.reg == RSP) {
                return doRspAdjust(o.disp);
            }
            if (o.k == K_FRAME) {
                // lea reg, [rbp/rsp ± disp] 会暴露帧地址 -> 不在首批范围
                return false;
            }
            Ir.IrInsn in = mk(Ir.IR_LEA, 64, reg, o.reg, 0);
            in.imm = o.disp;
            add(in);
            return true;
        }

        // ---- push/pop（0x50-0x5F/0x68/0x6A）----
        private boolean doPushPop(int op) {
            if (op >= 0x50 && op <= 0x57) {               // push r64
                final int r = ((op - 0x50) + rexB * 8) & 0xFF;
                if (r == RSP) {
                    return false;
                }
                if (r == RBP) {
                    rspOff -= 8;
                    return true;                  // 保存值不再被读回
                }
                if (!emitFst(rspOff - 8, 64, r)) {
                    return false;
                }
                rspOff -= 8;
                return true;
            }
            if (op >= 0x58 && op <= 0x5F) {               // pop r64
                final int r = ((op - 0x58) + rexB * 8) & 0xFF;
                if (r == RSP) {
                    return false;
                }
                if (r == RBP) {
                    rspOff += 8;
                    return true;
                }
                if (!emitFld(r, rspOff, 64, null)) {
                    return false;
                }
                rspOff += 8;
                return true;
            }
            return false;                                 // push imm16/32 不在首批范围
        }

        // ---- jcc ----
        private boolean doJcc(int cc, long rel) {
            if (!pend.valid) {
                return false;
            }
            final int irc = mapCc(cc, pend.zfOnly);
            if (irc < 0) {
                return false;
            }
            Ir.IrInsn in = mk(Ir.IR_JCC, 32, 0, pend.a, pend.b);
            in.sub = irc;
            in.imm = (int) (i + rel);                     // 目标机器码偏移（回填）
            add(in);
            return true;
        }

        // ---- setcc ----
        private boolean doSetcc(int cc) {
            Opnd o = new Opnd();
            if (!readRm(o, null)) {
                return false;
            }
            if (!pend.valid) {
                return false;
            }
            final int irc = mapCc(cc, pend.zfOnly);
            if (irc < 0) {
                return false;
            }
            if (o.k != K_REG) {
                return false;           // 仅支持寄存器目标（编译器随后 movzx）
            }
            final int t = tmp();
            Ir.IrInsn in = mk(Ir.IR_SETCC, 32, t, pend.a, pend.b);
            in.sub = irc;
            add(in);
            add(mk(Ir.IR_MOV, 32, o.reg, t, 0));
            return true;
        }

        // ---- movzx / movsx ----
        private boolean doMovx(boolean isSigned) {
            Opnd o = new Opnd();
            int[] regOut = new int[1];
            if (!readRm(o, regOut)) {
                return false;
            }
            final int reg = regOut[0];
            if (isSigned) {
                return false;                  // movsx 需符号扩展语义，暂不支持
            }
            // 仅支持 movzx r32, r8（源为寄存器；其 vreg 已持有规范值）
            if (o.k != K_REG) {
                return false;
            }
            add(mk(Ir.IR_MOV, 32, reg, o.reg, 0));
            return true;
        }

        // ---- rsp 调整 ----
        private boolean doRspAdjust(long delta) {
            rspOff += delta;
            return true;
        }

        boolean run(Ir.IrFunc out) {
            while (i < n) {
                final int start = i;
                curStart = start;
                if (!parsePrefixes()) {
                    d.badOff = start;
                    return false;
                }
                if (!avail(1)) {
                    d.badOff = start;
                    return false;
                }
                final int op = rdU8();

                final int w = opndWidth();
                boolean handled = true;

                // 每次指令前重置临时寄存器分配
                tmpNext = 0;

                if (op == 0x90) {                          // nop
                    // 空操作
                } else if (op == 0xC3) {                   // ret：函数体结束（节内其余为填充）
                    add(mk(Ir.IR_RET, 32, 0, 0, 0));
                    break;
                } else if (op == 0x88 || op == 0x89) {
                    handled = doMovRmReg((op == 0x88) ? 1 : w);
                } else if (op == 0x8A || op == 0x8B) {
                    handled = doMovRegRm((op == 0x8A) ? 1 : w);
                } else if (op >= 0xB0 && op <= 0xBF) {
                    handled = doMovImm(op);
                } else if (op == 0xC6 || op == 0xC7) {
                    handled = doMovImm(op);
                } else if (op == 0x8D) {
                    handled = doLea();
                } else if (op <= 0x3D && (op & 7) <= 5) {
                    // ALU 单字节族：0x00-0x05/0x08-0x0D/.../0x38-0x3D
                    // （0x04/0x05/0x0C/0x0D/... 为 AL/eAX 立即数形式，无 ModRM）
                    final int lo3 = op & 7;
                    handled = (lo3 == 4 || lo3 == 5) ? doAluAccImm(op)
                                                     : doAluRmReg(op);
                } else if (op == 0x80 || op == 0x81 || op == 0x83) {
                    handled = doAluRmImm(op);
                } else if (op == 0x84 || op == 0x85 || op == 0xA8 || op == 0xA9) {
                    handled = doTest(op);
                } else if (op == 0xF6 || op == 0xF7) {
                    handled = doUnaryGroup3(op);
                } else if (op == 0x69 || op == 0x6B) {
                    handled = doImulImm(op);
                } else if (op == 0xC0 || op == 0xC1 || op == 0xD0 || op == 0xD1
                        || op == 0xD2 || op == 0xD3) {
                    handled = doShift(op);
                } else if (op >= 0x50 && op <= 0x5F) {
                    handled = doPushPop(op);
                } else if (op == 0xC9) {                   // leave
                    if (rbpOff == Long.MIN_VALUE) {
                        handled = false;
                    } else {
                        rspOff = rbpOff + 8;
                        handled = true;
                    }
                } else if (op >= 0x70 && op <= 0x7F) {
                    if (!avail(1)) {
                        d.badOff = start;
                        return false;
                    }
                    final long rel = rdS8();
                    handled = doJcc(op - 0x70, rel);
                } else if (op == 0x0F) {
                    if (!avail(1)) {
                        d.badOff = start;
                        return false;
                    }
                    final int op2 = rdU8();
                    if (op2 >= 0x80 && op2 <= 0x8F) {      // jcc rel32
                        if (!avail(4)) {
                            d.badOff = start;
                            return false;
                        }
                        final long rel = rdS32();
                        handled = doJcc(op2 - 0x80, rel);
                    } else if (op2 >= 0x90 && op2 <= 0x9F) {  // setcc r/m8
                        handled = doSetcc(op2 - 0x90);
                    } else if (op2 == 0x1F) {                  // 多字节 nop（对齐填充）
                        Opnd o = new Opnd();
                        if (!readRm(o, null)) {
                            d.badOff = start;
                            return false;
                        }
                        handled = true;
                    } else if (op2 == 0xB6 || op2 == 0xB7) {  // movzx
                        handled = doMovx(false);
                    } else if (op2 == 0xBE || op2 == 0xBF) {  // movsx
                        handled = doMovx(true);
                    } else if (op2 == 0xAF) {                 // imul r, r/m
                        Opnd o = new Opnd();
                        int[] regOut = new int[1];
                        if (!readRm(o, regOut)) {
                            d.badOff = start;
                            return false;
                        }
                        int[] av = new int[1];
                        if (!valueOf(o, w, av)) {
                            d.badOff = start;
                            return false;
                        }
                        final int t = tmp();
                        Ir.IrInsn in = mk(Ir.IR_BIN, w, t, regOut[0], av[0]);
                        in.sub = Ir.IRB_MUL;
                        add(in);
                        pend.valid = false;
                        add(mk(Ir.IR_MOV, w, regOut[0], t, 0));
                        handled = true;
                    } else {
                        handled = false;
                    }
                } else if (op == 0xEB || op == 0xE9) {
                    final long rel;
                    if (op == 0xEB) {
                        if (!avail(1)) {
                            d.badOff = start;
                            return false;
                        }
                        rel = rdS8();
                    } else {
                        if (!avail(4)) {
                            d.badOff = start;
                            return false;
                        }
                        rel = rdS32();
                    }
                    Ir.IrInsn in = mk(Ir.IR_JMP, 32, 0, 0, 0);
                    in.imm = (int) (i + rel);
                    add(in);
                } else {
                    handled = false;
                }

                if (!handled) {
                    d.badOff = start;
                    return false;
                }
                if (i == start) {
                    d.badOff = start;
                    return false;
                }
            }

            // 目标回填（同一机器指令可能展开为多条 IR，映射须取第一条）
            Map<Integer, Integer> off2ir = new TreeMap<Integer, Integer>();
            for (int k = srcOff.size(); k-- > 0;) {
                off2ir.put(srcOff.get(k), Integer.valueOf(k));
            }
            for (Ir.IrInsn in : fn.insns) {
                if (in.op == Ir.IR_JMP || in.op == Ir.IR_JCC) {
                    Integer t = off2ir.get(Integer.valueOf(in.imm));
                    if (t == null) {
                        d.ok = false;
                        return false;
                    }
                    in.target = t.intValue();
                }
            }
            d.frameSlots = fn.frameSlots;
            d.nativeInsns = 0;
            d.ok = true;
            out.insns = fn.insns;
            out.nativeBytes = fn.nativeBytes;
            out.entry = fn.entry;
            out.frameSlots = fn.frameSlots;
            out.nativeInsns = fn.nativeInsns;
            return true;
        }
    }
}
