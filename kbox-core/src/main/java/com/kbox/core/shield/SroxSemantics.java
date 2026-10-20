package com.kbox.core.shield;

import java.util.HashMap;
import java.util.Map;

/**
 * SROX 语义差分验证器。
 *
 * <p>在 IR 层执行「原表示 vs 变换后表示」的差分测试：两者用同一随机种子初始化
 * 虚拟寄存器与静态帧槽，并用同一确定性内存模型（未写过的地址按地址哈希返回
 * 伪随机值），比较返回值和全部通用寄存器/帧槽。任何差异都判定变换破坏了语义，
 * 候选被回滚。</p>
 *
 * <p><b>覆盖边界（必须如实记录）</b>：这是有界差分测试，不是形式化证明——
 * 不覆盖无限输入空间、不覆盖 IR_NATIVE（无法解释的原生片段）、不覆盖真实进程
 * 内存别名与外部调用副作用。含 NATIVE 的函数直接标记为不可验证，SROX 不为其
 * 生成候选。</p>
 */
final class SroxSemantics {

    private SroxSemantics() {
    }

    /** 单次解释执行的结果。 */
    static final class Outcome {
        boolean ok = false;
        String err = "";
        int ret = 0;
        long[] gprs = new long[16];
        long[] frame = new long[0];
    }

    /** 含原生片段：IR 层无法完整解释，差分验证不可用。 */
    static boolean hasNative(Ir.IrFunc fn) {
        for (Ir.IrInsn in : fn.insns) {
            if (in.op == Ir.IR_NATIVE) {
                return true;
            }
        }
        return false;
    }

    /** 含真实内存访问：Java 侧 VM 引擎无法执行（MEMRD/MEMWR 返回 FAULT）。 */
    static boolean hasMemory(Ir.IrFunc fn) {
        for (Ir.IrInsn in : fn.insns) {
            if (in.op == Ir.IR_LD || in.op == Ir.IR_ST) {
                return true;
            }
        }
        return false;
    }

    /**
     * 有界差分等价检查。
     *
     * @param runs     随机初始状态组数
     * @param maxSteps 每组最大执行步数
     * @param why      失败原因（输出参数，可为 null）
     */
    static boolean equivalent(Ir.IrFunc base, Ir.IrFunc cand, long seed,
                              int runs, int maxSteps, StringBuilder why) {
        if (hasNative(base) || hasNative(cand)) {
            if (why != null) why.append("native-insn");
            return false;
        }
        if (runs < 1) runs = 1;
        for (int k = 0; k < runs; ++k) {
            long s = mix(seed + 0x9E3779B97F4A7C15L * (k + 1));
            Outcome a = run(base, s, maxSteps);
            Outcome b = run(cand, s, maxSteps);
            if (!a.ok || !b.ok) {
                if (why != null) why.append("exec:").append(a.ok ? b.err : a.err);
                return false;
            }
            if (a.ret != b.ret) {
                if (why != null) why.append("ret-diff");
                return false;
            }
            for (int i = 0; i < a.gprs.length; ++i) {
                if (a.gprs[i] != b.gprs[i]) {
                    if (why != null) why.append("gpr").append(i).append("-diff");
                    return false;
                }
            }
            int n = Math.min(a.frame.length, b.frame.length);
            for (int i = 0; i < n; ++i) {
                if (a.frame[i] != b.frame[i]) {
                    if (why != null) why.append("frame").append(i).append("-diff");
                    return false;
                }
            }
        }
        return true;
    }

    /** 解释执行一个 IR 函数。 */
    static Outcome run(Ir.IrFunc fn, long seed, int maxSteps) {
        Outcome o = new Outcome();
        if (fn == null || fn.insns.isEmpty()) {
            o.err = "empty";
            return o;
        }
        // 帧槽编号从 VM_STKFRM_SLOT0 起（0..VM_MACH_SLOTS-1 是机器寄存器槽），
        // 因此模型数组必须覆盖完整帧，而不是只覆盖 frameSlots 个槽。
        o.frame = new long[VmIsa.VM_STKFRM_SLOT0 + Math.max(0, fn.frameSlots)];
        final long[] v = new long[Ir.IR_VREG_MAX];
        for (int i = 0; i < v.length; ++i) {
            v[i] = mix(seed + 0x9E3779B97F4A7C15L * (i + 1));
        }
        for (int i = 0; i < o.frame.length; ++i) {
            o.frame[i] = mix(seed ^ (0xD6E8FEB86659FD93L * (i + 1)));
        }
        final Map<Long, Long> mem = new HashMap<Long, Long>();
        int pc = fn.entry;
        for (int steps = 0; steps < maxSteps; ++steps) {
            if (pc < 0 || pc >= fn.insns.size()) {
                o.err = "pc-out-of-range";
                return o;
            }
            Ir.IrInsn in = fn.insns.get(pc);
            switch (in.op) {
                case Ir.IR_MOVI:
                    v[in.dst] = norm(in.imm, in.width);
                    pc++;
                    break;
                case Ir.IR_MOV:
                    v[in.dst] = norm(v[in.a], in.width);
                    pc++;
                    break;
                case Ir.IR_BIN:
                    v[in.dst] = norm(bin(in.sub, v[in.a], v[in.b], in.width), in.width);
                    pc++;
                    break;
                case Ir.IR_UN:
                    v[in.dst] = norm(un(in.sub, v[in.a], in.width), in.width);
                    pc++;
                    break;
                case Ir.IR_LEA:
                    v[in.dst] = v[in.a] + in.imm;
                    pc++;
                    break;
                case Ir.IR_FLD:
                    if (in.imm < 0 || in.imm >= o.frame.length) {
                        o.err = "frame-load-oob";
                        return o;
                    }
                    v[in.dst] = norm(o.frame[in.imm], in.width);
                    pc++;
                    break;
                case Ir.IR_FST:
                    if (in.imm < 0 || in.imm >= o.frame.length) {
                        o.err = "frame-store-oob";
                        return o;
                    }
                    o.frame[in.imm] = norm(v[in.a], in.width);
                    pc++;
                    break;
                case Ir.IR_LD: {
                    long addr = v[in.a] + in.imm;
                    Long x = mem.get(Long.valueOf(addr));
                    long word = x != null ? x.longValue() : mix(seed ^ addr ^ 0xD6E8FEB86659FD93L);
                    v[in.dst] = norm(word, in.width);
                    pc++;
                    break;
                }
                case Ir.IR_ST: {
                    long addr = v[in.a] + in.imm;
                    mem.put(Long.valueOf(addr), Long.valueOf(norm(v[in.b], in.width)));
                    pc++;
                    break;
                }
                case Ir.IR_SETCC:
                    v[in.dst] = cc(in.sub, v[in.a], v[in.b], in.width) ? 1L : 0L;
                    pc++;
                    break;
                case Ir.IR_JMP:
                    pc = in.target;
                    break;
                case Ir.IR_JCC:
                    pc = cc(in.sub, v[in.a], v[in.b], in.width) ? in.target : pc + 1;
                    break;
                case Ir.IR_RET:
                    o.ret = (int) norm(v[0], 32);
                    for (int i = 0; i < o.gprs.length; ++i) {
                        o.gprs[i] = v[i];
                    }
                    o.ok = true;
                    return o;
                case Ir.IR_NATIVE:
                    o.err = "native";
                    return o;
                default:
                    o.err = "bad-op:" + in.op;
                    return o;
            }
        }
        o.err = "step-limit";
        return o;
    }

    // ---- 值模型 ----

    private static long norm(long x, int width) {
        if (width >= 64) {
            return x;
        }
        if (width <= 0) {
            return x & 0xFFFFFFFFL;
        }
        long mask = (1L << width) - 1L;
        return x & mask;
    }

    private static long bin(int sub, long a, long b, int width) {
        long x = norm(a, width);
        long y = norm(b, width);
        switch (sub) {
            case Ir.IRB_ADD: return x + y;
            case Ir.IRB_SUB: return x - y;
            case Ir.IRB_MUL: return x * y;
            case Ir.IRB_AND: return x & y;
            case Ir.IRB_OR: return x | y;
            case Ir.IRB_XOR: return x ^ y;
            case Ir.IRB_SHL: return x << (y & (width >= 64 ? 63 : 31));
            case Ir.IRB_SHR: {
                long u = x;
                if (width < 64) u &= (1L << width) - 1L;
                return u >>> (y & (width >= 64 ? 63 : 31));
            }
            case Ir.IRB_SAR: {
                long sx = signExtend(x, width);
                return sx >> (y & (width >= 64 ? 63 : 31));
            }
            default: return x;
        }
    }

    private static long un(int sub, long a, int width) {
        long x = norm(a, width);
        if (sub == Ir.IRU_NOT) {
            return ~x;
        }
        return -x;
    }

    private static long signExtend(long x, int width) {
        if (width >= 64) {
            return x;
        }
        int sh = 64 - (width <= 0 ? 32 : width);
        return (x << sh) >> sh;
    }

    private static boolean cc(int op, long a, long b, int width) {
        long x = norm(a, width);
        long y = norm(b, width);
        switch (op) {
            case Ir.IRC_EQ: return x == y;
            case Ir.IRC_NE: return x != y;
            case Ir.IRC_ULT: return Long.compareUnsigned(x, y) < 0;
            case Ir.IRC_UGE: return Long.compareUnsigned(x, y) >= 0;
            case Ir.IRC_ULE: return Long.compareUnsigned(x, y) <= 0;
            case Ir.IRC_UGT: return Long.compareUnsigned(x, y) > 0;
            case Ir.IRC_SLT: return signExtend(x, width) < signExtend(y, width);
            case Ir.IRC_SGE: return signExtend(x, width) >= signExtend(y, width);
            case Ir.IRC_SLE: return signExtend(x, width) <= signExtend(y, width);
            case Ir.IRC_SGT: return signExtend(x, width) > signExtend(y, width);
            default: return false;
        }
    }

    /** SplitMix64 finalizer：确定、无状态、跨平台一致。 */
    static long mix(long z) {
        z += 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }
}
