package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.List;

/**
 * IrMutate — 指令变异（Instruction Mutation）。
 *
 * <p>在 IR 层把可辨识的二元/一元运算重写为代数等价的更长指令序列
 * （等价于 VMProtect/Themida 的 mutation 引擎思想）：每个构建以随机种子
 * 选取变体，消除「单指令即单语义」的字节级签名。变异只作用于 32 位
 * 运算（IR 编译器对 64 位 BIN/UN 报错），且新增的临时虚拟寄存器通过
 * {@link IrLiveness} 保证不活跃于插入点。</p>
 *
 * <p>变体表（全部为 32 位整型恒等式）：</p>
 * <ul>
 *   <li>ADD a,b   → t=NEG(b); dst=SUB(a,t)</li>
 *   <li>SUB a,b   → t=NEG(b); dst=ADD(a,t)</li>
 *   <li>XOR a,b   → t1=OR(a,b); t2=AND(a,b); dst=SUB(t1,t2)</li>
 *   <li>AND a,b   → t0=NOT(a); t1=NOT(b); t0=OR(t0,t1); dst=NOT(t0)（德摩根）</li>
 *   <li>OR a,b    → t0=NOT(a); t1=NOT(b); t0=AND(t0,t1); dst=NOT(t0)（德摩根）</li>
 *   <li>NOT a     → t=MOVI(-1); dst=XOR(a,t)</li>
 *   <li>NEG a     → t0=NOT(a); t1=MOVI(1); dst=ADD(t0,t1)</li>
 *   <li>MOVI 0    → dst=XOR(t,t)（仅 level≥2）</li>
 * </ul>
 */
final class IrMutate {

    private IrMutate() {
    }

    /**
     * 对函数 IR 应用指令变异。
     *
     * @param level 0=关闭；1=基础（约 1/4 命中率）；2=激进（约 1/2 命中率 + MOVI 0 变异）
     */
    static void mutate(Ir.IrFunc fn, int seed, int level) {
        if (level <= 0) {
            return;
        }
        final List<Ir.IrInsn> insns = fn.insns;
        final int n = insns.size();
        if (n == 0) {
            return;
        }
        VmBuilder.Mt19937 rng = new VmBuilder.Mt19937(seed | 1);
        IrLiveness L = IrLiveness.compute(insns);

        int[] map = new int[n];
        List<Ir.IrInsn> out = new ArrayList<Ir.IrInsn>();
        for (int i = 0; i < n; ++i) {
            map[i] = out.size();
            Ir.IrInsn in = insns.get(i);
            // level 1：BIN/UN 与 1/4 命中；level 2：1/2 命中并含 MOVI 0
            boolean tryBin = (in.op == Ir.IR_BIN || in.op == Ir.IR_UN) && in.width == 32;
            boolean tryMovi = level >= 2 && in.op == Ir.IR_MOVI
                    && in.width == 32 && in.imm == 0;
            int roll = rng.next() & 3;
            if ((!tryBin && !tryMovi) || (level < 2 ? roll >= 1 : roll >= 2)) {
                out.add(in);
                continue;
            }
            Ir.IrInsn[] rep = tryMutate(in, L, i, level);
            if (rep == null) {
                out.add(in);
            } else {
                for (Ir.IrInsn r : rep) {
                    out.add(r);
                }
            }
        }

        // 指令展开后跳转目标（IR 下标）整体平移
        if (out.size() != n || !sameOrder(insns, out, map)) {
            for (Ir.IrInsn x : out) {
                if (x.op == Ir.IR_JMP || x.op == Ir.IR_JCC) {
                    x.target = map[x.target];
                }
            }
        }
        fn.insns = out;
    }

    /** 快速判定：存在任何展开（顺序已变）时无需 remap（out==n 且映射一致除外）。 */
    private static boolean sameOrder(List<Ir.IrInsn> a, List<Ir.IrInsn> b, int[] map) {
        for (int i = 0; i < a.size(); ++i) {
            if (map[i] != i) {
                return false;
            }
        }
        return true;
    }

    // ---- 变体 ----

    private static Ir.IrInsn[] tryMutate(Ir.IrInsn in, IrLiveness L, int i, int level) {
        if (in.op == Ir.IR_BIN) {
            final int dst = in.dst;
            final int a = in.a;
            final int b = in.b;
            switch (in.sub) {
                case Ir.IRB_ADD: {
                    int[] t = L.freeTempsAt(i, 1, dst);
                    if (t == null) {
                        return null;
                    }
                    return seq(
                            un(Ir.IRU_NEG, t[0], b),
                            bin(Ir.IRB_SUB, dst, a, t[0]));
                }
                case Ir.IRB_SUB: {
                    int[] t = L.freeTempsAt(i, 1, dst);
                    if (t == null) {
                        return null;
                    }
                    return seq(
                            un(Ir.IRU_NEG, t[0], b),
                            bin(Ir.IRB_ADD, dst, a, t[0]));
                }
                case Ir.IRB_XOR: {
                    int[] t = L.freeTempsAt(i, 2, dst);
                    if (t == null) {
                        return null;
                    }
                    return seq(
                            bin(Ir.IRB_OR, t[0], a, b),
                            bin(Ir.IRB_AND, t[1], a, b),
                            bin(Ir.IRB_SUB, dst, t[0], t[1]));
                }
                case Ir.IRB_AND: {
                    int[] t = L.freeTempsAt(i, 2, dst);
                    if (t == null) {
                        return null;
                    }
                    return seq(
                            un(Ir.IRU_NOT, t[0], a),
                            un(Ir.IRU_NOT, t[1], b),
                            bin(Ir.IRB_OR, t[0], t[0], t[1]),
                            un(Ir.IRU_NOT, dst, t[0]));
                }
                case Ir.IRB_OR: {
                    int[] t = L.freeTempsAt(i, 2, dst);
                    if (t == null) {
                        return null;
                    }
                    return seq(
                            un(Ir.IRU_NOT, t[0], a),
                            un(Ir.IRU_NOT, t[1], b),
                            bin(Ir.IRB_AND, t[0], t[0], t[1]),
                            un(Ir.IRU_NOT, dst, t[0]));
                }
                default:
                    return null;
            }
        }
        if (in.op == Ir.IR_UN) {
            final int dst = in.dst;
            final int a = in.a;
            switch (in.sub) {
                case Ir.IRU_NOT: {
                    int[] t = L.freeTempsAt(i, 1, dst);
                    if (t == null) {
                        return null;
                    }
                    return seq(
                            movi(t[0], -1),
                            bin(Ir.IRB_XOR, dst, a, t[0]));
                }
                case Ir.IRU_NEG: {
                    int[] t = L.freeTempsAt(i, 2, dst);
                    if (t == null) {
                        return null;
                    }
                    return seq(
                            un(Ir.IRU_NOT, t[0], a),
                            movi(t[1], 1),
                            bin(Ir.IRB_ADD, dst, t[0], t[1]));
                }
                default:
                    return null;
            }
        }
        if (level >= 2 && in.op == Ir.IR_MOVI && in.imm == 0) {
            int[] t = L.freeTempsAt(i, 1, in.dst);
            if (t == null) {
                return null;
            }
            return seq(bin(Ir.IRB_XOR, in.dst, t[0], t[0]));
        }
        return null;
    }

    // ---- 构造辅助 ----

    private static Ir.IrInsn bin(int sub, int dst, int a, int b) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_BIN;
        in.width = 32;
        in.sub = sub;
        in.dst = dst & 0xFF;
        in.a = a & 0xFF;
        in.b = b & 0xFF;
        return in;
    }

    private static Ir.IrInsn un(int sub, int dst, int a) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_UN;
        in.width = 32;
        in.sub = sub;
        in.dst = dst & 0xFF;
        in.a = a & 0xFF;
        return in;
    }

    private static Ir.IrInsn movi(int dst, int imm) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_MOVI;
        in.width = 32;
        in.dst = dst & 0xFF;
        in.imm = imm;
        return in;
    }

    private static Ir.IrInsn[] seq(Ir.IrInsn... xs) {
        return xs;
    }
}
