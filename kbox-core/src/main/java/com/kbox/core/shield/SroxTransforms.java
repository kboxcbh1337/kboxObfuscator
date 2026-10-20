package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * SROX 语义保持型变换（构建期）。
 *
 * <p>这些变换只作用于 {@link Ir.IrFunc}，由 {@link SroxEngine} 在验证门内
 * 逐候选应用：任一候选未通过语义差分验证即被丢弃，原表示保持不变。</p>
 *
 * <ul>
 *   <li>{@link #splitConstants}：把 32 位立即数拆成 XOR 双指令链，消除
 *       「MOVI 常数」这一可被常量恢复器直接提取的稳定特征。</li>
 *   <li>{@link #deadRegions}：在入口插入恒假分支 + 不可达垃圾块，破坏基本块
 *       线性布局与「入口即首个真实块」的结构推断；垃圾块永不执行。</li>
 * </ul>
 */
final class SroxTransforms {

    private SroxTransforms() {
    }

    /** 深拷贝（变换不得修改原 IR）。 */
    static Ir.IrFunc copy(Ir.IrFunc f) {
        Ir.IrFunc r = new Ir.IrFunc();
        r.entry = f.entry;
        r.frameSlots = f.frameSlots;
        r.nativeInsns = f.nativeInsns;
        r.nativeBytes = new ArrayList<Integer>(f.nativeBytes);
        r.insns = new ArrayList<Ir.IrInsn>(f.insns.size());
        for (Ir.IrInsn in : f.insns) {
            r.insns.add(cp(in));
        }
        return r;
    }

    /**
     * 常量分裂：{@code MOVI dst, k} → {@code MOVI dst, k^c; MOVI t, c; XOR dst,dst,t}。
     *
     * @param level 1 = 约 1/4 命中；2 = 约 1/2 命中
     * @return 是否发生了改写
     */
    static boolean splitConstants(Ir.IrFunc fn, long seed, int level) {
        if (level <= 0) {
            return false;
        }
        List<Ir.IrInsn> insns = fn.insns;
        final int n = insns.size();
        if (n == 0) {
            return false;
        }
        IrLiveness L = IrLiveness.compute(insns);
        long rng = SroxSemantics.mix(seed | 1L);
        int[] map = new int[n];
        List<Ir.IrInsn> out = new ArrayList<Ir.IrInsn>(n + 8);
        boolean changed = false;
        for (int i = 0; i < n; ++i) {
            map[i] = out.size();
            Ir.IrInsn in = insns.get(i);
            boolean candidate = in.op == Ir.IR_MOVI && in.width == 32
                    && Math.abs((long) in.imm) >= 8;
            if (!candidate) {
                out.add(cp(in));
                continue;
            }
            rng = SroxSemantics.mix(rng);
            int roll = (int) ((rng >>> 33) & 3L);
            if (level <= 1 ? roll != 0 : roll > 1) {
                out.add(cp(in));
                continue;
            }
            int[] t = L.freeTempsAt(i, 1, in.dst);
            if (t == null) {
                out.add(cp(in));
                continue;
            }
            int c = (int) (rng >>> 17) | 1;
            out.add(movi(in.dst, in.imm ^ c));
            out.add(movi(t[0], c));
            out.add(bin(Ir.IRB_XOR, in.dst, in.dst, t[0]));
            changed = true;
        }
        if (!changed) {
            return false;
        }
        for (Ir.IrInsn x : out) {
            if ((x.op == Ir.IR_JMP || x.op == Ir.IR_JCC)
                    && x.target >= 0 && x.target < n) {
                x.target = map[x.target];
            }
        }
        fn.insns = out;
        return true;
    }

    /**
     * 不可达区域：入口插入「t=1,u=1,t^=u → JCC t==u 跳垃圾」的恒假守卫，
     * 并在末尾追加 1..3 个垃圾块。守卫恒不成立，垃圾块永不执行。
     *
     * <p>要求 {@code entry == 0}（提升器产物的约定）且有 2 个入口处不活跃的
     * 临时虚拟寄存器；不满足时返回 false。</p>
     */
    static boolean deadRegions(Ir.IrFunc fn, long seed) {
        if (fn.entry != 0) {
            return false;
        }
        List<Ir.IrInsn> insns = fn.insns;
        final int n = insns.size();
        if (n == 0) {
            return false;
        }
        IrLiveness L = IrLiveness.compute(insns);
        int[] temps = L.freeTempsAt(0, 2, -1);
        if (temps == null) {
            return false;
        }
        final int t = temps[0];
        final int u = temps[1];
        final int guard = 4;
        List<Ir.IrInsn> out = new ArrayList<Ir.IrInsn>(n + guard + 16);
        out.add(movi(t, 1));
        out.add(movi(u, 1));
        out.add(bin(Ir.IRB_XOR, t, t, u));       // t = 0
        Ir.IrInsn jcc = new Ir.IrInsn();
        jcc.op = Ir.IR_JCC;
        jcc.width = 32;
        jcc.a = t;
        jcc.b = u;                                // 0 == 1 恒假
        jcc.sub = Ir.IRC_EQ;
        out.add(jcc);
        for (Ir.IrInsn in : insns) {
            Ir.IrInsn c = cp(in);
            if ((c.op == Ir.IR_JMP || c.op == Ir.IR_JCC) && c.target >= 0) {
                c.target += guard;
            }
            out.add(c);
        }
        final int junkStart = out.size();
        jcc.target = junkStart;
        long rng = SroxSemantics.mix(seed ^ 0xA24BAED4963EE407L);
        int blocks = 1 + (int) ((rng >>> 33) % 3L);
        for (int b = 0; b < blocks; ++b) {
            rng = SroxSemantics.mix(rng);
            int ops = 2 + (int) ((rng >>> 35) % 3L);
            for (int k = 0; k < ops; ++k) {
                rng = SroxSemantics.mix(rng);
                int sel = (int) ((rng >>> 33) % 4L);
                int imm = (int) (rng >>> 17);
                switch (sel) {
                    case 0:
                        out.add(movi(t, imm));
                        break;
                    case 1:
                        out.add(bin(Ir.IRB_XOR, t, t, u));
                        break;
                    case 2:
                        out.add(bin(Ir.IRB_ADD, u, u, t));
                        break;
                    default: {
                        Ir.IrInsn lea = new Ir.IrInsn();
                        lea.op = Ir.IR_LEA;
                        lea.width = 64;
                        lea.dst = t;
                        lea.a = u;
                        lea.imm = imm;
                        out.add(lea);
                        break;
                    }
                }
            }
            Ir.IrInsn back = new Ir.IrInsn();
            back.op = Ir.IR_JMP;
            back.width = 32;
            back.target = 0;                       // 永不执行；保持 CFG 合法
            out.add(back);
        }
        fn.insns = out;
        return true;
    }

    // ---- 构造辅助 ----

    private static Ir.IrInsn cp(Ir.IrInsn in) {
        Ir.IrInsn r = new Ir.IrInsn();
        r.op = in.op;
        r.width = in.width;
        r.dst = in.dst;
        r.a = in.a;
        r.b = in.b;
        r.sub = in.sub;
        r.imm = in.imm;
        r.target = in.target;
        r.natOff = in.natOff;
        r.natLen = in.natLen;
        return r;
    }

    private static Ir.IrInsn movi(int dst, int imm) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_MOVI;
        in.width = 32;
        in.dst = dst;
        in.imm = imm;
        return in;
    }

    private static Ir.IrInsn bin(int sub, int dst, int a, int b) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_BIN;
        in.width = 32;
        in.dst = dst;
        in.a = a;
        in.b = b;
        in.sub = sub;
        return in;
    }
}
