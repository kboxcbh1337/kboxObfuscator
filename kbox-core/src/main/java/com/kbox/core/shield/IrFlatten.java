package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

/**
 * IrFlatten — 控制流平坦化（CFG Flattening）。
 *
 * <p>把函数 IR 的可见控制流重写为「块号寄存器（静态帧槽）+ switch 派发器」：
 * 每个基本块先计算后继块号写入帧槽，再无条件跳到派发器；派发器依块号
 * 逐比较跳转。等价于 VMProtect/Themida 的平坦化层，且与既有 VM 的
 * dispatch（switch/table）形成双重调度混淆。</p>
 *
 * <p>块切分采用 leader 式：块起点 = 0、每个跳转目标、每个跳转后的下一条
 * （JCC 下落与 JMP 之后）。块尾可能是跳转指令，也可能是纯下落（无跳转的
 * 块体直接落入下一块），后者同样改写为「写后继块号 + 跳派发器」。</p>
 *
 * <p>适用性检查（不满足则原样保留，避免语义破坏）：</p>
 * <ul>
 *   <li>至少 2 个基本块；</li>
 *   <li>所有跳转目标为有效块起点（防御性校验，leader 切分下恒成立）；</li>
 *   <li>静态帧还有空余帧槽（存放块号）；</li>
 *   <li>存在 2 个在任何块入口均不活跃的临时虚拟寄存器（派发器/尾部专用）。
 *       该要求源于派发器可被任何块跳到、也可跳到任何块：若临时寄存器在
 *       某个块入口活跃，写块号会破坏其值。</li>
 * </ul>
 *
 * <p>布局：{@code [prologue: idSlot=entry][dispatcher: 逐块比较][块 0..N-1]}。</p>
 */
final class IrFlatten {

    private IrFlatten() {
    }

    /** 平坦化函数 IR。返回 false 表示不适用（保持原 IR 不变）。 */
    static boolean flatten(Ir.IrFunc fn) {
        final List<Ir.IrInsn> insns = fn.insns;
        final int n = insns.size();
        if (n < 3) {
            return false;
        }

        // ---- 1) leader 式切分基本块 ----
        boolean[] isLeader = new boolean[n];
        isLeader[0] = true;
        for (int i = 0; i < n; ++i) {
            final int op = insns.get(i).op;
            if (op == Ir.IR_JMP || op == Ir.IR_JCC) {
                final int t = insns.get(i).target;
                if (t >= 0 && t < n) {
                    isLeader[t] = true;
                }
                if (i + 1 < n) {
                    isLeader[i + 1] = true;   // JCC 下落 / JMP 之后
                }
            }
        }
        List<int[]> blocks = new ArrayList<int[]>();
        int start = 0;
        for (int i = 1; i <= n; ++i) {
            if (i == n || isLeader[i]) {
                blocks.add(new int[] { start, i });
                start = i;
            }
        }
        if (blocks.size() < 2) {
            return false;
        }

        // ---- 2) 校验所有跳转目标恰为块起点 ----
        int[] idOf = new int[n];
        Arrays.fill(idOf, -1);
        for (int b = 0; b < blocks.size(); ++b) {
            idOf[blocks.get(b)[0]] = b;
        }
        for (Ir.IrInsn in : insns) {
            if (in.op == Ir.IR_JMP || in.op == Ir.IR_JCC) {
                if (in.target < 0 || in.target >= n || idOf[in.target] < 0) {
                    return false;
                }
            }
        }

        // ---- 3) 块号帧槽 ----
        if (fn.frameSlots >= VmIsa.VM_STKFRM_WORDS) {
            return false;
        }
        final int idSlot = VmIsa.VM_STKFRM_SLOT0 + fn.frameSlots;

        // ---- 4) 全局空闲临时寄存器（任何块入口均不活跃） ----
        IrLiveness L = IrLiveness.compute(insns);
        List<Integer> starts = new ArrayList<Integer>();
        for (int b = 0; b < blocks.size(); ++b) {
            starts.add(Integer.valueOf(blocks.get(b)[0]));
        }
        BitSet free = L.neverLiveAt(starts);
        int ta = -1;
        int tb = -1;
        for (int v = 16; v < 32; ++v) {
            if (free.get(v)) {
                if (ta < 0) {
                    ta = v;
                } else {
                    tb = v;
                    break;
                }
            }
        }
        if (ta < 0 || tb < 0) {
            return false;
        }

        // ---- 5) 构建平坦化 IR ----
        List<Ir.IrInsn> out = new ArrayList<Ir.IrInsn>();

        // 入口：idSlot = 入口块 id，随后落入派发器
        out.add(movi(ta, idOf[fn.entry]));
        out.add(fst(idSlot, ta));
        final int dispatcher = out.size();

        // 派发器：idSlot == b → 跳块 b；末块直接 JMP
        int[] dispJcc = new int[blocks.size() - 1];
        for (int b = 0; b < blocks.size() - 1; ++b) {
            out.add(fld(tb, idSlot));
            out.add(movi(ta, b));
            out.add(jcc(ta, tb, Ir.IRC_EQ, 0));       // target 回填
            dispJcc[b] = out.size() - 1;
        }
        out.add(jmp(0));                               // target 回填
        final int dispLast = out.size() - 1;

        int[] blockStart = new int[blocks.size()];
        for (int b = 0; b < blocks.size(); ++b) {
            blockStart[b] = out.size();
            final int[] blk = blocks.get(b);
            final int termIdx = blk[1] - 1;
            final int termOp = insns.get(termIdx).op;
            if (termOp == Ir.IR_JMP) {
                final int tgt = insns.get(termIdx).target;
                for (int k = blk[0]; k < termIdx; ++k) {
                    out.add(cp(insns.get(k)));
                }
                out.add(movi(ta, idOf[tgt]));
                out.add(fst(idSlot, ta));
                out.add(jmp(dispatcher));
            } else if (termOp == Ir.IR_JCC) {
                final int tgt = insns.get(termIdx).target;
                for (int k = blk[0]; k < termIdx; ++k) {
                    out.add(cp(insns.get(k)));
                }
                final int j2idx = out.size();
                out.add(cp(insns.get(termIdx)));      // target 稍后回填为取用尾块
                // 下落尾：idSlot = 下落块 id
                out.add(movi(ta, idOf[blk[1]]));
                out.add(fst(idSlot, ta));
                out.add(jmp(dispatcher));
                // 取用尾：idSlot = 取用目标块 id
                final int tailT = out.size();
                out.add(movi(ta, idOf[tgt]));
                out.add(fst(idSlot, ta));
                out.add(jmp(dispatcher));
                out.get(j2idx).target = tailT;
            } else if (termOp == Ir.IR_RET) {
                // RET 块（末块）：原样保留
                for (int k = blk[0]; k < blk[1]; ++k) {
                    out.add(cp(insns.get(k)));
                }
            } else {
                // 纯下落块：body 原样 + 尾（idSlot = 下一块 id）
                for (int k = blk[0]; k < blk[1]; ++k) {
                    out.add(cp(insns.get(k)));
                }
                out.add(movi(ta, idOf[blk[1]]));
                out.add(fst(idSlot, ta));
                out.add(jmp(dispatcher));
            }
        }

        // ---- 6) 回填派发器 ----
        for (int b = 0; b < blocks.size() - 1; ++b) {
            out.get(dispJcc[b]).target = blockStart[b];
        }
        out.get(dispLast).target = blockStart[blocks.size() - 1];

        fn.insns = out;
        fn.frameSlots += 1;
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
        in.dst = dst & 0xFF;
        in.imm = imm;
        return in;
    }

    private static Ir.IrInsn fld(int dst, int slot) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_FLD;
        in.width = 32;
        in.dst = dst & 0xFF;
        in.imm = slot;
        return in;
    }

    private static Ir.IrInsn fst(int slot, int a) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_FST;
        in.width = 32;
        in.a = a & 0xFF;
        in.imm = slot;
        return in;
    }

    private static Ir.IrInsn jmp(int target) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_JMP;
        in.width = 32;
        in.target = target;
        return in;
    }

    private static Ir.IrInsn jcc(int a, int b, int cc, int target) {
        Ir.IrInsn in = new Ir.IrInsn();
        in.op = Ir.IR_JCC;
        in.width = 32;
        in.a = a & 0xFF;
        in.b = b & 0xFF;
        in.sub = cc;
        in.target = target;
        return in;
    }
}
