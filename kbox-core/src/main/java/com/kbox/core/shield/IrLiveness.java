package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

/**
 * IrLiveness — 以指令为单位的简单活跃分析。
 *
 * <p>供两条 IR 后处理共用：{@link IrMutate}（指令变异）与 {@link IrFlatten}
 * （控制流平坦化）。二者都会在任意 IR 位置插入使用「临时虚拟寄存器
 * （16..31）」的新指令，若插入点选择的临时寄存器恰好是活跃值，虚拟机的
 * 帧槽会被覆盖，导致语义错误。因此插入前必须知道每个位置的活跃集合。
 *
 * <p>模型与 IR 语义一致：{@code defs[i]} / {@code uses[i]} 来自
 * {@link Ir.IrInsn} 的操作数；后继为顺序下落（i+1），跳转指令取
 * {@code target}（JMP）与 {@code target + i+1}（JCC）。RET 无后继，
 * 且读取虚拟 rax（结果语义）。标准反向迭代至不动点。</p>
 */
final class IrLiveness {

    private final List<BitSet> liveIn = new ArrayList<BitSet>();
    private final List<BitSet> liveOut = new ArrayList<BitSet>();

    private IrLiveness(int n) {
        for (int i = 0; i < n; ++i) {
            liveIn.add(new BitSet(32));
            liveOut.add(new BitSet(32));
        }
    }

    // ---- 查询 ----

    /** 指令 i 输入时寄存器 v 是否活跃（v 为 0..31 的虚拟寄存器号）。 */
    boolean liveIn(int i, int v) {
        return liveIn.get(i).get(v);
    }

    /** 指令 i 输入时的活跃集合（调用方勿修改）。 */
    BitSet liveInSet(int i) {
        return liveIn.get(i);
    }

    /**
     * 在位置 i 不活跃的临时寄存器（16..31），返回至多 {@code need} 个；
     * 不足时返回 null。返回的临时寄存器保证不活跃于位置 i（含原指令的
     * 目的寄存器 dst，避免语义混淆）。
     *
     * @param excludeDst 排除该 vreg（通常传原指令的 dst；-1 不排除）
     */
    int[] freeTempsAt(int i, int need, int excludeDst) {
        int[] out = new int[need];
        int got = 0;
        for (int v = 16; v < 32 && got < need; ++v) {
            if (v == excludeDst) {
                continue;
            }
            if (!liveIn.get(i).get(v)) {
                out[got++] = v;
            }
        }
        return got == need ? out : null;
    }

    /**
     * 在所有给定位置（通常是各基本块入口）均不活跃的临时寄存器集合。
     * 这类寄存器可在函数内任意插入的临时指令中安全使用。
     */
    BitSet neverLiveAt(List<Integer> starts) {
        BitSet r = new BitSet(32);
        r.set(16, 32);
        for (int s : starts) {
            r.andNot(liveIn.get(s));
        }
        return r;
    }

    // ---- 分析 ----

    static IrLiveness compute(List<Ir.IrInsn> insns) {
        final int n = insns.size();
        IrLiveness L = new IrLiveness(n);
        BitSet[] defs = new BitSet[n];
        BitSet[] uses = new BitSet[n];
        for (int i = 0; i < n; ++i) {
            defs[i] = new BitSet(32);
            uses[i] = new BitSet(32);
            Ir.IrInsn in = insns.get(i);
            switch (in.op) {
                case Ir.IR_MOVI:
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_MOV:
                    uses[i].set(in.a);
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_BIN:
                    uses[i].set(in.a);
                    uses[i].set(in.b);
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_UN:
                    uses[i].set(in.a);
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_LEA:
                    uses[i].set(in.a);
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_FLD:
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_FST:
                    uses[i].set(in.a);
                    break;
                case Ir.IR_LD:
                    uses[i].set(in.a);
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_ST:
                    uses[i].set(in.a);
                    uses[i].set(in.b);
                    break;
                case Ir.IR_SETCC:
                    uses[i].set(in.a);
                    uses[i].set(in.b);
                    defs[i].set(in.dst);
                    break;
                case Ir.IR_JMP:
                    // target 为 IR 下标，不涉寄存器
                    break;
                case Ir.IR_JCC:
                    uses[i].set(in.a);
                    uses[i].set(in.b);
                    break;
                case Ir.IR_RET:
                    uses[i].set(VmIsa.GPR_RAX);
                    break;
                default:
                    break;          // IR_NATIVE 等：不涉寄存器
            }
        }

        // 后继（JCC 有取用目标 target 与下落 i+1 两个后继）
        int[][] succ = new int[n][];
        for (int i = 0; i < n; ++i) {
            switch (insns.get(i).op) {
                case Ir.IR_JMP:
                    succ[i] = new int[] { insns.get(i).target };
                    break;
                case Ir.IR_JCC:
                    succ[i] = (i + 1 < n)
                            ? new int[] { insns.get(i).target, i + 1 }
                            : new int[] { insns.get(i).target };
                    break;
                case Ir.IR_RET:
                    succ[i] = new int[0];
                    break;
                default:
                    succ[i] = (i + 1 < n) ? new int[] { i + 1 } : new int[0];
                    break;
            }
        }

        boolean changed = true;
        while (changed) {
            changed = false;
            for (int i = n - 1; i >= 0; --i) {
                BitSet lo = new BitSet(32);
                for (int s : succ[i]) {
                    if (s >= 0 && s < n) {
                        lo.or(L.liveIn.get(s));
                    }
                }
                BitSet li = new BitSet(32);
                li.or(lo);
                li.andNot(defs[i]);
                li.or(uses[i]);
                if (!li.equals(L.liveIn.get(i))) {
                    L.liveIn.set(i, li);
                    changed = true;
                }
            }
        }
        // 收敛后 liveOut 与 liveIn 均已为不动点，liveOut 本类不单独暴露
        return L;
    }
}
