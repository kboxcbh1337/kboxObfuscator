package com.kbox.core.shield;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SROX 可恢复性代理指标。
 *
 * <p><b>重要声明</b>：这些数值是「结构可恢复性」的代理指标，用于在同一构建内
 * 比较候选表示、淘汰只增加体积却未改变结构特征的变换；它们不是对商业保护器
 * 强度的测量，也不能替代独立分析者在固定预算下的盲测。</p>
 *
 * <p>指标：</p>
 * <ul>
 *   <li>{@code patternReuse}：语义 opcode 二元组重复率（越高越容易被模板匹配）。</li>
 *   <li>{@code constSurvival}：原表示的立即数仍以字面量出现在候选中的比例。</li>
 *   <li>{@code linearRatio}：长度 ≤2 的基本块占比（越高越容易恢复块结构）。</li>
 *   <li>{@code branchNorm}：边/节点密度归一化（控制流复杂度）。</li>
 *   <li>{@code entropyNorm}：opcode 分布熵归一化（指令语义多样性）。</li>
 *   <li>{@code sizeRatio}：候选/原表示的指令数比。</li>
 * </ul>
 */
final class SroxMetrics {

    int insns;
    int blocks;
    int edges;
    int linearBlocks;
    int immInsns;
    double patternReuse;
    double constSurvival;
    double linearRatio;
    double branchNorm;
    double entropyNorm;
    double sizeRatio;
    double score;

    private SroxMetrics() {
    }

    static SroxMetrics compute(Ir.IrFunc base, Ir.IrFunc cand) {
        SroxMetrics m = new SroxMetrics();
        List<Ir.IrInsn> insns = cand.insns;
        m.insns = insns.size();
        m.sizeRatio = base.insns.isEmpty() ? 0.0 : (double) insns.size() / base.insns.size();

        // ---- 基本块 / 边 ----
        int n = insns.size();
        boolean[] leader = new boolean[Math.max(1, n)];
        if (n > 0) leader[0] = true;
        for (int i = 0; i < n; ++i) {
            int op = insns.get(i).op;
            if (op == Ir.IR_JMP || op == Ir.IR_JCC) {
                int t = insns.get(i).target;
                if (t >= 0 && t < n) leader[t] = true;
                if (i + 1 < n) leader[i + 1] = true;
            }
        }
        int[] blockStart = new int[Math.max(1, n)];
        int[] blockEnd = new int[Math.max(1, n)];
        int bc = 0;
        int start = 0;
        for (int i = 1; i <= n; ++i) {
            if (i == n || leader[i]) {
                blockStart[bc] = start;
                blockEnd[bc] = i;
                ++bc;
                start = i;
            }
        }
        m.blocks = bc;
        int edges = 0;
        int linear = 0;
        for (int b = 0; b < bc; ++b) {
            int from = blockStart[b];
            int to = blockEnd[b];
            if (to - from <= 2) ++linear;
            if (to <= from) continue;
            int term = insns.get(to - 1).op;
            if (term == Ir.IR_JMP) {
                ++edges;
            } else if (term == Ir.IR_JCC) {
                ++edges;
                if (to < n) ++edges;              // 下落边
            } else if (term != Ir.IR_RET && to < n) {
                ++edges;                          // 纯下落块
            }
        }
        m.edges = edges;
        m.linearBlocks = linear;
        m.linearRatio = bc == 0 ? 0.0 : (double) linear / bc;
        m.branchNorm = bc == 0 ? 0.0 : Math.min(1.0, ((double) edges / bc) / 3.0);

        // ---- 立即数存活 ----
        Set<Integer> baseImm = immSet(base.insns);
        Set<Integer> candImm = immSet(cand.insns);
        if (!baseImm.isEmpty()) {
            int kept = 0;
            for (Integer v : baseImm) {
                if (candImm.contains(v)) ++kept;
            }
            m.constSurvival = (double) kept / baseImm.size();
        }
        m.immInsns = candImm.size();

        // ---- opcode 二元组重复率 ----
        Map<Integer, Integer> bigrams = new HashMap<Integer, Integer>();
        int total = 0;
        for (int i = 1; i < n; ++i) {
            int k = key(insns.get(i - 1)) * 4096 + key(insns.get(i));
            Integer c = bigrams.get(Integer.valueOf(k));
            bigrams.put(Integer.valueOf(k), Integer.valueOf(c == null ? 1 : c.intValue() + 1));
            ++total;
        }
        m.patternReuse = total == 0 ? 0.0 : 1.0 - (double) bigrams.size() / total;

        // ---- 语义 opcode 熵 ----
        Map<Integer, Integer> hist = new HashMap<Integer, Integer>();
        for (Ir.IrInsn in : insns) {
            Integer c = hist.get(Integer.valueOf(key(in)));
            hist.put(Integer.valueOf(key(in)), Integer.valueOf(c == null ? 1 : c.intValue() + 1));
        }
        double h = 0.0;
        for (Integer c : hist.values()) {
            double p = (double) c.intValue() / Math.max(1, n);
            h -= p * (Math.log(p) / Math.log(2.0));
        }
        m.entropyNorm = Math.min(1.0, h / 4.5);

        // ---- 综合分（代理，不是强度结论） ----
        double s = 0.28 * (1.0 - m.patternReuse)
                + 0.20 * m.branchNorm
                + 0.20 * (1.0 - m.constSurvival)
                + 0.17 * m.entropyNorm
                + 0.15 * (1.0 - m.linearRatio)
                - 0.05 * Math.max(0.0, m.sizeRatio - 3.0);
        m.score = Math.max(0.0, Math.min(1.0, s));
        return m;
    }

    private static int key(Ir.IrInsn in) {
        int k = in.op;
        if (in.op == Ir.IR_BIN || in.op == Ir.IR_UN
                || in.op == Ir.IR_SETCC || in.op == Ir.IR_JCC) {
            k = k * 32 + (in.sub & 31);
        }
        return k;
    }

    private static Set<Integer> immSet(List<Ir.IrInsn> insns) {
        Set<Integer> s = new HashSet<Integer>();
        for (Ir.IrInsn in : insns) {
            if ((in.op == Ir.IR_MOVI || in.op == Ir.IR_LEA) && in.imm != 0) {
                s.add(Integer.valueOf(in.imm));
            }
        }
        return s;
    }

    String summary() {
        return String.format(java.util.Locale.ROOT,
                "ir=%d blocks=%d edges=%d linear=%.3f const=%.3f reuse=%.3f ent=%.3f size=%.2f score=%.4f",
                insns, blocks, edges, linearRatio, constSurvival, patternReuse,
                entropyNorm, sizeRatio, score);
    }
}
