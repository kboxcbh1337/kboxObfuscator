package com.kbox.core.silentshield;

/**
 * SilentShield — 风险级别。
 *
 * <p>每个检测到的"特殊代码"模式都会被赋予一个风险级别，用于决定
 * 自动防护动作的强度与报告中的排序优先级：
 * <ul>
 *   <li>{@link #INFO}    — 存在但不影响正确性（仅记录）</li>
 *   <li>{@link #LOW}     — 低风险，保守处理即可</li>
 *   <li>{@link #MEDIUM}  — 中等风险，需自动分配 keep/降级</li>
 *   <li>{@link #HIGH}    — 高风险，若处理不当会直接破坏运行</li>
 *   <li>{@link #CRITICAL}— 致命风险，必须强制防护或整体降级</li>
 * </ul>
 */
public enum RiskLevel {
    INFO(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

    private final int rank;

    RiskLevel(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }

    public static RiskLevel max(RiskLevel a, RiskLevel b) {
        return a.rank >= b.rank ? a : b;
    }

    public static RiskLevel min(RiskLevel a, RiskLevel b) {
        return a.rank <= b.rank ? a : b;
    }
}
