package com.kbox.core.shield;

/**
 * ShieldOptions — kboXShield PE 加壳的可选参数（对应原先硬编码在
 * {@link ShieldPacker} 中的 KboxConfig 防御字段与架构选择）。
 *
 * <p>默认值与原始 C++ {@code packer/main.cpp} 完全一致，因此
 * {@code new ShieldOptions()} 等价于移植前的固定行为。</p>
 */
public final class ShieldOptions {

    /** 架构：跟随输入 PE 自身（默认）。 */
    public static final int ARCH_AUTO = 0;
    /** 架构：仅允许 PE32+（x86-64）；输入不是时打包失败。 */
    public static final int ARCH_X64 = 64;
    /** 架构：仅允许 PE32（x86）；输入不是时打包失败。 */
    public static final int ARCH_X86 = 32;

    /** 架构偏好（{@link #ARCH_AUTO} / {@link #ARCH_X64} / {@link #ARCH_X86}）。 */
    public int arch = ARCH_AUTO;

    /**
     * 启用的运行期检测位掩码（{@link KboxFormat#KBOX_DEF_PEB_DEBUG} 等 18 位）。
     * 0 表示关闭全部运行期防御检查。
     */
    public int defFlags = 0x0003FFFF;

    /**
     * 分级响应策略位：bit0 = 弱信号延迟后继续、bit1 = 转诱饵路径、
     * bit2 = 敌对时终止。默认 7（三者均启用）。
     */
    public int defPolicy = 7;

    /** 弱信号延迟：空转循环次数（0 = 不延迟）。 */
    public int defDelayLoops = 20000000;

    /** 反调试 / 反 VM 的 rdtsc 阈值。 */
    public int defTimingTicks = 100000;

    /** 是否启用虚拟化标记节（{@code .textvm*}）的方法体虚拟化；关闭后只做加壳。 */
    public boolean virtualizeMarkedSections = true;

    /**
     * 是否启用函数级虚拟化（x64）：解析 .pdata 的 RUNTIME_FUNCTION 表，
     * 对可提升的函数逐个虚拟化（入口改写 jmp、原函数体保留为诱饵），
     * 使普通 EXE/DLL 无需 .textvm* 标记节即可获得函数级虚拟化防护。
     */
    public boolean virtualizeFunctions = true;

    /**
     * 指令变异等级：0=关闭；1=基础（代数恒等式重写）；2=激进（含 MOVI 0 变异）。
     * 作用于被虚拟化函数的 IR，每次构建随机选型。
     */
    public int irMutation = 1;

    /** 是否对被虚拟化函数的 IR 做控制流平坦化（块号帧槽 + switch 派发器）。 */
    public boolean cfgFlatten = true;

    /**
     * SROX（Self-Researching Representation Obfuscation eXperiment）：
     * 构建期自研究闭环。对每个被虚拟化函数生成多个语义保持候选表示，
     * 用有界差分语义验证 + 可恢复性代理指标选择，失败则回滚到原表示。
     * 仅影响构建期，不引入运行期自修改。
     */
    public boolean srox = true;

    /** SROX 研究等级：0=关闭；1=轻度（变异/常量分裂）；2=+平坦化；3=+不可达区域/双族。 */
    public int sroxLevel = 3;

    /** 每函数候选数（研究轮数）。越大搜索越充分、构建越慢。 */
    public int sroxRounds = 4;

    /** 语义差分验证的随机状态组数。 */
    public int sroxVerifyRuns = 4;

    /** 超过该 IR 指令数的函数不做 SROX（仍走原有虚拟化路径）。 */
    public int sroxMaxIrInsns = 4000;

    /** SROX 报告输出路径；空 = 不写文件（只写构建日志摘要）。 */
    public String sroxReport = "";

    /** 本次构建的 SROX 研究种子（由 ShieldPacker 写入；同一产物可复现）。 */
    public long sroxSeed = 0L;

    public ShieldOptions() {
    }

    public ShieldOptions arch(int v) {
        this.arch = v;
        return this;
    }

    public ShieldOptions defFlags(int v) {
        this.defFlags = v;
        return this;
    }

    public ShieldOptions defPolicy(int v) {
        this.defPolicy = v;
        return this;
    }

    public ShieldOptions defDelayLoops(int v) {
        this.defDelayLoops = v;
        return this;
    }

    public ShieldOptions defTimingTicks(int v) {
        this.defTimingTicks = v;
        return this;
    }

    public ShieldOptions virtualizeMarkedSections(boolean v) {
        this.virtualizeMarkedSections = v;
        return this;
    }

    public ShieldOptions virtualizeFunctions(boolean v) {
        this.virtualizeFunctions = v;
        return this;
    }

    public ShieldOptions irMutation(int v) {
        this.irMutation = v;
        return this;
    }

    public ShieldOptions cfgFlatten(boolean v) {
        this.cfgFlatten = v;
        return this;
    }

    public ShieldOptions srox(boolean v) {
        this.srox = v;
        return this;
    }

    public ShieldOptions sroxLevel(int v) {
        this.sroxLevel = v;
        return this;
    }

    public ShieldOptions sroxRounds(int v) {
        this.sroxRounds = v;
        return this;
    }

    public ShieldOptions sroxReport(String v) {
        this.sroxReport = v == null ? "" : v;
        return this;
    }

    /** 架构偏好的可读名（日志/UI 用）。 */
    public String archName() {
        switch (arch) {
            case ARCH_X64:
                return "x64-only";
            case ARCH_X86:
                return "x86-only";
            default:
                return "auto";
        }
    }
}
