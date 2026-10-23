package com.kbox.core.silentshield;

/**
 * SilentShield — 单条深度自检发现。
 *
 * <p>由 {@link AdaptationAuditor} 在输入 jar 中扫描"同类工具适配性弱点"
 * 对应的特殊代码模式后产生。每条发现记录：模式族（family）、所属类（internal
 * name）、成员（"name desc"）、风险级别、应执行的防护动作、触发条件描述与
 * 缓解说明。随后 {@link SilentShield} 会用它去 {@link WeaknessCatalog} 中
 * 查询该族的权威动作并落地到配置，实现"检测 → 分配 → 预防"的闭环。
 */
public final class AuditFinding {

    /** 模式族，与 {@link WeaknessCatalog} 中的 family 一一对应（如 REFLECTION_FOR_NAME）。 */
    public final String family;
    /** 所属类 internal name（资源级发现可为空串）。 */
    public final String owner;
    /** 成员描述（"name desc"）；类级/资源级发现可为空串；资源路径也放在此字段。 */
    public final String member;
    /** 该发现的风险级别。 */
    public final RiskLevel risk;
    /** 该发现应执行的防护动作。 */
    public final ProtectionAction action;
    /** 人类可读的触发条件。 */
    public final String trigger;
    /** 人类可读的缓解/处理说明。 */
    public final String mitigation;
    /**
     * 动作真正应落在的类（internal name）。默认与 owner 相同；但当"发现位置"
     * 与"受影响目标"不同（如 REFLECTION_FOR_NAME：owner 是 forName 的调用方，
     * 需要保名的是被加载的目标类）时由发现方显式给出，KEEP_CLASS 等动作
     * 优先使用该字段，避免钉死调用方而放过目标。
     */
    public final String targetClass;

    public AuditFinding(String family, String owner, String member,
                        RiskLevel risk, ProtectionAction action,
                        String trigger, String mitigation) {
        this(family, owner, member, risk, action, trigger, mitigation, "");
    }

    public AuditFinding(String family, String owner, String member,
                        RiskLevel risk, ProtectionAction action,
                        String trigger, String mitigation, String targetClass) {
        this.family = family;
        this.owner = owner == null ? "" : owner;
        this.member = member == null ? "" : member;
        this.risk = risk;
        this.action = action;
        this.trigger = trigger;
        this.mitigation = mitigation;
        this.targetClass = targetClass == null ? "" : targetClass;
    }

    /** 去重标识：同 family + owner + member 视为同一条；targetClass 参与去重，
     *  否则同一调用方对不同目标类的多次 forName 会互相吞掉。 */
    public String key() {
        return family + "|" + owner + "|" + member
                + (targetClass.isEmpty() ? "" : "|" + targetClass);
    }

    @Override
    public String toString() {
        return family + " " + (owner.isEmpty() ? "<resource>" : owner)
                + (member.isEmpty() ? "" : " :: " + member)
                + " [" + risk + " -> " + action + "]";
    }
}
