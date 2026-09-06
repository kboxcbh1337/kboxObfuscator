package com.kbox.core.silentshield;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.analysis.MemberRef;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SilentShield — 自研智能防护系统编排器。
 *
 * <p>闭环："检测 → 分配 → 预防"。
 * <ol>
 *   <li><b>检测</b>：{@link AdaptationAuditor} 对输入 jar 做深度自检（25 类
 *       其他混淆器适配性弱点对应的特殊代码模式），产出原始发现列表。</li>
 *   <li><b>分配</b>：按 family|owner|member 去重（保留最高风险），然后对每条
 *       发现去 {@link WeaknessCatalog}（精编弱点目录：来源混淆器 / 支柱 /
 *       弱点 / 症状 / 加固）查询该族的权威动作。</li>
 *   <li><b>预防</b>：把动作落地到 {@link ProtectionConfig} / graph keep-set——
 *       反射目标 keep、序列化保留、SPI provider 保留、回调接口成员保留、
 *       Swing GUI 类排除 JNIC/VMP（预防"无画面"）、资源路径不重命名、
 *       Signature 属性保留等，全部发生在任何混淆 pass 之前。</li>
 *   <li><b>报告</b>：输出人类可读的适配性审查报告（风险分布、已分配动作、
 *       逐条明细含"来源混淆器/支柱/弱点/加固"、预防措施），供交付与回归使用。</li>
 * </ol>
 *
 * <p>SilentShield 只做保守动作（宁可少混淆也不破坏语义），与商业混淆器
 * "渐进降级 / 最小侵入"哲学一致。它是安全增强层：对简单 jar 无副作用
 * （keep 集只增不减），对复杂 jar 自动规避易碎路径——每条加固对策都
 * 直接源于其他混淆器已暴露的适配性弱点。
 */
public final class SilentShield {

    private static final String TAG = "silentshield";

    private final WeaknessCatalog catalog = WeaknessCatalog.get();

    /** 运行结果摘要。 */
    public static final class Result {
        /** 去重后的发现（已按最高风险合并）。 */
        public final List<AuditFinding> findings;
        /** 实际落地到配置/keep 集的动作数。 */
        public final int appliedActions;
        /** 人类可读报告全文。 */
        public final String report;
        /** 报告文件路径（null = 未写入）。 */
        public final Path reportFile;

        Result(List<AuditFinding> findings, int appliedActions, String report, Path reportFile) {
            this.findings = findings;
            this.appliedActions = appliedActions;
            this.report = report;
            this.reportFile = reportFile;
        }
    }

    /**
     * 运行完整闭环。
     *
     * @param graph      已分析的类图（会被读取，可能向其 keep-set 播种松散反射名）。
     * @param cfg        将被就地修改：keepPrefixes / keepMembers / nativeExcludePrefixes /
     *                   excludeControlFlowPrefixes / excludeResourcePatterns / keepAttributes。
     * @param reportFile 报告输出路径；null 则不写文件（报告仍通过返回值给出）。
     */
    public Result run(ClassGraph graph, ProtectionConfig cfg, Path reportFile) throws IOException {
        long t0 = System.currentTimeMillis();

        // 1. 深度自检。
        List<AuditFinding> raw = new AdaptationAuditor().audit(graph, cfg);

        // 2. 去重：同 family|owner|member 保留最高风险。
        Map<String, AuditFinding> unique = new LinkedHashMap<>();
        for (AuditFinding f : raw) {
            AuditFinding prev = unique.get(f.key());
            if (prev == null || f.risk.rank() > prev.risk.rank()) unique.put(f.key(), f);
        }
        List<AuditFinding> findings = new ArrayList<>(unique.values());

        // 3. 逐条分配动作并落地。
        ActionSink sink = new ActionSink(graph);
        for (AuditFinding f : findings) {
            ProtectionAction action = catalog.actionFor(f.family);
            sink.apply(f, action);
        }
        sink.commit(cfg);

        // 4. 生成报告并（可选）写入。
        String report = render(findings, sink, System.currentTimeMillis() - t0);
        if (reportFile != null) {
            try {
                Files.createDirectories(reportFile.toAbsolutePath().getParent());
                Files.write(reportFile, report.getBytes(StandardCharsets.UTF_8));
                KBoxLog.info(TAG, "Audit report written: " + reportFile);
            } catch (IOException e) {
                KBoxLog.warn(TAG, "Cannot write report " + reportFile + ": " + e.getMessage());
            }
        }
        return new Result(findings, sink.applied, report, reportFile);
    }

    // ------------------------------------------------------------------
    // 动作落地
    // ------------------------------------------------------------------

    /** 汇总动作应用，一次性写入 cfg / graph keep-set，并统计。 */
    private static final class ActionSink {
        private final ClassGraph graph;
        private final Set<String> keepClasses = new LinkedHashSet<>();
        private final Set<String> keepMembers = new LinkedHashSet<>();
        private final Set<String> keepNoArgCtors = new LinkedHashSet<>();
        private final Set<String> excludeNative = new LinkedHashSet<>();
        private final Set<String> skipControlFlow = new LinkedHashSet<>();
        private final Set<String> keepResources = new LinkedHashSet<>();
        private final Set<String> keepBeanAccessors = new LinkedHashSet<>();
        private final Set<String> packageKeeps = new LinkedHashSet<>();
        private final List<String> looseReflectionNames = new ArrayList<>();
        private final EnumMap<ProtectionAction, Integer> actionCount = new EnumMap<>(ProtectionAction.class);
        private int applied;

        ActionSink(ClassGraph graph) {
            this.graph = graph;
        }

        void apply(AuditFinding f, ProtectionAction action) {
            switch (action) {
                case KEEP_CLASS:
                    if (!f.owner.isEmpty()) keepClasses.add(f.owner);
                    break;
                case KEEP_MEMBER:
                    if (!f.owner.isEmpty() && !f.member.isEmpty()) {
                        int sp = f.member.indexOf(' ');
                        if (sp > 0) {
                            String name = f.member.substring(0, sp).trim();
                            String desc = f.member.substring(sp + 1).trim();
                            if (!name.isEmpty() && !desc.isEmpty()) {
                                keepMembers.add(ProtectionConfig.memberKey(f.owner, name, desc));
                            }
                        } else if (!f.member.trim().isEmpty()) {
                            // 只有名字、无 owner/desc 的松散反射查找（getDeclaredMethod("x")）。
                            looseReflectionNames.add(f.member.trim());
                        }
                    }
                    break;
                case KEEP_NOARG_CTOR:
                    if (!f.owner.isEmpty()) keepNoArgCtors.add(f.owner);
                    break;
                case KEEP_SERIALIZATION:
                    if (!f.owner.isEmpty()) keepClasses.add(f.owner);
                    break;
                case KEEP_SIGNATURE:
                    // Signature 属性保留是全局开关，去重后只需置位一次。
                    keepMembers.add("*SIGNATURE*");
                    break;
                case EXCLUDE_FROM_NATIVE:
                    if (!f.owner.isEmpty()) excludeNative.add(f.owner);
                    break;
                case SKIP_CONTROL_FLOW:
                    if (!f.owner.isEmpty()) skipControlFlow.add(f.owner);
                    break;
                case KEEP_RESOURCE: {
                    String path = f.member.isEmpty() ? f.owner : f.member;
                    String inGraph = normalizeResource(graph, path);
                    if (inGraph != null) keepResources.add(inGraph);
                    break;
                }
                case KEEP_BEAN_ACCESSORS:
                    if (!f.owner.isEmpty()) keepBeanAccessors.add(f.owner);
                    break;
                case KEEP_PACKAGE:
                    if (!f.owner.isEmpty()) packageKeeps.add(f.owner);
                    break;
                default:
                    // NONE / GRADUAL_DEGRADE / SKIP_STRING_ENCRYPTION：仅记录，不落地。
                    break;
            }
            actionCount.merge(action, 1, Integer::sum);
        }

        /** 把已收集的动作一次性写回 cfg 与 graph keep-set。 */
        void commit(ProtectionConfig cfg) {
            for (String c : keepClasses) cfg.getKeepPrefixes().add(c.replace('/', '.'));
            for (String mk : keepMembers) {
                if ("*SIGNATURE*".equals(mk)) {
                    cfg.getKeepAttributes().add("Signature");
                    continue;
                }
                cfg.getKeepMembers().add(mk);
            }
            for (String c : keepNoArgCtors) {
                cfg.getKeepMembers().add(ProtectionConfig.memberKey(c, "<init>", "()V"));
            }
            for (String c : excludeNative) cfg.getNativeExcludePrefixes().add(c.replace('/', '.'));
            for (String c : skipControlFlow) cfg.getExcludeControlFlowPrefixes().add(c.replace('/', '.'));
            for (String r : keepResources) cfg.getExcludeResourcePatterns().add(r);
            // Bean 访问器：按类扫描其 getX/setX/isX 方法并逐条 keep（Jackson/JavaBeans/Lombok 属性反射）。
            for (String c : keepBeanAccessors) {
                ClassNode cn = graph.getClasses().get(c);
                if (cn == null || cn.methods == null) continue;
                for (Object o : (java.util.List<MethodNode>) cn.methods) {
                    MethodNode mn = (MethodNode) o;
                    if (isBeanAccessor(mn.name, mn.desc)) {
                        cfg.getKeepMembers().add(ProtectionConfig.memberKey(cn.name, mn.name, mn.desc));
                    }
                }
            }
            for (String p : packageKeeps) {
                cfg.getKeepPrefixes().add(p.replace('/', '.') + ".");
            }
            // 松散反射名：播种 graph keep-set 的 "__anykept__"（RetentionDecision 认）。
            for (String name : looseReflectionNames) {
                graph.keep(new MemberRef("__anykept__", name, ""));
            }
            applied = keepClasses.size() + keepMembers.size() + keepNoArgCtors.size()
                    + excludeNative.size() + skipControlFlow.size() + keepResources.size()
                    + packageKeeps.size() + looseReflectionNames.size()
                    + (cfg.getKeepAttributes().contains("Signature") ? 1 : 0)
                    + keepBeanAccessors.size();
        }
    }

    /** JavaBeans 访问器约定：getX() / setX(v) / isX()。 */
    private static boolean isBeanAccessor(String name, String desc) {
        if (name == null || name.length() <= 3 || name.charAt(0) == '<') return false;
        if (name.startsWith("get") && desc.startsWith("()")) return true;
        if (name.startsWith("set") && desc.startsWith("(") && desc.endsWith(")V")) return true;
        if (name.startsWith("is") && desc.startsWith("()Z")) return true;
        return false;
    }

    /** 资源路径归一化：返回 graph 中真实存在的 key，不存在返回 null。 */
    private static String normalizeResource(ClassGraph graph, String path) {
        if (path == null || path.isEmpty()) return null;
        if (graph.getResources().containsKey(path)) return path;
        if (path.startsWith("/") && graph.getResources().containsKey(path.substring(1))) {
            return path.substring(1);
        }
        if (graph.getResources().containsKey("/" + path)) return "/" + path;
        return null;
    }

    // ------------------------------------------------------------------
    // 报告渲染
    // ------------------------------------------------------------------

    private String render(List<AuditFinding> findings, ActionSink sink, long ms) {
        StringBuilder sb = new StringBuilder(8192);

        // 风险分布。
        int[] riskCount = new int[RiskLevel.values().length];
        for (AuditFinding f : findings) riskCount[f.risk.rank()]++;
        int mutating = 0;
        for (AuditFinding f : findings) {
            if (catalog.actionFor(f.family).isMutating()) mutating++;
        }
        // 覆盖的支柱统计。
        Map<String, Integer> pillarCount = new LinkedHashMap<>();
        for (WeaknessCatalog.Weakness w : catalog.entries()) {
            pillarCount.merge(w.pillar, 1, Integer::sum);
        }

        sb.append("================================================================\n");
        sb.append("SilentShield — 其他混淆器适配性弱点加固审查报告\n");
        sb.append("================================================================\n");
        sb.append("弱点目录: WeaknessCatalog 内置 ").append(catalog.size())
                .append(" 条弱点条目，覆盖 ").append(catalog.sources().size())
                .append(" 个混淆器源（");
        boolean first = true;
        for (String s : catalog.sources()) {
            if (!first) sb.append(", ");
            sb.append(s);
            first = false;
        }
        sb.append("）\n");
        sb.append("支柱分布: ");
        for (Map.Entry<String, Integer> e : pillarCount.entrySet()) {
            sb.append(e.getKey()).append("=").append(e.getValue()).append(' ');
        }
        sb.append('\n');
        sb.append("审计耗时: ").append(ms).append(" ms\n");
        sb.append("发现数  : 原始 ").append(findings.size()).append(" 条（去重后）")
                .append("，其中需落地动作 ").append(mutating).append(" 条\n");
        sb.append("风险分布: INFO=").append(riskCount[0])
                .append(" LOW=").append(riskCount[1])
                .append(" MEDIUM=").append(riskCount[2])
                .append(" HIGH=").append(riskCount[3])
                .append(" CRITICAL=").append(riskCount[4]).append('\n');
        sb.append("----------------------------------------------------------------\n");

        // 按风险降序排列明细（仅 MEDIUM+）。
        findings.sort((a, b) -> Integer.compare(b.risk.rank(), a.risk.rank()));
        int shown = 0;
        sb.append("逐条明细（仅列出 risk >= MEDIUM）:\n");
        for (AuditFinding f : findings) {
            if (f.risk.rank() < RiskLevel.MEDIUM.rank()) continue;
            ProtectionAction act = catalog.actionFor(f.family);
            WeaknessCatalog.Weakness wk = catalog.weaknessFor(f.family);
            shown++;
            sb.append("  #").append(shown).append(" [").append(f.risk).append("] ")
                    .append(f.family).append(" ").append(f.owner.isEmpty() ? "<resource>" : f.owner)
                    .append(f.member.isEmpty() ? "" : " :: " + f.member).append('\n');
            if (wk != null) {
                sb.append("      source  : ").append(wk.source).append('\n');
                sb.append("      pillar  : ").append(wk.pillar).append('\n');
                sb.append("      weakness: ").append(wk.weakness).append('\n');
                sb.append("      symptom : ").append(wk.symptom).append('\n');
            }
            sb.append("      trigger : ").append(f.trigger).append('\n');
            if (wk != null) {
                sb.append("      hardening: ").append(wk.hardening).append('\n');
            }
            sb.append("      action  : ").append(act).append(act.isMutating() ? " (applied)" : " (recorded)").append('\n');
        }
        sb.append("----------------------------------------------------------------\n");
        sb.append("自动分配的防护动作汇总:\n");
        for (Map.Entry<ProtectionAction, Integer> e : sink.actionCount.entrySet()) {
            sb.append("  [").append(String.format("%-22s", e.getKey())).append("] x ").append(e.getValue()).append('\n');
        }
        sb.append("  applied total = ").append(sink.applied).append(" 项已写入配置/keep 集\n");
        sb.append("================================================================\n");
        return sb.toString();
    }
}
