package com.kbox.core.silentshield;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * AdaptabilityReport — 商业级适配性验收报告生成器（"10 年商业级混淆适配性"的交付物）。
 *
 * <p>把 SilentShield（弱点目录 + 深度自检 + 动作落地）与 {@link ModernStackAdapter}
 * （现代技术栈主动适配 + JDK 8..25 版本感知）的结果汇总成一份可供甲方合规审查的
 * <b>适配性验收报告</b>。报告结构对齐商业混淆器适配性四大支柱：
 *
 * <ul>
 *   <li><b>SPEC</b> — 规范遵循（JVMS/JNI ABI/StackMapTable/invokedynamic/bridge）。</li>
 *   <li><b>CONTRACT</b> — 隐式契约（反射/序列化/SPI/注解/资源路径/回调/入口）。</li>
 *   <li><b>DEGRADE</b> — 渐进降级（GUI EDT 回调、协程状态机、自定义 ClassLoader）。</li>
 *   <li><b>ENV</b> — 环境（JDK 8..25 类文件版本、multi-release、JPMS、GraalVM）。</li>
 * </ul>
 *
 * <p>附加"10 年适配矩阵"：按来源混淆器（ZKM/JNIC/ProGuard/Allatori/DashO/R8-D8/
 * Stringer/Spring/Jackson/Kotlin/GraalVM…）分组，给出每个来源命中的弱点族数与对策，
 * 直观展示"其他混淆器在哪失败，我们就在哪加固"的十年覆盖。
 */
public final class AdaptabilityReport {

    private final WeaknessCatalog catalog = WeaknessCatalog.get();

    /** 报告渲染所需的汇总数据。 */
    public static final class Data {
        public final List<AuditFinding> findings;
        public final int appliedActions;
        public final ModernStackAdapter.Result stack;

        public Data(List<AuditFinding> findings, int appliedActions, ModernStackAdapter.Result stack) {
            this.findings = findings;
            this.appliedActions = appliedActions;
            this.stack = stack;
        }
    }

    private AdaptabilityReport() {
    }

    /**
     * 渲染完整验收报告并（可选）写入文件。
     *
     * @return 报告全文。
     */
    public static String render(ClassGraph graph, ProtectionConfig cfg, Data data, Path reportFile) {
        AdaptabilityReport rep = new AdaptabilityReport();
        String text = rep.renderText(data);
        if (reportFile != null) {
            try {
                Files.createDirectories(reportFile.toAbsolutePath().getParent());
                Files.write(reportFile, text.getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) {
                // 报告写入失败不影响主构建。
            }
        }
        return text;
    }

    private String renderText(Data data) {
        StringBuilder sb = new StringBuilder(16_384);
        ModernStackAdapter.Result st = data.stack;

        sb.append("================================================================\n");
        sb.append("KBox 适配性验收报告 — 10 年商业级混淆适配（Java 8..25）\n");
        sb.append("================================================================\n");

        // 1. 环境支柱。
        sb.append("\n[ENV] JDK 类文件版本跨度\n");
        if (st.jdkMaxVersion == 0) {
            sb.append("  (无输入类)\n");
        } else {
            sb.append("  最低: ").append(st.jdkMinVersion).append(" = ")
                    .append(ModernStackAdapter.versionLabel(st.jdkMinVersion)).append('\n');
            sb.append("  最高: ").append(st.jdkMaxVersion).append(" = ")
                    .append(ModernStackAdapter.versionLabel(st.jdkMaxVersion)).append('\n');
            sb.append("  支持: 52..69（Java 8..25），ASM 9.10 均匀支持；输入内最高版本 ")
                    .append(st.jdkMaxVersion > 69 ? "超出（告警）" : "在支持范围内").append('\n');
        }

        // 2. 现代技术栈主动适配。
        sb.append("\n[ADAPT] 现代技术栈主动适配\n");
        sb.append("  Kotlin 协程     : ").append(st.kotlinSeen ? "是" : "否")
                .append("，已排除 ").append(st.coroutineExclusions).append(" 个状态机类")
                .append("（JNIC/VMP + 控制流）\n");
        sb.append("  multi-release  : ").append(st.multiRelease ? "是" : "否").append('\n');
        sb.append("  JPMS module-info: ").append(st.hasModuleInfo ? "是" : "否").append('\n');
        sb.append("  GraalVM 元数据  : ").append(st.graalMetadataSeen ? "是" : "否")
                .append(st.graalMetadataSeen ? "（已保留）" : "").append('\n');

        // 3. 支柱统计。
        sb.append("\n[SPEC/CONTRACT/DEGRADE] 四支柱覆盖\n");
        Map<String, Integer> byPillar = new LinkedHashMap<>();
        for (AuditFinding f : data.findings) {
            WeaknessCatalog.Weakness wk = catalog.weaknessFor(f.family);
            byPillar.merge(wk == null ? "??" : wk.pillar, 1, Integer::sum);
        }
        for (String p : new String[]{"SPEC", "CONTRACT", "DEGRADE", "ENV"}) {
            sb.append("  ").append(p).append(": ").append(byPillar.getOrDefault(p, 0)).append('\n');
        }

        // 4. 十年适配矩阵（按来源混淆器/生态）。
        sb.append("\n[MATRIX] 10 年适配矩阵（来源 -> 弱点族 / 对策落地）\n");
        Map<String, Integer> bySourceCnt = new LinkedHashMap<>();
        Map<String, Integer> bySourceMut = new LinkedHashMap<>();
        for (WeaknessCatalog.Weakness w : catalog.entries()) {
            for (String s : w.source.split("/")) {
                s = s.trim();
                bySourceCnt.merge(s, 1, Integer::sum);
                if (w.action.isMutating()) bySourceMut.merge(s, 1, Integer::sum);
            }
        }
        sb.append("  弱点目录条目数: ").append(catalog.size())
                .append("，覆盖来源: ").append(catalog.sources().size()).append('\n');
        bySourceCnt.forEach((s, c) -> sb.append("    ").append(String.format("%-14s", s))
                .append("#").append(c).append(" 族，其中需落地动作 ").append(bySourceMut.getOrDefault(s, 0)).append('\n'));

        // 5. 本次构建落地统计。
        sb.append("\n[RESULT] 本次构建适配性落地\n");
        sb.append("  去重后发现: ").append(data.findings.size()).append('\n');
        sb.append("  落地动作  : ").append(data.appliedActions).append(" 项（keep/排除/属性/资源）\n");

        // 6. 高优先级明细。
        sb.append("\n[HIGH-RISK] 高风险命中明细（risk >= HIGH）\n");
        int shown = 0;
        for (AuditFinding f : data.findings) {
            if (f.risk.rank() < RiskLevel.HIGH.rank()) continue;
            WeaknessCatalog.Weakness wk = catalog.weaknessFor(f.family);
            shown++;
            sb.append("  #").append(shown).append(" [").append(f.risk).append("] ")
                    .append(f.family).append(" ").append(f.owner.isEmpty() ? "<resource>" : f.owner)
                    .append(f.member.isEmpty() ? "" : " :: " + f.member).append('\n');
            if (wk != null) {
                sb.append("      source  : ").append(wk.source).append('\n');
                sb.append("      pillar  : ").append(wk.pillar).append('\n');
                sb.append("      symptom : ").append(wk.symptom).append('\n');
                sb.append("      hardening: ").append(wk.hardening).append('\n');
            }
            sb.append("      action  : ").append(catalog.actionFor(f.family)).append('\n');
        }
        if (shown == 0) sb.append("  (无)\n");

        sb.append("\n================================================================\n");
        sb.append("报告完备：四支柱 + 现代技术栈 + JDK 8..25 + 10 年来源矩阵 + 高风险明细。\n");
        sb.append("================================================================\n");
        return sb.toString();
    }
}