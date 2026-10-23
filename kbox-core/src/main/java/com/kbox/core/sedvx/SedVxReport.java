package com.kbox.core.sedvx;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SED-VX part F: the validation / evaluation record.
 *
 * <p>Every run produces this report, and it is the object the HTML console and
 * the CLI print. The fields mirror the metrics the design document defines as
 * meaningful — not "how much code was inflated", but how many sensitive sites
 * were found, how many were actually diffused, which realization was used, and
 * how many rewrites were refused by verification.
 */
public final class SedVxReport {

    public int classesScanned;
    public int methodsScanned;
    public int sensitiveMethods;
    public int sensitiveClasses;
    public int slicesSelected;
    public int slicesRewritten;
    public int sitesDiffused;
    public int sitesRejected;
    public int verifyFailures;
    public long durationMs;
    public String seedFingerprint = "";
    public final Map<String, Integer> realizationUse = new LinkedHashMap<>();
    public final List<String> topSlices = new ArrayList<>();
    public final List<String> rejected = new ArrayList<>();
    public String atlasJson = "{}";
    /** True when this run only analysed (no bytes changed). */
    public boolean analyzeOnly;

    public String toJson() {
        StringBuilder sb = new StringBuilder(2048);
        sb.append("{\"analyzeOnly\":").append(analyzeOnly)
                .append(",\"classesScanned\":").append(classesScanned)
                .append(",\"methodsScanned\":").append(methodsScanned)
                .append(",\"sensitiveMethods\":").append(sensitiveMethods)
                .append(",\"sensitiveClasses\":").append(sensitiveClasses)
                .append(",\"slicesSelected\":").append(slicesSelected)
                .append(",\"slicesRewritten\":").append(slicesRewritten)
                .append(",\"sitesDiffused\":").append(sitesDiffused)
                .append(",\"sitesRejected\":").append(sitesRejected)
                .append(",\"verifyFailures\":").append(verifyFailures)
                .append(",\"durationMs\":").append(durationMs)
                .append(",\"seedFingerprint\":\"").append(SemanticAtlas.esc(seedFingerprint)).append('"')
                .append(",\"realizations\":{");
        int i = 0;
        for (Map.Entry<String, Integer> e : realizationUse.entrySet()) {
            if (i++ > 0) sb.append(',');
            sb.append('"').append(SemanticAtlas.esc(e.getKey())).append("\":").append(e.getValue());
        }
        sb.append("},\"slices\":[");
        for (int k = 0; k < topSlices.size(); k++) {
            if (k > 0) sb.append(',');
            sb.append('"').append(SemanticAtlas.esc(topSlices.get(k))).append('"');
        }
        sb.append("],\"rejected\":[");
        for (int k = 0; k < rejected.size(); k++) {
            if (k > 0) sb.append(',');
            sb.append('"').append(SemanticAtlas.esc(rejected.get(k))).append('"');
        }
        sb.append("],\"atlas\":").append(atlasJson).append('}');
        return sb.toString();
    }

    public String toMarkdown() {
        StringBuilder sb = new StringBuilder();
        sb.append("# SED-VX 分析报告\n\n");
        sb.append("| 指标 | 值 |\n|---|---|\n");
        row(sb, "模式", analyzeOnly ? "仅分析（未改写字节码）" : "分析与改写");
        row(sb, "扫描类 / 方法", classesScanned + " / " + methodsScanned);
        row(sb, "敏感方法 / 敏感类", sensitiveMethods + " / " + sensitiveClasses);
        row(sb, "入选关键切片", String.valueOf(slicesSelected));
        row(sb, "已改写切片", String.valueOf(slicesRewritten));
        row(sb, "语义位点已扩散", String.valueOf(sitesDiffused));
        row(sb, "被验证拒绝的位点", String.valueOf(sitesRejected));
        row(sb, "类验证失败", String.valueOf(verifyFailures));
        row(sb, "耗时", durationMs + " ms");
        row(sb, "构建种子指纹", seedFingerprint);
        sb.append("\n## 等价实现使用分布\n\n| 实现 | 次数 |\n|---|---|\n");
        for (Map.Entry<String, Integer> e : realizationUse.entrySet()) {
            sb.append("| ").append(e.getKey()).append(" | ").append(e.getValue()).append(" |\n");
        }
        sb.append("\n## 关键切片（按证据排序）\n\n");
        for (String s : topSlices) sb.append("- `").append(s).append("`\n");
        if (!rejected.isEmpty()) {
            sb.append("\n## 被拒绝的改写\n\n");
            for (String s : rejected) sb.append("- ").append(s).append("\n");
        }
        sb.append("\n> 说明：本报告只描述本次构建实际发现的语义证据、实际扩散的位点与验证结果。")
                .append("它不构成“不可逆向”的结论；SED-VX 的效果必须以跨版本迁移率与语义恢复率等指标持续实测。\n");
        return sb.toString();
    }

    private static void row(StringBuilder sb, String k, String v) {
        sb.append("| ").append(k).append(" | ").append(v).append(" |\n");
    }
}
