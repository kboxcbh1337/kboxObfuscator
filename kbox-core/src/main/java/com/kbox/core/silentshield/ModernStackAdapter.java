package com.kbox.core.silentshield;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;

/**
 * ModernStackAdapter — 现代技术栈自动适配（"10 年商业级混淆适配性"的主动适配层）。
 *
 * <p>与 {@link AdaptationAuditor}（扫描"其他混淆器弱点模式"）互补，本组件对输入 jar
 * 做<b>主动适配</b>，把现代 JVM 生态十年演进引入的易碎点提前规避：
 *
 * <ul>
 *   <li><b>JDK 版本感知（Java 8..25）</b>：统计输入 jar 的类文件主版本跨度（52..69），
 *       与 ASM 支持范围对齐；超出（&gt; Java 25）时告警而非静默损坏。</li>
 *   <li><b>Kotlin 协程</b>：suspend 函数与 ContinuationImpl 状态机类方法体复杂
 *       （try/finally/恢复点），下沉 JNIC/VMP 或破坏性控制流变换会破坏协程恢复——
 *       自动把此类加入 nativeExcludePrefixes + excludeControlFlowPrefixes。</li>
 *   <li><b>multi-release / JPMS / GraalVM / 现代字节码</b>：识别并如实记录，
 *       供 {@link AdaptabilityReport} 输出商业级验收报告。</li>
 * </ul>
 *
 * <p>只做保守动作（宁可少混淆也不破坏语义），在 SilentShield 之后运行。
 */
public final class ModernStackAdapter {

    private static final String TAG = "stack-adapt";

    /** Continuation 参数内部名（suspend 函数末参）。 */
    private static final String CONTINUATION = "Lkotlin/coroutines/Continuation;";
    /** ContinuationImpl 状态机父类前缀。 */
    private static final String CONTINUATION_IMPL_PREFIX = "kotlin/coroutines/jvm/internal/";

    /** 适配结果（供报告使用）。 */
    public static final class Result {
        /** 额外产生的适配性发现（供验收报告汇总）。 */
        public final List<AuditFinding> findings = new ArrayList<>();
        public int jdkMinVersion;
        public int jdkMaxVersion;
        public boolean multiRelease;
        public boolean hasModuleInfo;
        public boolean kotlinSeen;
        public boolean graalMetadataSeen;
        /** 新增到 nativeExcludePrefixes 的协程状态机类数。 */
        public int coroutineExclusions;
    }

    /**
     * 运行现代技术栈适配：只改 {@code cfg} 的保守排除项，返回 {@link Result} 供报告。
     */
    public Result run(ClassGraph graph, ProtectionConfig cfg) {
        Result r = new Result();
        r.jdkMinVersion = Integer.MAX_VALUE;

        for (ClassNode cn : new ArrayList<>(graph.getClasses().values())) {
            int v = cn.version;
            if (v > 0) {
                if (v < r.jdkMinVersion) r.jdkMinVersion = v;
                if (v > r.jdkMaxVersion) r.jdkMaxVersion = v;
            }
            if ("module-info".equals(cn.name)) r.hasModuleInfo = true;
            adaptClass(graph, cfg, cn, r);
        }

        for (String path : graph.getResources().keySet()) {
            if (path.startsWith("META-INF/versions/")) r.multiRelease = true;
            if (path.startsWith("META-INF/native-image/")) {
                r.graalMetadataSeen = true;
                r.findings.add(new AuditFinding("NATIVE_IMAGE_METADATA", "", path, RiskLevel.HIGH,
                        ProtectionAction.KEEP_RESOURCE,
                        "GraalVM native-image metadata " + path,
                        "keep native-image metadata (build-time contract)"));
            }
        }

        if (r.jdkMaxVersion == 0) r.jdkMinVersion = 0;
        KBoxLog.info(TAG, "  Java class-file span: "
                + (r.jdkMaxVersion == 0 ? "n/a" : versionLabel(r.jdkMinVersion) + ".." + versionLabel(r.jdkMaxVersion))
                + " (major " + r.jdkMinVersion + ".." + r.jdkMaxVersion + "), supported 52..69 (Java 8..25)");
        if (r.jdkMaxVersion > 69) {
            KBoxLog.warn(TAG, "Input contains class files newer than Java 25 (major " + r.jdkMaxVersion
                    + "); ASM 9.10 supports up to Java 27 — verify behavior before shipping.");
        }
        if (r.kotlinSeen) {
            KBoxLog.info(TAG, "  Kotlin coroutines present; " + r.coroutineExclusions
                    + " state-machine class(es) excluded from JNIC/VMP + control-flow");
        }
        if (r.multiRelease) KBoxLog.info(TAG, "  multi-release jar (META-INF/versions) detected");
        if (r.hasModuleInfo) KBoxLog.info(TAG, "  JPMS module-info present");
        if (r.graalMetadataSeen) KBoxLog.info(TAG, "  GraalVM native-image metadata present (kept)");
        return r;
    }

    @SuppressWarnings("unchecked")
    private void adaptClass(ClassGraph graph, ProtectionConfig cfg, ClassNode cn, Result r) {
        // ---- Kotlin 协程状态机类：ContinuationImpl 子类 / 含 invokeSuspend ----
        boolean stateMachine = cn.superName != null
                && cn.superName.startsWith(CONTINUATION_IMPL_PREFIX)
                && cn.superName.contains("ContinuationImpl");
        boolean hasSuspend = false;
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.desc != null && mn.desc.contains(CONTINUATION)) {
                    hasSuspend = true;
                }
            }
        }
        if (stateMachine || hasSuspend) {
            r.kotlinSeen = true;
            String dotted = cn.name.replace('/', '.');
            if (!cfg.getNativeExcludePrefixes().contains(dotted)) {
                cfg.getNativeExcludePrefixes().add(dotted);
                cfg.getExcludeControlFlowPrefixes().add(dotted);
                r.coroutineExclusions++;
                r.findings.add(new AuditFinding(
                        stateMachine ? "KOTLIN_COROUTINES" : "KOTLIN_COROUTINES",
                        cn.name, "", RiskLevel.HIGH, ProtectionAction.EXCLUDE_FROM_NATIVE,
                        (stateMachine ? "coroutine state machine " : "suspend function holder ") + cn.name,
                        "excluded from JNIC/VMP + control-flow (coroutine resume safety)"));
            }
        }
    }

    /** 类文件主版本 -> Java 发行版标签（52..69）。 */
    static String versionLabel(int major) {
        switch (major) {
            case 52: return "Java 8";
            case 53: return "Java 9";
            case 54: return "Java 10";
            case 55: return "Java 11";
            case 56: return "Java 12";
            case 57: return "Java 13";
            case 58: return "Java 14";
            case 59: return "Java 15";
            case 60: return "Java 16";
            case 61: return "Java 17";
            case 62: return "Java 18";
            case 63: return "Java 19";
            case 64: return "Java 20";
            case 65: return "Java 21";
            case 66: return "Java 22";
            case 67: return "Java 23";
            case 68: return "Java 24";
            case 69: return "Java 25";
            default: return "?" + major;
        }
    }
}
