package com.kbox.core.sedvx;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.analysis.DependencyAnalyzer;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * SED-VX orchestrator: Atlas → Critical Slice → Realization Pool → Weaving →
 * Validation → Report.
 *
 * <p>The design document's six components map onto the classes in this package:
 * {@link SemanticAtlas} (A), {@link CriticalSlicer} (B),
 * {@link RealizationPool} (C), {@link SedVxWeaver} (D + E), and this class plus
 * {@link SedVxReport} (F). The implementation is deliberately a
 * <em>restricted</em> first step: it supports int/long value evidence in
 * handler-free, non-JNIC/VMP methods, and refuses anything it cannot verify.
 *
 * <p>Reports are written to the build work directory as
 * {@code sedvx-report.json} and {@code sedvx-report.md}, and are also surfaced
 * through the HTML console.
 */
public final class SedVxEngine {

    private static final String TAG = "sedvx";

    private SedVxEngine() {}

    /**
     * Analyses and (when {@code mutate}) rewrites the graph.
     *
     * @param graph  parsed input (mutated only when {@code mutate})
     * @param cfg    build config (read-only here)
     * @param mutate {@code false} for a report-only dry run
     */
    public static SedVxReport run(ClassGraph graph, ProtectionConfig cfg, boolean mutate) {
        long t0 = System.currentTimeMillis();
        SedVxReport rep = new SedVxReport();
        rep.analyzeOnly = !mutate;
        SemanticAtlas atlas = SemanticAtlas.build(graph);
        rep.classesScanned = atlas.classCount();
        rep.methodsScanned = atlas.methodCount();
        rep.sensitiveMethods = atlas.sensitiveCount();
        rep.sensitiveClasses = atlas.classEvidence().size();
        rep.seedFingerprint = seedFingerprint();
        int maxSlices = Math.max(1, cfg.getSedVxMaxSlices());
        List<SemanticAtlas.MethodInfo> slices = CriticalSlicer.select(atlas, maxSlices, 2);
        rep.slicesSelected = slices.size();
        for (int i = 0; i < slices.size() && i < 20; i++) {
            SemanticAtlas.MethodInfo mi = slices.get(i);
            rep.topSlices.add(mi.key() + "  evidence=" + mi.evidence.size()
                    + " depth=" + (mi.depth == Integer.MAX_VALUE ? -1 : mi.depth));
        }
        if (mutate) {
            List<SemanticAtlas.MethodInfo> rewriteable = CriticalSlicer.rewriteable(slices);
            SedVxWeaver.Stats st = SedVxWeaver.weave(graph, cfg, rewriteable,
                    Math.max(1, cfg.getSedVxBudget()));
            rep.slicesRewritten = st.slicesRewritten;
            rep.sitesDiffused = st.sitesDiffused;
            rep.sitesRejected = st.sitesRejected;
            rep.verifyFailures = st.verifyFailures;
            rep.realizationUse.putAll(st.realizationUse);
            rep.rejected.addAll(st.rejected);
        }
        rep.atlasJson = atlas.toJson(40);
        rep.durationMs = System.currentTimeMillis() - t0;
        if (!mutate) {
            KBoxLog.info(TAG, "SED-VX analysis: " + rep.sensitiveMethods + " sensitive method(s), "
                    + rep.slicesSelected + " slice(s) selected (report only)");
        } else {
            KBoxLog.info(TAG, "SED-VX weaving: " + rep.slicesRewritten + " slice(s), "
                    + rep.sitesDiffused + " evidence site(s) diffused, "
                    + rep.sitesRejected + " rejected by verification");
        }
        return rep;
    }

    /** Report-only convenience for the GUI: parses a jar and analyses it. */
    public static SedVxReport analyzeJar(Path jar, ProtectionConfig cfg) throws Exception {
        ClassGraph graph = new DependencyAnalyzer().analyze(jar);
        return run(graph, cfg, false);
    }

    /** Writes both report formats into {@code dir} (created if missing). */
    public static void writeReports(SedVxReport rep, Path dir) {
        try {
            Files.createDirectories(dir);
            Files.write(dir.resolve("sedvx-report.json"),
                    rep.toJson().getBytes(StandardCharsets.UTF_8));
            Files.write(dir.resolve("sedvx-report.md"),
                    rep.toMarkdown().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            KBoxLog.warn(TAG, "failed to write SED-VX report: " + e.getMessage());
        }
    }

    /** Short, non-secret fingerprint of the build seed (for report correlation). */
    private static String seedFingerprint() {
        long h = com.kbox.core.util.DetRandom.derive("sedvx-report", "seed");
        return Long.toHexString(h).toUpperCase(java.util.Locale.ROOT);
    }
}
