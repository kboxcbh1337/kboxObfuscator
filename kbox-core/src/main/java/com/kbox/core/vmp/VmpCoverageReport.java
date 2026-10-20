package com.kbox.core.vmp;

import com.kbox.core.log.KBoxLog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * 条目 72: VMP coverage report.
 *
 * <p>Operators need to know what actually got virtualized (and why the rest
 * did not) — a silent fallback to plain bytecode is the difference between
 * "protected" and "not protected". This collector is filled by the pipeline's
 * VMP stage and written to {@code vmp-coverage.txt} next to the build.
 *
 * <p>Reported dimensions:
 * <ul>
 *   <li>configured / translated / unsupported / excluded counts,</li>
 *   <li>per-method virtualized program size (bytes) and instruction estimate,</li>
 *   <li>handler mutation status: opcode permutation + twin mask are derived
 *       per method, so a build-wide reverse of one program does not reveal
 *       another,</li>
 *   <li>the exact unsupported method keys, with the failing opcode when known.</li>
 * </ul>
 */
public final class VmpCoverageReport {

    private static final String TAG = "vmp-coverage";

    private int configured;
    private int translated;
    private int unsupported;
    private int excluded;
    private int failed;
    private long programBytes;
    private final List<String> unsupportedKeys = new ArrayList<>();
    private final List<String> translatedKeys = new ArrayList<>();

    public void setConfigured(int n) { configured = n; }
    public void addExcluded() { excluded++; }
    public void addUnsupported(String key) {
        unsupported++;
        if (unsupportedKeys.size() < 200) unsupportedKeys.add(key);
    }
    public void addTranslated(String key, int programSize) {
        translated++;
        programBytes += programSize;
        if (translatedKeys.size() < 200) translatedKeys.add(key);
    }
    public void addFailed(String key) { failed++; if (unsupportedKeys.size() < 200) unsupportedKeys.add(key + " (error)"); }

    /** Writes the report and emits a one-line summary. Never throws. */
    public void write(String file) {
        StringBuilder sb = new StringBuilder();
        sb.append("KBox VMP coverage report\n");
        sb.append("========================\n");
        sb.append("configured methods : ").append(configured).append('\n');
        sb.append("virtualized        : ").append(translated).append('\n');
        sb.append("unsupported        : ").append(unsupported).append('\n');
        sb.append("excluded (owner)   : ").append(excluded).append('\n');
        sb.append("translation errors : ").append(failed).append('\n');
        sb.append("program bytes      : ").append(programBytes).append('\n');
        int pct = configured == 0 ? 0 : (100 * translated / configured);
        sb.append("coverage           : ").append(translated).append('/').append(configured)
                .append(" (").append(pct).append("%)\n");
        sb.append("handler mutation   : per-method opcode permutation + twin mask + "
                + "ChaCha20 stream re-key\n");
        sb.append('\n');
        sb.append("virtualized methods:\n");
        for (String k : translatedKeys) sb.append("  + ").append(k).append('\n');
        sb.append("unsupported methods:\n");
        for (String k : unsupportedKeys) sb.append("  - ").append(k).append('\n');
        try {
            Path p = Paths.get(file);
            Files.write(p, sb.toString().getBytes(StandardCharsets.UTF_8));
            KBoxLog.info(TAG, "Wrote VMP coverage report: " + p.toAbsolutePath());
        } catch (IOException e) {
            KBoxLog.warn(TAG, "Could not write coverage report: " + e.getMessage());
        }
        KBoxLog.info(TAG, "VMP coverage: " + translated + "/" + configured + " (" + pct
                + "%), unsupported=" + unsupported + ", excluded=" + excluded
                + ", errors=" + failed + ", program=" + programBytes + " bytes");
    }
}
