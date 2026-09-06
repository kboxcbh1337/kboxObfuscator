package com.kbox.core.name;

import com.kbox.core.log.KBoxLog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Z9 incremental obfuscation: loads a previous {@link MappingWriter} output
 * (ProGuard-compatible {@code Old -> New} mapping) and pre-fills a
 * {@link Mapping} with the CLASS renames, so a class present in both builds
 * keeps the SAME obfuscated name across versions. This is what makes
 * protections reproducible / stack traces debuggable across rebuilds.
 *
 * <p>Only class lines are reused:
 * <pre>
 *   com.example.OriginalClass -> com.example.a:
 * </pre>
 * Member lines are intentionally NOT reused — the member-line format
 * ({@code <returnType> <name> -> <newName>}) is ambiguous between fields and
 * methods, and cannot be resolved to an ASM descriptor without the current
 * class definition. Reusing only the (unambiguous) class names captures the
 * core incremental benefit with zero risk of a mis-renamed member.
 *
 * <p>All failures (missing file, bad syntax) are non-fatal: incremental reuse
 * is a best-effort optimisation and a fresh build never breaks because of it.
 */
public final class MappingLoader {

    private static final String TAG = "mapping-reuse";

    private MappingLoader() {}

    /** Load {@code useMappingPath} into {@code mapping} if set. Best-effort. */
    public static void loadInto(Mapping mapping, String useMappingPath) {
        if (useMappingPath == null || useMappingPath.isEmpty()) return;
        try {
            Path p = Paths.get(useMappingPath);
            if (!Files.exists(p)) {
                KBoxLog.info(TAG, "useMapping file not found, building fresh: " + useMappingPath);
                return;
            }
            int reused = 0;
            for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                if (!t.endsWith(":")) continue;               // only class lines
                int arrow = t.indexOf(" -> ");
                if (arrow < 0) continue;
                String oldDotted = t.substring(0, arrow).trim();
                String newDotted = t.substring(arrow + 4).trim();
                if (newDotted.endsWith(":")) newDotted = newDotted.substring(0, newDotted.length() - 1);
                String oldInternal = oldDotted.replace('.', '/');
                String newInternal = newDotted.replace('.', '/');
                if (!oldInternal.equals(newInternal) && !oldInternal.isEmpty() && !newInternal.isEmpty()) {
                    mapping.mapClass(oldInternal, newInternal);
                    reused++;
                }
            }
            KBoxLog.info(TAG, "Incremental mapping reused " + reused + " class names from "
                    + useMappingPath + (reused == 0 ? " (fresh random names)" : ""));
        } catch (IOException | RuntimeException e) {
            KBoxLog.warn(TAG, "useMapping reuse failed, building fresh: " + e.getMessage());
        }
    }
}