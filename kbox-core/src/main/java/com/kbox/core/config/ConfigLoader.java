package com.kbox.core.config;

import com.kbox.core.KBoxException;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Loads a {@link ProtectionConfig} from a simple, line-oriented text file.
 *
 * <p>The format is intentionally minimal (no external YAML dependency):
 * <pre>
 *   # boolean toggles
 *   renameIdentifiers = true
 *   controlFlowStrength = 2
 *
 *   # retention lists, comma separated
 *   keepPrefix = com.example.api., com.example.Main
 *   nativeMethod = com.example.License#check(Ljava/lang/String;)Z
 *   entryPoint = com.example.Main
 *   cc = C:/msys64/mingw64/bin/gcc.exe
 * </pre>
 *
 * Unknown keys are reported as a warning but do not fail the build.
 */
public final class ConfigLoader {

    private ConfigLoader() {}

    public static ProtectionConfig load(Path file) throws IOException {
        ProtectionConfig cfg = new ProtectionConfig();
        if (file == null || !Files.exists(file)) {
            return cfg; // empty / defaults
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int ln = 0;
            while ((line = r.readLine()) != null) {
                ln++;
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) continue;
                int eq = t.indexOf('=');
                if (eq < 0) {
                    throw new KBoxException("Config line " + ln + " has no '=': " + line);
                }
                String key = t.substring(0, eq).trim();
                String val = t.substring(eq + 1).trim();
                apply(cfg, key, val);
            }
        }
        // Ensure entry points are kept (they hold main()/SPI bootstrap).
        for (String ep : cfg.getEntryPoints()) {
            cfg.getKeepPrefixes().add(ep);
        }
        return cfg;
    }

    private static void apply(ProtectionConfig cfg, String key, String val) {
        switch (key) {
            case "renameIdentifiers": cfg.setRenameIdentifiers(bool(val)); break;
            case "encryptStrings": cfg.setEncryptStrings(bool(val)); break;
            case "obfuscateControlFlow": cfg.setObfuscateControlFlow(bool(val)); break;
            case "obfuscateEntryPoint": cfg.setObfuscateEntryPoint(bool(val)); break;
            case "encryptClasses": cfg.setEncryptClasses(bool(val)); break;
            case "enableVmp": cfg.setEnableVmp(bool(val)); break;
            case "enableJnic": cfg.setEnableJnic(bool(val)); break;
            case "obfuscateResources": cfg.setObfuscateResources(bool(val)); break;
            case "autoAdaptMinecraft": cfg.setAutoAdaptMinecraft(bool(val)); break;
            case "fixKotlinMetadata": cfg.setFixKotlinMetadata(bool(val)); break;
            case "antiDecompilerLevel": cfg.setAntiDecompilerLevel(Integer.parseInt(val)); break;
            case "antiDebug": cfg.setAntiDebug(bool(val)); break;
            case "vmpSelfCheck": cfg.setVmpSelfCheck(bool(val)); break;
            case "scatterStrings": cfg.setScatterStrings(bool(val)); break;
            case "watermark": cfg.setWatermark(val); break;
            case "integrityCheck": cfg.setIntegrityCheck(bool(val)); break;
            case "exceptionJumpObf": cfg.setExceptionJumpObf(bool(val)); break;
            case "nativeAntiHook": cfg.setNativeAntiHook(bool(val)); break;
            case "nullGuard": cfg.setNullGuard(bool(val)); break;
            case "methodInlineExtract": cfg.setMethodInlineExtract(bool(val)); break;
            case "eraseAnnotations": cfg.setEraseAnnotations(bool(val)); break;
            case "hideCallGraph": cfg.setHideCallGraph(bool(val)); break;
            case "fakeDebugInfo": cfg.setFakeDebugInfo(bool(val)); break;
            case "whiteboxStrings": cfg.setWhiteboxStrings(bool(val)); break;
            case "obfuscateConstants": cfg.setObfuscateConstants(bool(val)); break;
            case "typeConfusion": cfg.setTypeConfusionStrength(Integer.parseInt(val.trim())); break;
            case "parallelThreads": cfg.setParallelThreads(Integer.parseInt(val)); break;
            case "gpuAccel": cfg.setGpuAccel(bool(val)); break;
            case "mappingFile": cfg.setMappingFile(val); break;
            case "controlFlowStrength": cfg.setControlFlowStrength(Integer.parseInt(val)); break;
            case "stringEncryptionStrength": cfg.setStringEncryptionStrength(Integer.parseInt(val)); break;
            case "failOnNativeError": cfg.setFailOnNativeError(bool(val)); break;
            case "nativeCoverage": cfg.setJnicFullCoverage(val.trim().equalsIgnoreCase("full")); break;
            case "vmpCoverage": cfg.setVmpFullCoverage(val.trim().equalsIgnoreCase("full")); break;
            case "cc": cfg.setCc(val.isEmpty() ? null : val); break;
            case "licPublicKey": case "licensePublicKey":
                cfg.setLicPublicKey(val.trim()); break;
            case "licAppSecret": case "licenseAppSecret":
                cfg.setLicAppSecret(val.trim()); break;

            // --- Adaptive library handling ---
            case "neverFail": cfg.setNeverFail(bool(val)); break;
            case "renamePackages": cfg.setRenamePackages(bool(val)); break;
            case "fixedXorKey": cfg.setFixedXorKey(bool(val)); break;
            case "rollbackToOriginalBytes": cfg.setRollbackToOriginalBytes(bool(val)); break;
            case "autoKeepRules": cfg.setAutoKeepRules(bool(val)); break;
            case "quiet": cfg.setQuiet(bool(val)); break;
            case "suppressWarnings": cfg.setSuppressWarnings(bool(val)); break;
            case "keepAttributes": addAll(cfg.getKeepAttributes(), val); break;
            case "libraryPrefix":
                for (String p : val.split(",")) cfg.getLibraryClassifier().addLibraryPrefix(p.trim());
                break;
            case "userPrefix":
                for (String p : val.split(",")) cfg.getLibraryClassifier().addUserPrefix(p.trim());
                break;
            case "useDefaultLibraryPrefixes":
                cfg.getLibraryClassifier().setUseDefaultPrefixes(bool(val));
                if (!bool(val)) cfg.getLibraryClassifier().clearDefaults();
                break;

            case "keepPrefix": addAll(cfg.getKeepPrefixes(), val); break;
            case "excludeControlFlow": addAll(cfg.getExcludeControlFlowPrefixes(), val); break;
            case "keepMember": addAll(cfg.getKeepMembers(), val); break;
            case "nativeMethod": addNormalizedMethod(cfg.getNativeMethods(), val); break;
            case "jniPlatform": cfg.setJniPlatform(com.kbox.core.jnic.JniPlatform.fromConfig(val)); break;
            case "vmpMethod": addNormalizedMethod(cfg.getVmpMethods(), val); break;
            case "nativeEligiblePrefix": addAll(cfg.getNativeEligiblePrefixes(), val); break;
            case "entryPoint": cfg.getEntryPoints().add(val); break;
            case "encryptResource": addAll(cfg.getEncryptResourcePatterns(), val); break;
            case "excludeResource": addAll(cfg.getExcludeResourcePatterns(), val); break;
            case "encryptClassPrefix": addAll(cfg.getEncryptClassPrefixes(), val); break;

            default:
                com.kbox.core.log.KBoxLog.warn("config", "Unknown config key '" + key + "' ignored");
        }
    }

    private static boolean bool(String v) {
        return "true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v);
    }

    /**
     * Normalizes user-friendly method specs into internal {@code owner#name#desc} format.
     * Supports both config-file format ({@code com.example.Class.method (I)V}) and
     * already-normalized {@code #}-separated format.
     */
    static void addNormalizedMethod(java.util.Set<String> target, String val) {
        for (String spec : val.split(",")) {
            spec = spec.trim();
            if (spec.isEmpty()) continue;

            // Already in normalized format (owner#name#desc)?
            if (spec.contains("#")) {
                target.add(spec);
                continue;
            }

            // Config format: "com.example.Class.method (L...;)V"
            int lastSpace = spec.lastIndexOf(' ');
            if (lastSpace <= 0) {
                com.kbox.core.log.KBoxLog.warn("config", "Invalid method spec (no space): " + spec);
                continue;
            }
            String desc = spec.substring(lastSpace + 1).trim();
            String ownerMethod = spec.substring(0, lastSpace).trim();

            // Split by last '.' to separate owner from method name
            int lastDot = ownerMethod.lastIndexOf('.');
            if (lastDot <= 0) {
                com.kbox.core.log.KBoxLog.warn("config", "Invalid method spec (no class.method separator): " + spec);
                continue;
            }
            String owner = ownerMethod.substring(0, lastDot).replace('.', '/');
            String name = ownerMethod.substring(lastDot + 1);

            target.add(com.kbox.core.config.ProtectionConfig.memberKey(owner, name, desc));
        }
    }

    private static void addAll(Set<String> target, String csv) {
        for (String p : csv.split(",")) {
            String t = p.trim();
            if (!t.isEmpty()) target.add(t);
        }
    }

    /** Helper for callers that already have a comma list. */
    public static Set<String> splitCsv(String csv) {
        Set<String> out = new LinkedHashSet<>();
        if (csv != null) addAll(out, csv);
        return out;
    }
}
