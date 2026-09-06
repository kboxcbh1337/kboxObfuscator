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
 *   bfvmMethod = com.example.License#check(Ljava/lang/String;)Z
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
            boolean first = true;
            while ((line = r.readLine()) != null) {
                ln++;
                if (first) {
                    first = false;
                    // Strip a leading UTF-8 BOM (common when configs are saved by
                    // Windows editors / PowerShell), which String.trim() does NOT
                    // remove (\uFEFF > U+0020).
                    if (!line.isEmpty() && line.charAt(0) == '\uFEFF') {
                        line = line.substring(1);
                    }
                }
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) continue;
                // Strip inline comments (" ... # ..." / " ... ; ..."). Only
                // removed when preceded by a space so values containing '#' (rare
                // like hex secrets) are left intact when not spaced.
                int ci = indexOfInlineComment(t);
                String body = (ci < 0) ? t : t.substring(0, ci);
                int eq = body.indexOf('=');
                if (eq < 0) {
                    throw new KBoxException("Config line " + ln + " has no '=': " + line);
                }
                String key = body.substring(0, eq).trim();
                String val = body.substring(eq + 1).trim();
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
            // 一键全开（最大强度预设，可开关）。放在文件前部，后续行可覆盖单键。
            case "allMax":
                if (bool(val)) cfg.applyMaxStrength();
                break;
            case "renameIdentifiers": cfg.setRenameIdentifiers(bool(val)); break;
            case "encryptStrings": cfg.setEncryptStrings(bool(val)); break;
            case "obfuscateControlFlow": cfg.setObfuscateControlFlow(bool(val)); break;
            case "obfuscateEntryPoint": cfg.setObfuscateEntryPoint(bool(val)); break;
            case "encryptClasses": cfg.setEncryptClasses(bool(val)); break;
            case "enableVmp": cfg.setEnableVmp(bool(val)); break;
            case "enableBfvm": cfg.setEnableBfvm(bool(val)); break;
            case "vmpInterleave": cfg.setVmpInterleave(Integer.parseInt(val)); break;
            case "brainfuckShield": cfg.setBrainfuckShield(bool(val)); break;
            case "brainfuckShieldLevel": cfg.setBrainfuckShieldLevel(Integer.parseInt(val)); break;
            case "reflectionGate": cfg.setReflectionGate(bool(val)); break;
            case "enableVmpNative": cfg.setEnableVmpNative(bool(val)); break;
            case "enableJnic": cfg.setEnableJnic(bool(val)); break;
            case "obfuscateResources": cfg.setObfuscateResources(bool(val)); break;
            case "brainfuckLoader": cfg.setBrainfuckLoader(bool(val)); break;
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
            case "mbaConstants": cfg.setMbaConstants(Integer.parseInt(val.trim())); break;
            case "honeypot": cfg.setHoneypotLevel(Integer.parseInt(val.trim())); break;
            case "opaqueStateMachine": cfg.setOpaqueStateMachine(Integer.parseInt(val.trim())); break;
            case "blobMockFill": cfg.setBlobMockFill(Integer.parseInt(val.trim())); break;
            case "methodSplit": cfg.setMethodSplit(Integer.parseInt(val.trim())); break;
            case "sentinelInterleave": cfg.setSentinelInterleave(Integer.parseInt(val.trim())); break;
            case "stackFrameRedirect": cfg.setStackFrameRedirect(Integer.parseInt(val.trim())); break;
            case "entropyTimeAnchor": cfg.setEntropyTimeAnchor(Integer.parseInt(val.trim())); break;
            case "selfWipeSections": cfg.setSelfWipeSections(Integer.parseInt(val.trim())); break;
            case "processHeartbeat": cfg.setProcessHeartbeat(Integer.parseInt(val.trim())); break;
            case "honeypotPe": cfg.setHoneypotPe(Integer.parseInt(val.trim())); break;
            case "oneTimeSemantic": cfg.setOneTimeSemantic(Integer.parseInt(val.trim())); break;
            case "lineageChain": cfg.setLineageChain(Integer.parseInt(val.trim())); break;
            case "selfRefAuth": cfg.setSelfRefAuth(Integer.parseInt(val.trim())); break;
            case "multiRep": cfg.setMultiRep(Integer.parseInt(val.trim())); break;
            case "polyGold": cfg.setPolyGold(Integer.parseInt(val.trim())); break;
            case "signalPoison": cfg.setSignalPoison(Integer.parseInt(val.trim())); break;
            case "buildSigBind": cfg.setBuildSigBind(Integer.parseInt(val.trim())); break;
            case "typeConfusion": cfg.setTypeConfusionStrength(Integer.parseInt(val.trim())); break;
            case "parallelThreads": cfg.setParallelThreads(Integer.parseInt(val)); break;
            case "gpuAccel": cfg.setGpuAccel(bool(val)); break;
            case "mappingFile": cfg.setMappingFile(val); break;
            case "useMapping": cfg.setUseMapping(val.trim()); break;
            case "silentShield": cfg.setSilentShield(bool(val)); break;
            case "silentShieldReport": cfg.setSilentShieldReport(val); break;
            case "modernStackAdapt": cfg.setModernStackAdapt(bool(val)); break;
            case "adaptabilityReport": cfg.setAdaptabilityReport(val); break;
            case "controlFlowStrength": cfg.setControlFlowStrength(Integer.parseInt(val)); break;
            case "flattenerMinInsns": case "flattenerMin": cfg.setFlattenerMinInsns(Integer.parseInt(val)); break;
            case "flattenerMaxInsns": case "flattenerMax": cfg.setFlattenerMaxInsns(Integer.parseInt(val)); break;
            case "stringEncryptionStrength": cfg.setStringEncryptionStrength(Integer.parseInt(val)); break;
            case "jnicEplDriven": cfg.setJnicEplDriven(bool(val)); break;
            case "failOnNativeError": cfg.setFailOnNativeError(bool(val)); break;
            case "nativeCoverage": cfg.setJnicFullCoverage(val.trim().equalsIgnoreCase("full")); break;
            case "vmpCoverage": cfg.setVmpFullCoverage(val.trim().equalsIgnoreCase("full")); break;
            case "cc": cfg.setCc(val.isEmpty() ? null : val); break;
            case "nativeShell": cfg.setNativeShell(intVal(val, 0)); break;
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
            case "bfvmMethod": addNormalizedMethod(cfg.getBfvmMethods(), val); break;
            case "nativeEligiblePrefix": addAll(cfg.getNativeEligiblePrefixes(), val); break;
            case "nativeExcludePrefix": addAll(cfg.getNativeExcludePrefixes(), val); break;
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

    private static int intVal(String v, int dflt) {
        try { return Integer.parseInt(v.trim()); } catch (Exception e) { return dflt; }
    }

    /**
     * Find the first inline comment marker ({@code #} or {@code ;}) that is
     * preceded by whitespace. Leading whole-line comment markers are handled
     * by the caller. Returns {@code -1} when there is no inline comment.
     */
    private static int indexOfInlineComment(String s) {
        for (int i = 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c == '#' || c == ';') && Character.isWhitespace(s.charAt(i - 1))) {
                return i;
            }
        }
        return -1;
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
