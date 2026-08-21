package com.kbox.core.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Immutable protection configuration. Built either from the YAML-ish config
 * file (see {@link ConfigLoader}) or programmatically by the CLI/Maven plugin.
 *
 * <p>Every toggle has a safe default so an empty config still produces a
 * working, obfuscated output.
 */
public final class ProtectionConfig {

    /**
     * Obfuscation scope controlling which classes/resources are processed.
     * <ul>
     *   <li>{@link #ALL} - obfuscate all classes and resources</li>
     *   <li>{@link #SELECTIVE} - only obfuscate classes/resources matching the
     *       include patterns</li>
     *   <li>{@link #EXCLUDE} - obfuscate all except those matching the exclude
     *       patterns</li>
     * </ul>
     */
    public enum ObfuscationScope {
        /** Obfuscate all classes and resources. */
        ALL,
        /** Only obfuscate classes/resources matching include patterns. */
        SELECTIVE,
        /** Obfuscate all except those matching exclude patterns. */
        EXCLUDE
    }

    // --- Toggle flags ---
    private boolean renameIdentifiers = true;
    private boolean encryptStrings = true;
    private boolean obfuscateControlFlow = true;
    /** Obfuscate the launcher's entry point: the real Main-Class name stored in
     *  {@code Original-Main-Class} is XOR-masked with a per-build random seed so a
     *  casual manifest/dump inspection can't trivially identify the application's
     *  {@code main()} class. The launcher transparently un-masks it at boot. */
    private boolean obfuscateEntryPoint = true;
    private boolean encryptClasses = false;       // off by default: harder to debug
    private boolean enableVmp = false;            // opt-in: per-method via marker
    private boolean vmpProtectRuntime = false;    // opt-in: VMP-protect runtime decryption methods (experimental)
    private boolean enableJnic = false;           // opt-in: per-method via marker
    private boolean obfuscateResources = false;   // opt-in: rename + encrypt non-class files
    private boolean fixKotlinMetadata = true;     // rewrite Kotlin @Metadata after rename
    /** Auto-detect the Minecraft mod loader and adapt keep/resource rules. */
    private boolean autoAdaptMinecraft = false;

    // --- Anti-analysis toggles ---
    /** 0=off, 1=light, 2=medium, 3=aggressive. Injects goto chains, exception-table
     *  bombs, InnerClasses cycles and a constant-pool bomb that crash/hamper
     *  Recaf, JD-GUI and Bytecode Viewer while staying JVM-legal. */
    private int antiDecompilerLevel = 0;
    /** Insert runtime JDWP/JVMTI/agent + timing checks that silently corrupt state. */
    private boolean antiDebug = false;
    /** Verify the VmpInterpreter class hash at <clinit>; corrupt dispatch on tamper. */
    private boolean vmpSelfCheck = false;
    /** Split each encrypted string across N static fields + inline decrypt. */
    private boolean scatterStrings = false;
    /** Embed a watermark bit string into flattener dispatch IDs + opaque-predicate consts. */
    private String watermark = null;
    /** At boot, hash all .class entries and compare to stored integrity.hash. */
    private boolean integrityCheck = false;
    /** Rewrite simple branches as athrow + catch (degrades decompiler readability). */
    private boolean exceptionJumpObf = false;
    /** Insert a native anti-hook preamble (entry-integrity + LD_PRELOAD check) in JNIC C. */
    private boolean nativeAntiHook = false;
    /** Inject null-guards after Class.getResourceAsStream() calls, replacing null
     *  with an empty ByteArrayInputStream to prevent NPE when resources are renamed. */
    private boolean nullGuard = false;

    // === Advanced transforms (new) ===
    /** Inline small hot methods and split large methods (method inlining/extraction). */
    private boolean methodInlineExtract = false;
    /** Erase runtime-visible annotations except those needed by the framework. */
    private boolean eraseAnnotations = false;
    /** Hide the call graph by rerouting direct calls through synthetic indirection. */
    private boolean hideCallGraph = false;
    /** Inject fake (bogus) local-variable / line-number debug info to mislead decompilers. */
    private boolean fakeDebugInfo = false;
    /** White-box string encryption (single lookup-based decryptor, no key in bytecode). */
    private boolean whiteboxStrings = false;
    /** Indirect-encrypt magic-number int constants via a runtime lookup (const-obfuscation). */
    private boolean obfuscateConstants = false;
    /** Parallel pipeline threads (0 = auto = CPU cores). */
    private int parallelThreads = 0;
    /** Use GPU (Aparapi/OpenCL) for bulk string-encryption when available. */
    private boolean gpuAccel = false;

    /**
     * Optional path to a deobfuscation mapping file (ProGuard-style). When set,
     * the obfuscator writes class/method/field rename mappings plus the resource
     * name mapping to this file after all transforms complete. This lets a
     * release/build pipeline (or an IDE debugger with a mapping-aware stack
     * trace tool) reverse the obfuscation for stack traces and diagnostics.
     * <p>{@code null} (default) means no mapping file is written.
     */
    private String mappingFile = null;

    // --- Strength knobs ---
    /** 1=light, 2=medium, 3=aggressive. Higher means more opaque predicates / bogus branches. */
    private int controlFlowStrength = 2;
    private int stringEncryptionStrength = 1;     // 1=XOR, 2=AES-derive

    // --- Retention / native method selection ---
    /** Class name prefixes that must never be renamed (e.g. application entry points). */
    private final Set<String> keepPrefixes = new HashSet<>();
    /**
     * Class-name prefixes that must be skipped by control-flow obfuscation only.
     * Names/members are STILL renamed and every other body transform still runs;
     * only the flattening/opaque-predicate pass is skipped for these classes.
     * Used for self-hosting, where flattening the engine's own CFG classes
     * corrupts them and breaks COMPUTE_FRAMES at runtime.
     */
    private final Set<String> excludeControlFlowPrefixes = new HashSet<>();
    /** Fully-qualified member specs "owner.name desc" that must be kept. */
    private final Set<String> keepMembers = new HashSet<>();
    /** Methods marked for JNIC native conversion: "owner.name desc". */
    private final Set<String> nativeMethods = new HashSet<>();
    /** JVM platform target for JNI code generation. */
    private com.kbox.core.jnic.JniPlatform jniPlatform = com.kbox.core.jnic.JniPlatform.HOTSPOT;
    /** Methods marked for VMP: "owner.name desc". */
    private final Set<String> vmpMethods = new HashSet<>();
    /** Class name prefixes that are eligible for native conversion (whitelist). */
    private final Set<String> nativeEligiblePrefixes = new HashSet<>();

    // --- Native toolchain ---
    private String cc;            // path to C compiler; null = autodetect

    /** Publisher Ed25519 public key (SPKI hex). When set, the packager embeds it
     *  (masked) into the jar and gates class/VM decryption on a valid license. */
    private String licPublicKey = null;
    /** Hex app-secret from LicGen (matches the signed license). Class/VM keys mix
     *  {@code SHA-256(appSecret)} so a valid license is required to decrypt. */
    private String licAppSecret = null;
    private boolean failOnNativeError = false;  // false => fall back to obfuscation

    /**
     * JNIC auto-coverage mode.
     * <ul>
     *   <li>{@code full}   — select EVERY eligible method (no 50-cap). Maximizes how
     *       much logic is sunk to native; keeps only methods that are genuinely
     *       untranslatable (constructors, keep members, unsupported bytecode).</li>
     *   <li>{@code default} — legacy behavior: cap at the largest 50 methods.</li>
     * </ul>
     * Default is {@code "default"} for backwards compatibility; set to
     * {@code "full"} for maximum JNIC coverage (larger native blob).
     */
    private boolean jnicFullCoverage = false;

    /** VMP auto-coverage mode. {@code full} selects EVERY eligible method (no
     *  30-cap, size window 1..∞) so the entire engine is virtualized; the legacy
     *  default caps at 30 medium-sized (5..50 insn) methods. Set {@code full}
     *  for maximum obfuscation breadth (larger, slower startup). */
    private boolean vmpFullCoverage = false;

    // --- Resource obfuscation ---
    /** Glob patterns (ant-style) of resource paths to encrypt (default: sensitive files only). */
    private final Set<String> encryptResourcePatterns = new HashSet<>();
    /** Glob patterns of resource paths to exclude from renaming entirely. */
    private final Set<String> excludeResourcePatterns = new HashSet<>();

    // --- Anti-Dump (class body encryption) ---
    /** Class-name prefixes eligible for whole-class-file AES-GCM encryption.
     *  Empty = encrypt ALL non-runtime, non-entry classes. */
    private final Set<String> encryptClassPrefixes = new HashSet<>();

    // === Fine-grained file selection ===
    /** Obfuscation scope: ALL = obfuscate everything, SELECTIVE = only obfuscate
     *  listed files, EXCLUDE = obfuscate all except listed files. */
    private ObfuscationScope obfuscationScope = ObfuscationScope.ALL;

    /** Class name patterns to include in selective obfuscation (internal names,
     *  e.g. "com/example/**"). */
    private Set<String> includePatterns = new HashSet<>();

    /** Class name patterns to exclude from obfuscation (internal names,
     *  e.g. "com/example/api/**"). */
    private Set<String> excludePatterns = new HashSet<>();

    /** Resource patterns to include in selective obfuscation. */
    private final Set<String> includeResourcePatterns = new HashSet<>();

    /** Resource patterns to exclude from obfuscation (in addition to
     *  {@link #excludeResourcePatterns}). */
    private final Set<String> excludeResourcePatterns2 = new HashSet<>();

    // === Adaptive library handling (ProGuard-style) ===
    /**
     * Library classifier — distinguishes user code from third-party library
     * code (JDK + common shaded libs). Library classes are never transformed.
     * Never null. The classifier is consulted by every transformation stage
     * via {@link LibraryClassifier#shouldTransform(String, ProtectionConfig)}.
     */
    private final LibraryClassifier libraryClassifier = new LibraryClassifier();

    /**
     * When {@code true} (default), the obfuscator never fails the build:
     * per-class transformation errors are logged and the class is rolled back
     * to its original bytes. Set to {@code false} to abort the build on the
     * first per-class error (advanced debugging only).
     * <p>Equivalent to ProGuard's implicit graceful-degradation behaviour.
     */
    private boolean neverFail = true;

    /**
     * When {@code true} (default), keep the original bytes of any class that
     * fails serialization in the packager. When {@code false}, a class that
     * cannot be serialized is dropped from the output jar (risky).
     */
    private boolean rollbackToOriginalBytes = true;

    /**
     * When {@code true}, the entire package path (directory structure) of
     * each non-kept class is replaced with a random obfuscated package of the
     * same depth. This makes the decompiled directory layout meaningless
     * (e.g. {@code com.example.service.User} -> {@code a.b.c.X}).
     * <p>Default is {@code false} for backwards compatibility (preserves
     * Spring component-scan, resource paths, and SPI lookups that depend on
     * package structure). Enable for maximum-strength, non-Spring apps.
     */
    private boolean renamePackages = false;

    /**
     * When {@code true}, string encryption uses a single fixed XOR key
     * (deterministic) instead of per-string random keys. This trades a bit
     * of cryptographic strength for repeatability, faster startup, and
     * simpler runtime decryption — useful for constrained environments or
     * when deterministic output is desired (e.g. reproducible builds).
     * The key is derived from the watermark + a fixed seed, so the same
     * input + watermark always produces the same encrypted strings.
     * <p>Default is {@code false} (per-string random keys for max strength).
     */
    private boolean fixedXorKey = false;

    /**
     * Attributes to preserve (ProGuard {@code -keepattributes} equivalent).
     * Defaults keep the runtime-relevant attributes. Add to this set via the
     * config file or {@code -keepattributes} CLI flag.
     * <p>Recognized attribute names: {@code Signature}, {@code InnerClasses},
     * {@code EnclosingMethod}, {@code RuntimeVisibleAnnotations},
     * {@code RuntimeInvisibleAnnotations}, {@code RuntimeVisibleParameterAnnotations},
     * {@code AnnotationDefault}, {@code Exceptions}, {@code Deprecated},
     * {@code Synthetic}, {@code ConstantValue}, {@code LocalVariableTable},
     * {@code LineNumberTable}, {@code MethodParameters}, {@code PermittedSubclasses},
     * {@code Record}, {@code Module}.
     */
    private final Set<String> keepAttributes = new HashSet<>();

    /**
     * When {@code true} (default), the auto keep-rule deriver runs after the
     * reflection scan and seeds the keep set with framework annotations,
     * Serializable fields, native methods, ServiceLoader entries, etc. Set to
     * {@code false} to disable auto-derivation (advanced users only).
     */
    private boolean autoKeepRules = true;

    /** Suppress non-error log output (ProGuard {@code -dontnote}). */
    private boolean quiet = false;

    /** Suppress warning log output (ProGuard {@code -dontwarn}). Use with care. */
    private boolean suppressWarnings = false;

    private final List<String> entryPoints = new ArrayList<>(); // main classes / SPI impls

    public boolean isRenameIdentifiers() { return renameIdentifiers; }
    public void setRenameIdentifiers(boolean v) { renameIdentifiers = v; }
    public boolean isEncryptStrings() { return encryptStrings; }
    public void setEncryptStrings(boolean v) { encryptStrings = v; }
    public boolean isObfuscateControlFlow() { return obfuscateControlFlow; }
    public void setObfuscateControlFlow(boolean v) { obfuscateControlFlow = v; }
    public boolean isObfuscateEntryPoint() { return obfuscateEntryPoint; }
    public void setObfuscateEntryPoint(boolean v) { obfuscateEntryPoint = v; }
    public boolean isEncryptClasses() { return encryptClasses; }
    public void setEncryptClasses(boolean v) { encryptClasses = v; }
    public boolean isEnableVmp() { return enableVmp; }
    public void setEnableVmp(boolean v) { enableVmp = v; }
    public boolean isVmpProtectRuntime() { return vmpProtectRuntime; }
    public void setVmpProtectRuntime(boolean v) { vmpProtectRuntime = v; }
    public boolean isEnableJnic() { return enableJnic; }
    public void setEnableJnic(boolean v) { enableJnic = v; }
    public boolean isObfuscateResources() { return obfuscateResources; }
    public void setObfuscateResources(boolean v) { obfuscateResources = v; }
    public boolean isFixKotlinMetadata() { return fixKotlinMetadata; }
    public void setFixKotlinMetadata(boolean v) { fixKotlinMetadata = v; }
    public boolean isAutoAdaptMinecraft() { return autoAdaptMinecraft; }
    public void setAutoAdaptMinecraft(boolean v) { autoAdaptMinecraft = v; }

    public int getAntiDecompilerLevel() { return antiDecompilerLevel; }
    public void setAntiDecompilerLevel(int v) { antiDecompilerLevel = Math.max(0, Math.min(3, v)); }
    public boolean isAntiDebug() { return antiDebug; }
    public void setAntiDebug(boolean v) { antiDebug = v; }
    public boolean isVmpSelfCheck() { return vmpSelfCheck; }
    public void setVmpSelfCheck(boolean v) { vmpSelfCheck = v; }
    public boolean isScatterStrings() { return scatterStrings; }
    public void setScatterStrings(boolean v) { scatterStrings = v; }
    public String getWatermark() { return watermark; }
    public void setWatermark(String v) { watermark = (v == null || v.isEmpty()) ? null : v; }
    public boolean isIntegrityCheck() { return integrityCheck; }
    public void setIntegrityCheck(boolean v) { integrityCheck = v; }
    public boolean isExceptionJumpObf() { return exceptionJumpObf; }
    public void setExceptionJumpObf(boolean v) { exceptionJumpObf = v; }
    public boolean isNativeAntiHook() { return nativeAntiHook; }
    public void setNativeAntiHook(boolean v) { nativeAntiHook = v; }
    public boolean isNullGuard() { return nullGuard; }
    public void setNullGuard(boolean v) { nullGuard = v; }

    public boolean isMethodInlineExtract() { return methodInlineExtract; }
    public void setMethodInlineExtract(boolean v) { methodInlineExtract = v; }
    public boolean isEraseAnnotations() { return eraseAnnotations; }
    public void setEraseAnnotations(boolean v) { eraseAnnotations = v; }
    public boolean isHideCallGraph() { return hideCallGraph; }
    public void setHideCallGraph(boolean v) { hideCallGraph = v; }
    public boolean isFakeDebugInfo() { return fakeDebugInfo; }
    public void setFakeDebugInfo(boolean v) { fakeDebugInfo = v; }
    public boolean isWhiteboxStrings() { return whiteboxStrings; }
    public void setWhiteboxStrings(boolean v) { whiteboxStrings = v; }
    public boolean isObfuscateConstants() { return obfuscateConstants; }
    public void setObfuscateConstants(boolean v) { obfuscateConstants = v; }

    // === L3 type-confusion ===
    /** 0=off, 1=locals only, 2=+exception arg relay, 3=+reflection redirection.
     *  Opt-in (default off) because these are high-risk bytecode rewrites. */
    private int typeConfusionStrength = 0;
    public int getTypeConfusionStrength() { return typeConfusionStrength; }
    public void setTypeConfusionStrength(int v) { typeConfusionStrength = Math.max(0, Math.min(3, v)); }
    public boolean isTypeConfusion() { return typeConfusionStrength > 0; }
    public int getParallelThreads() { return parallelThreads; }
    public void setParallelThreads(int v) { parallelThreads = Math.max(0, v); }
    public boolean isGpuAccel() { return gpuAccel; }
    public void setGpuAccel(boolean v) { gpuAccel = v; }
    public String getMappingFile() { return mappingFile; }
    public void setMappingFile(String v) { mappingFile = (v == null || v.isEmpty()) ? null : v; }

    public int getControlFlowStrength() { return controlFlowStrength; }
    public void setControlFlowStrength(int v) { controlFlowStrength = Math.max(1, Math.min(3, v)); }
    public int getStringEncryptionStrength() { return stringEncryptionStrength; }
    public void setStringEncryptionStrength(int v) { stringEncryptionStrength = Math.max(1, Math.min(3, v)); }

    public Set<String> getKeepPrefixes() { return keepPrefixes; }
    public Set<String> getExcludeControlFlowPrefixes() { return excludeControlFlowPrefixes; }
    /** Returns {@code true} if the given internal class name is excluded from control-flow obfuscation. */
    public boolean isExcludedFromControlFlow(String internalName) {
        if (internalName == null) return false;
        String dotted = internalName.replace('/', '.');
        for (String p : excludeControlFlowPrefixes) {
            if (p == null || p.isEmpty()) continue;
            if (dotted.startsWith(p) || internalName.startsWith(p)) return true;
        }
        return false;
    }
    public Set<String> getKeepMembers() { return keepMembers; }
    public Set<String> getNativeMethods() { return nativeMethods; }
    public com.kbox.core.jnic.JniPlatform getJniPlatform() { return jniPlatform; }
    public void setJniPlatform(com.kbox.core.jnic.JniPlatform v) { jniPlatform = (v == null) ? com.kbox.core.jnic.JniPlatform.HOTSPOT : v; }
    public Set<String> getVmpMethods() { return vmpMethods; }
    public Set<String> getNativeEligiblePrefixes() { return nativeEligiblePrefixes; }
    public List<String> getEntryPoints() { return entryPoints; }
    public Set<String> getEncryptResourcePatterns() { return encryptResourcePatterns; }
    public Set<String> getExcludeResourcePatterns() { return excludeResourcePatterns; }
    public Set<String> getEncryptClassPrefixes() { return encryptClassPrefixes; }

    // --- Fine-grained file selection getters/setters ---
    public ObfuscationScope getObfuscationScope() { return obfuscationScope; }
    public void setObfuscationScope(ObfuscationScope v) {
        this.obfuscationScope = (v == null) ? ObfuscationScope.ALL : v;
    }
    /** Returns the include-pattern set directly so callers may add/remove entries. */
    public Set<String> getIncludePatterns() { return includePatterns; }
    public void setIncludePatterns(Set<String> v) {
        this.includePatterns = (v == null) ? new HashSet<>() : v;
    }
    /** Returns the exclude-pattern set directly so callers may add/remove entries. */
    public Set<String> getExcludePatterns() { return excludePatterns; }
    public void setExcludePatterns(Set<String> v) {
        this.excludePatterns = (v == null) ? new HashSet<>() : v;
    }
    /** Returns the resource include-pattern set directly so callers may add/remove entries. */
    public Set<String> getIncludeResourcePatterns() { return includeResourcePatterns; }
    /** Returns the secondary resource exclude-pattern set directly so callers may add/remove entries. */
    public Set<String> getExcludeResourcePatterns2() { return excludeResourcePatterns2; }

    public String getCc() { return cc; }
    public void setCc(String cc) { this.cc = cc; }

    public String getLicPublicKey() { return licPublicKey; }
    public void setLicPublicKey(String v) { licPublicKey = (v == null || v.isEmpty()) ? null : v; }
    public boolean isLicensed() { return licPublicKey != null; }

    public String getLicAppSecret() { return licAppSecret; }
    public void setLicAppSecret(String v) { licAppSecret = (v == null || v.isEmpty()) ? null : v; }
    public boolean isFailOnNativeError() { return failOnNativeError; }
    public void setFailOnNativeError(boolean v) { failOnNativeError = v; }
    public boolean isJnicFullCoverage() { return jnicFullCoverage; }
    public void setJnicFullCoverage(boolean v) { jnicFullCoverage = v; }
    public boolean isVmpFullCoverage() { return vmpFullCoverage; }
    public void setVmpFullCoverage(boolean v) { vmpFullCoverage = v; }

    // --- Adaptive library handling getters/setters ---
    /** Returns the library classifier (never null). Mutate it to add/override prefixes. */
    public LibraryClassifier getLibraryClassifier() { return libraryClassifier; }
    /** Convenience: true if the class is library code (must not be transformed). */
    public boolean isLibraryClass(String internalName) {
        return libraryClassifier.isLibraryClass(internalName);
    }
    /** Convenience: should the obfuscator transform this class?
     *  Single canonical decision — consults library classifier, keep prefixes,
     *  KBox runtime prefix and the FileSelector. */
    public boolean shouldTransformClass(String internalName) {
        return libraryClassifier.shouldTransform(internalName, this);
    }

    /**
     * Body-protection decision (string encryption / control flow). Kept
     * classes are still protected — only their names are preserved. See
     * {@link com.kbox.core.config.LibraryClassifier#shouldProtect}.
     */
    public boolean shouldProtectClass(String internalName) {
        return libraryClassifier.shouldProtect(internalName, this);
    }

    public boolean isNeverFail() { return neverFail; }
    public void setNeverFail(boolean v) { neverFail = v; }

    public boolean isRenamePackages() { return renamePackages; }
    public void setRenamePackages(boolean v) { renamePackages = v; }

    public boolean isFixedXorKey() { return fixedXorKey; }
    public void setFixedXorKey(boolean v) { fixedXorKey = v; }
    public boolean isRollbackToOriginalBytes() { return rollbackToOriginalBytes; }
    public void setRollbackToOriginalBytes(boolean v) { rollbackToOriginalBytes = v; }
    public Set<String> getKeepAttributes() { return keepAttributes; }
    public boolean isAutoKeepRules() { return autoKeepRules; }
    public void setAutoKeepRules(boolean v) { autoKeepRules = v; }
    public boolean isQuiet() { return quiet; }
    public void setQuiet(boolean v) { quiet = v; }
    public boolean isSuppressWarnings() { return suppressWarnings; }
    public void setSuppressWarnings(boolean v) { suppressWarnings = v; }

    /** Convenience: should a class with this internal name be kept entirely? */
    public boolean isKept(String internalName) {
        String dotted = internalName.replace('/', '.');
        for (String p : keepPrefixes) {
            if (dotted.startsWith(p) || internalName.startsWith(p)) return true;
        }
        return false;
    }

    public ProtectionConfig copy() {
        ProtectionConfig c = new ProtectionConfig();
        c.renameIdentifiers = renameIdentifiers;
        c.encryptStrings = encryptStrings;
        c.obfuscateControlFlow = obfuscateControlFlow;
        c.obfuscateEntryPoint = obfuscateEntryPoint;
        c.encryptClasses = encryptClasses;
        c.enableVmp = enableVmp;
        c.vmpProtectRuntime = vmpProtectRuntime;
        c.enableJnic = enableJnic;
        c.obfuscateResources = obfuscateResources;
        c.fixKotlinMetadata = fixKotlinMetadata;
        c.autoAdaptMinecraft = autoAdaptMinecraft;
        c.antiDecompilerLevel = antiDecompilerLevel;
        c.antiDebug = antiDebug;
        c.vmpSelfCheck = vmpSelfCheck;
        c.scatterStrings = scatterStrings;
        c.watermark = watermark;
        c.integrityCheck = integrityCheck;
        c.exceptionJumpObf = exceptionJumpObf;
        c.nativeAntiHook = nativeAntiHook;
        c.nullGuard = nullGuard;
        c.controlFlowStrength = controlFlowStrength;
        c.stringEncryptionStrength = stringEncryptionStrength;
        c.keepPrefixes.addAll(keepPrefixes);
        c.excludeControlFlowPrefixes.addAll(excludeControlFlowPrefixes);
        c.keepMembers.addAll(keepMembers);
        c.nativeMethods.addAll(nativeMethods);
        c.vmpMethods.addAll(vmpMethods);
        c.nativeEligiblePrefixes.addAll(nativeEligiblePrefixes);
        c.cc = cc;
        c.licPublicKey = licPublicKey;
        c.licAppSecret = licAppSecret;
        c.failOnNativeError = failOnNativeError;
        c.jnicFullCoverage = jnicFullCoverage;
        c.vmpFullCoverage = vmpFullCoverage;
        c.entryPoints.addAll(entryPoints);
        c.encryptResourcePatterns.addAll(encryptResourcePatterns);
        c.excludeResourcePatterns.addAll(excludeResourcePatterns);
        c.encryptClassPrefixes.addAll(encryptClassPrefixes);
        c.obfuscationScope = obfuscationScope;
        c.includePatterns.addAll(includePatterns);
        c.excludePatterns.addAll(excludePatterns);
        c.includeResourcePatterns.addAll(includeResourcePatterns);
        c.excludeResourcePatterns2.addAll(excludeResourcePatterns2);
        // Adaptive library handling state.
        c.neverFail = neverFail;
        c.renamePackages = renamePackages;
        c.fixedXorKey = fixedXorKey;
        c.rollbackToOriginalBytes = rollbackToOriginalBytes;
        c.keepAttributes.addAll(keepAttributes);
        c.autoKeepRules = autoKeepRules;
        c.quiet = quiet;
        c.suppressWarnings = suppressWarnings;
        c.methodInlineExtract = methodInlineExtract;
        c.eraseAnnotations = eraseAnnotations;
        c.hideCallGraph = hideCallGraph;
        c.fakeDebugInfo = fakeDebugInfo;
        c.whiteboxStrings = whiteboxStrings;
        c.obfuscateConstants = obfuscateConstants;
        c.parallelThreads = parallelThreads;
        c.gpuAccel = gpuAccel;
        // Library classifier: clone its prefix sets (the new instance already
        // has the defaults; copy user additions/overrides on top).
        for (String p : libraryClassifier.getUserPrefixes()) {
            c.libraryClassifier.addUserPrefix(p);
        }
        // Re-apply only the user-added library prefixes (defaults already present).
        // We can't distinguish default from user-added, so we copy the entire
        // set — duplicates are harmless (Set semantics).
        for (String p : libraryClassifier.getLibraryPrefixes()) {
            c.libraryClassifier.addLibraryPrefix(p);
        }
        if (!libraryClassifier.isUseDefaultPrefixes()) {
            c.libraryClassifier.clearDefaults();
        }
        return c;
    }

    @Override
    public String toString() {
        return "ProtectionConfig{rename=" + renameIdentifiers + ", strings=" + encryptStrings
                + ", cf=" + obfuscateControlFlow + "(" + controlFlowStrength + ")"
                + ", classEnc=" + encryptClasses + ", vmp=" + enableVmp
                + ", jnic=" + enableJnic + ", native=" + nativeMethods.size()
                + ", resources=" + obfuscateResources
                + ", autoMc=" + autoAdaptMinecraft
                + ", antiDec=" + antiDecompilerLevel + ", antiDbg=" + antiDebug
                + ", vmpChk=" + vmpSelfCheck + ", scatter=" + scatterStrings
                + ", wm=" + (watermark != null) + ", integ=" + integrityCheck
                + ", exJmp=" + exceptionJumpObf + ", ntvHook=" + nativeAntiHook
                + ", nullGuard=" + nullGuard
                + ", keepPrefix=" + keepPrefixes + ", cc=" + cc
                + ", lic=" + isLicensed()
                + ", scope=" + obfuscationScope
                + ", include=" + includePatterns.size()
                + ", exclude=" + excludePatterns.size()
                + ", incRes=" + includeResourcePatterns.size()
                + ", excRes2=" + excludeResourcePatterns2.size()
                + ", neverFail=" + neverFail
                + ", renamePackages=" + renamePackages
                + ", fixedXorKey=" + fixedXorKey
                + ", jnicFull=" + jnicFullCoverage
                + ", autoKeep=" + autoKeepRules
                + ", libPrefixes=" + libraryClassifier.getLibraryPrefixes().size()
                + ", userPrefixes=" + libraryClassifier.getUserPrefixes().size()
                + ", keepAttrs=" + keepAttributes + "}";
    }

    /** Parse a member spec "owner#name#desc" -> trimmed array, or null on bad input. */
    public static String[] parseMemberSpec(String spec) {
        String[] parts = spec.split("#");
        if (parts.length == 3) return parts;
        parts = spec.split("\\s+");
        if (parts.length == 3) return parts;
        return null;
    }

    /** Build a member spec key from ASM-style parts. */
    public static String memberKey(String owner, String name, String desc) {
        return owner.replace('/', '.') + "#" + name + "#" + desc;
    }
}
