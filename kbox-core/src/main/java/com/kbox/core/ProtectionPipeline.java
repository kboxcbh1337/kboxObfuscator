package com.kbox.core;

import com.kbox.core.analysis.AutoKeepDeriver;
import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.analysis.DependencyAnalyzer;
import com.kbox.core.analysis.ReflectionScanner;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.controlflow.ControlFlowObfuscator;
import com.kbox.core.jnic.JnicOrchestrator;
import com.kbox.core.kotlin.KotlinMetadataFixer;
import com.kbox.core.log.KBoxLog;
import com.kbox.core.name.Mapping;
import com.kbox.core.name.NameObfuscator;
import com.kbox.core.packaging.Packager;
import com.kbox.core.resource.ResourceEncryptor;
import com.kbox.core.resource.ResourceMapping;
import com.kbox.core.resource.ResourceNameObfuscator;
import com.kbox.core.stringenc.StringEncryptor;
import com.kbox.core.vmp.VmpMethodInjector;
import com.kbox.core.vmp.VmpTranslator;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Top-level orchestrator. Runs the full pipeline against one input jar and
 * produces one protected output jar (+ optional native lib):
 *
 * <pre>
 *   analyze -> reflection scan -> JNIC (build lib) -> control flow ->
 *   string encrypt -> VMP -> rename -> anti-analysis -> resource obf -> package
 * </pre>
 *
 * <p>Each stage reports detailed progress via {@link KBoxLog#stage(int, int, String)}
 * and {@link KBoxLog#progress(int, String)}, so both CLI and GUI can show
 * real-time progress bars and detailed diagnostics.
 *
 * <p>Order rationale:
 * <ul>
 *   <li>JNIC before renaming so the generated JNI symbol names match the
 *       original class/method names (the JVM resolves
 *       {@code Java_pkg_Class_method} from the Java declaration).</li>
 *   <li>Control-flow before string encryption so opaque-predicate / flattened
 *       branches can't be trivially stripped by inspecting string callsites.</li>
 *   <li>VMP after control-flow so the dispatcher logic we run is already obfuscated.</li>
 *   <li>Rename last so all prior passes can resolve original names cheaply.</li>
 * </ul>
 *
 * Methods that fail VMP translation are silently skipped (they keep their
 * obfuscated Java body); methods that fail JNIC translation are silently
 * skipped (they keep their body and go through the obfuscation pipeline).
 */
public final class ProtectionPipeline {

    private static final String TAG = "pipeline";
    private static final int TOTAL_STAGES = 23;

    private final Path inputJar;
    private final Path outputJar;
    private final ProtectionConfig cfg;
    private final Path workDir;

    public ProtectionPipeline(Path inputJar, Path outputJar, ProtectionConfig cfg, Path workDir) {
        this.inputJar = inputJar;
        this.outputJar = outputJar;
        this.cfg = cfg;
        this.workDir = workDir;
    }

    public void run() throws IOException {
        Files.createDirectories(workDir);
        long startMs = System.currentTimeMillis();
        KBoxLog.info(TAG, "========================================================");
        KBoxLog.info(TAG, "KBox Obfuscator — ZKM-level + JNIC + VMP protection");
        KBoxLog.info(TAG, "========================================================");
        KBoxLog.info(TAG, "Input jar:  " + inputJar);
        KBoxLog.info(TAG, "Output jar: " + outputJar);
        KBoxLog.info(TAG, "Work dir:   " + workDir);
        KBoxLog.info(TAG, "Config: " + cfg);
        KBoxLog.info(TAG, "--------------------------------------------------------");
        printFeatureSummary();

        int stage = 0;

        // ---- Stage 1: Analyze ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Class & resource analysis");
        long t0 = System.currentTimeMillis();
        DependencyAnalyzer analyzer = new DependencyAnalyzer();
        ClassGraph graph = analyzer.analyze(inputJar);
        long analyzeMs = System.currentTimeMillis() - t0;
        int totalClasses = graph.getClasses().size();
        int totalResources = graph.getResources().size();
        KBoxLog.progress(100, "Loaded " + totalClasses + " classes, "
                + totalResources + " resources (" + analyzeMs + "ms)");
        KBoxLog.info(TAG, "  Classes: " + totalClasses);

        // ---- Stage 1a: Auto Minecraft mod adaptation (explicit opt-in) ----
        // Detect the loader from the jar metadata (fabric.mod.json / mods.toml /
        // plugin.yml / TweakClass / mixins.json) and seed keep + resource rules
        // so the mod's entry points survive obfuscation without manual config.
        if (cfg.isAutoAdaptMinecraft()) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "Auto Minecraft mod adaptation");
            try {
                com.kbox.core.minecraft.MinecraftModDetector detector =
                        new com.kbox.core.minecraft.MinecraftModDetector(graph, cfg);
                com.kbox.core.minecraft.MinecraftModDetector.Result mc = detector.detect();
                if (mc.isMod()) {
                    detector.apply(mc);
                    KBoxLog.info(TAG, "  Auto-adapting to " + mc.loader
                            + " (" + mc.entryClasses.size() + " entry classes kept)");
                } else {
                    KBoxLog.info(TAG, "  No Minecraft mod loader detected — skipping adaptation");
                }
            } catch (Exception e) {
                KBoxLog.warn(TAG, "Minecraft auto-adaptation failed: " + e.getMessage()
                        + " (continuing without)");
            }
        }

        // ---- Stage 1b: Mixin config analysis ----
        // Parse mixins.*.json and @Mixin annotations to protect the full
        // Mixin ecosystem BEFORE any transformation runs. Without this, the
        // obfuscator corrupts Mixin target classes (e.g. leader.event.rd),
        // causing VerifyError: "Bad type on operand stack" when Mixin's
        // runtime injector processes corrupted bytecode.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Mixin config analysis");
        com.kbox.core.analysis.MixinConfigParser.Result mixinResult =
                com.kbox.core.analysis.MixinConfigParser.parse(graph);
        // Add mixin classes and their targets to keepPrefixes so isKept()
        // returns true for them, causing shouldTransform() to skip ALL
        // bytecode transformations (control flow, string encrypt, etc.).
        for (String c : mixinResult.mixinClasses) {
            cfg.getKeepPrefixes().add(c.replace('/', '.'));
        }
        for (String c : mixinResult.targetClasses) {
            cfg.getKeepPrefixes().add(c.replace('/', '.'));
        }
        // Seed keepMembers with the exact method signatures that Mixin
        // injects into. This ensures the NameObfuscator does not rename
        // these methods (which would break @Inject method target resolution).
        for (String sig : mixinResult.targetMethodSigs) {
            cfg.getKeepMembers().add(sig);
        }
        if (!mixinResult.mixinClasses.isEmpty()) {
            KBoxLog.info(TAG, "  Mixin protection: " + mixinResult.mixinClasses.size()
                    + " mixin classes, " + mixinResult.targetClasses.size()
                    + " target classes, " + mixinResult.targetMethodSigs.size()
                    + " method signatures locked");
        }
        KBoxLog.info(TAG, "  Resources: " + totalResources);
        if (graph.isSpringBootFatJar()) {
            KBoxLog.info(TAG, "  Spring Boot Fat Jar detected");
        }

        // ---- Stage 2: Reflection scan ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Reflection scan (keep-set seeding)");
        new ReflectionScanner().scan(graph);

        // ---- Stage 3: Auto keep-rule derivation ----
        // Runs after the reflection scan so we can build on top of the seeded
        // keep-set. Derives keep rules for Serializable fields, framework
        // annotations, native methods, ServiceLoader entries, and class-name
        // shaped string constants — the equivalent of ProGuard's -keep inference
        // plus Spring/Hibernate/Jackson component-scan rules, but automatic.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Auto keep-rule derivation (adaptive)");
        if (cfg.isAutoKeepRules()) {
            new AutoKeepDeriver(graph, cfg).derive();
        } else {
            KBoxLog.info(TAG, "  Auto keep-rule derivation disabled (autoKeepRules=false)");
        }

        // ---- Stage 5b: Native annotation scan ----
        // Runs after auto-keep so keep rules are already established for
        // annotated classes. Scans @Native/@NotNative annotations and seeds
        // the nativeMethods config.
        KBoxLog.stage(++stage, TOTAL_STAGES, "@Native/@NotNative annotation scan");
        new com.kbox.core.analysis.NativeAnnotationScanner(graph, cfg).scan();

        // ---- Stage 6: Auto JNIC/VMP method selection ----
        // Runs BEFORE control-flow obfuscation so instruction counts are
        // based on the original (small) methods.  Keys will be remapped
        // after identifier renaming so JNIC uses the final class names.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Auto JNIC/VMP method selection");
        new com.kbox.core.analysis.AutoJnicVmpSelector(graph, cfg).select();

        // ---- Stage 6: Control-flow obfuscation (ZKM-style) ----
        // Must run BEFORE JNIC so the obfuscated Java is what gets translated
        // to C. Also runs before VMP so VMP-dispatched code is already obscured.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Control-flow obfuscation");
        new ControlFlowObfuscator(graph, cfg).obfuscate();

        // ---- Stage 6b: Method inlining/extraction ----
        // Breaks method boundaries to foil decompiler method-graph analysis.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Method inlining / extraction");
        new com.kbox.core.obfu.MethodObfuscator(graph, cfg).apply();

        // ---- Stage 6c: Annotation erasure ----
        // Strips runtime annotations (except framework-critical ones) to remove
        // semantic metadata useful to reverse engineers.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Annotation erasure");
        new com.kbox.core.obfu.AnnotationEraser(graph, cfg).apply();

        // ---- Stage 6d: Call-graph hiding ----
        // Injects dead-code decoy calls to obscure the true call graph.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Call-graph hiding");
        new com.kbox.core.obfu.CallGraphHider(graph, cfg).apply();

        // ---- Stage 6e: Debug-info forging ----
        // Injects fake local-variable metadata to mislead decompilers.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Debug-info forging");
        new com.kbox.core.obfu.DebugInfoForger(graph, cfg).apply();

        // ---- Stage 6f: L3 type confusion ----first
        // Opt-in high-risk transforms: locals cross-type reuse + exception arg
        // relay + reflection redirection. Runs BEFORE const-obf so it sees the
        // original (non-indirect) int literals and its verifier-safe relays can
        // be serialized cleanly. Safely no-ops unless typeConfusion>0.
        KBoxLog.stage(++stage, TOTAL_STAGES, "L3 type confusion");
        new com.kbox.core.obfu.TypeConfusionObfuscator(graph, cfg).apply();

        // ---- Stage 6g: Constant obfuscation ----
        // Replaces magic-number int constants with an indirect runtime lookup,
        // raising the cost of static analysis (constants no longer appear inline).
        KBoxLog.stage(++stage, TOTAL_STAGES, "Constant obfuscation");
        new com.kbox.core.obfu.ConstantObfuscator(graph, cfg).apply();

        // ---- Stage 7: Identifier renaming ----
        // MUST run BEFORE JNIC so the native DLL's JNI_OnLoad uses the
        // renamed class names in FindClass/RegisterNatives.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Identifier renaming");
        NameObfuscator nameObfuscator = new NameObfuscator(graph, cfg);
        Mapping mapping = nameObfuscator.compute();
        Map<String, String> classMap = mapping.getClassMap();
        KBoxLog.info(TAG, "  Renamed " + classMap.size() + " classes");

        // ---- Stage 8: Kotlin metadata fixup ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Kotlin @Metadata fixup");
        new KotlinMetadataFixer(graph, cfg).fix(mapping);

        // Apply renames to every class via ClassRemapper.
        KBoxLog.progress(33, "Applying renames via ClassRemapper");
        Map<String, ClassNode> remappedClasses = new HashMap<>();
        int renameIdx = 0;
        int renameTotal = graph.getClasses().size();
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            ClassNode remapped = nameObfuscator.apply(e.getValue());
            remappedClasses.put(mapping.mapClass(e.getKey()), remapped);
            renameIdx++;
            if (renameTotal > 100 && renameIdx % (renameTotal / 10 + 1) == 0) {
                KBoxLog.progress(33 + (66 * renameIdx / renameTotal),
                        "Remapped " + renameIdx + "/" + renameTotal + " classes");
            }
        }
        graph.getClasses().clear();
        graph.getClasses().putAll(remappedClasses);
        KBoxLog.progress(100, "All classes remapped (" + renameTotal + " total)");

        // Remap JNIC/VMP method keys to use renamed class names so
        // JNI_OnLoad's FindClass uses the post-rename class name.
        remapNativeMethodKeys(cfg, mapping);

        // ---- Stage 10: JNIC (Java→Native translation) ----
        // Runs AFTER control-flow obfuscation AND identifier renaming (so
        // FindClass/RegisterNatives uses the renamed class name), and BEFORE VMP.
        KBoxLog.stage(++stage, TOTAL_STAGES, "JNIC (Java→Native translation)");
        JnicOrchestrator jnic = new JnicOrchestrator(graph, cfg);
        JnicOrchestrator.Result jnicResult = jnic.run(workDir);
        if (!cfg.isEnableJnic()) {
            KBoxLog.info(TAG, "  JNIC disabled, skipping");
        } else {
            KBoxLog.info(TAG, "  Native library: " + jnicResult.libraryPath);
            if (jnicResult.packedBlob != null) {
                KBoxLog.info(TAG, "  Native blob (packed): " + jnicResult.packedBlob.length + " bytes");
            }
            if (!jnicResult.failed.isEmpty()) {
                KBoxLog.warn(TAG, "  JNIC fall-backs (" + jnicResult.failed.size() + "):");
                for (Map.Entry<String, String> e : jnicResult.failed.entrySet()) {
                    KBoxLog.warn(TAG, "    " + e.getKey() + " -> " + e.getValue());
                }
            }
        }

        // ---- Stage 10b: Native crypto (master-key derivation layer) ----
        // Compiles + packs the optional native HKDF / decrypt-erase library so the
        // hardware-bound master key is derived off the Java heap. Purely additive:
        // a null result simply means the runtime uses the byte-identical Java HKDF.
        byte[] nativeCryptoBlob = com.kbox.core.jnic.NativeCryptoBuilder.build(workDir, cfg);
        if (nativeCryptoBlob == null) {
            KBoxLog.info(TAG, "  Native crypto layer inactive (Java HKDF fallback)");
        } else {
            KBoxLog.info(TAG, "  Native crypto blob (packed): " + nativeCryptoBlob.length + " bytes");
        }

        // ---- Stage 8: String encryption ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "String encryption");
        if (cfg.getStringEncryptionStrength() >= 3) {
            KBoxLog.info(TAG, "  Mode: AES-256-CTR (per-string IV, centralized decryptor, lazy cache)");
            new com.kbox.core.stringenc.AesStringEncryptor(graph, cfg).apply();
        } else if (cfg.isWhiteboxStrings()) {
            KBoxLog.info(TAG, "  Mode: white-box (lookup-table decryption)");
            new com.kbox.core.stringenc.WhiteboxStringEncryptor(graph, cfg).apply();
        } else if (cfg.isScatterStrings() && cfg.isEncryptStrings()) {
            KBoxLog.info(TAG, "  Mode: scattered (inline decryption, 8 holders x 256 fields)");
            new com.kbox.core.stringenc.StringScatterer(graph, cfg).apply();
        } else {
            KBoxLog.info(TAG, "  Mode: " + (cfg.isEncryptStrings() ? "centralized XOR/AES" : "disabled"));
            new StringEncryptor(graph, cfg).encrypt();
        }

        // ---- Stage 9: VMP injection (Virtual Machine Protection) ----
        // Runs AFTER JNIC so VMP only processes methods that were NOT
        // sunk to native. This avoids unnecessary VMP on methods that
        // are already compiled to C.
        KBoxLog.stage(++stage, TOTAL_STAGES, "VMP (Virtual Machine Protection)");
        if (cfg.isEnableVmp()) {
            new com.kbox.core.vmp.VmpRuntimeProtector(graph, cfg).load();
            injectVmp(graph);
        } else {
            KBoxLog.info(TAG, "  VMP disabled, skipping");
        }

        // ---- Stage 10: Anti-analysis passes ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Anti-analysis (anti-decompiler + watermark + exception-jump)");
        new com.kbox.core.controlflow.AntiDecompiler(graph, cfg).apply();
        new com.kbox.core.controlflow.Watermarker(graph, cfg).apply();
        new com.kbox.core.controlflow.ExceptionJumpObfuscator(graph, cfg).apply();

        // ---- Stage 12b: Null-guard injection ----
        // Injects null checks after Class.getResourceAsStream() calls so that
        // obfuscated resource paths returning null don't cause downstream NPE.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Null-guard injection (getResourceAsStream safety)");
        new com.kbox.core.controlflow.ResourceNullGuardTransformer(graph, cfg).apply();

        // Mark CF-modified classes: any non-library class whose bytecode was
        // potentially altered by control-flow, string encryption, VMP,
        // anti-decompiler, or exception-jump transforms. Classes that only
        // went through ClassRemapper keep their existing StackMapTable frames.
        if (cfg.isObfuscateControlFlow() || cfg.isEncryptStrings()
                || cfg.isScatterStrings() || cfg.isEnableVmp()
                || cfg.getAntiDecompilerLevel() > 0
                || cfg.isExceptionJumpObf() || cfg.isObfuscateConstants()) {
            for (String name : graph.getClasses().keySet()) {
                if (cfg.shouldProtectClass(name)) {
                    graph.markCfModified(name);
                }
            }
        }

        // ---- Stage 13: Resource obfuscation ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Resource obfuscation (rename + encrypt)");
        ResourceMapping resMapping = null;
        byte[] resSeed = null;
        if (cfg.isObfuscateResources()) {
            // Forge/FML uses its own LaunchWrapper ClassLoader chain which
            // bypasses KBox's ResourceGuardClassLoader. Obfuscated resource
            // paths cannot be resolved, leading to NPE at runtime when
            // Class.getResourceAsStream() returns null for renamed resources.
            if (graph.getManifest() != null
                    && new String(graph.getManifest(), StandardCharsets.UTF_8).contains("TweakClass:")) {
                KBoxLog.warn(TAG, "obfuscateResources disabled: Forge/FML uses its own "
                        + "ClassLoader chain which cannot resolve KBox-obfuscated "
                        + "resource paths. Use obfuscateResources only with standalone jars.");
            } else {
                KBoxLog.progress(25, "Computing resource name mapping");
                resMapping = new ResourceNameObfuscator(graph, cfg).compute();
                KBoxLog.progress(50, "Generating AES-256 seed");
                resSeed = ResourceEncryptor.newSeed();
                KBoxLog.progress(75, "Encrypting resource bodies");
                new ResourceEncryptor(graph, cfg, resSeed).apply(resMapping);
                KBoxLog.progress(100, "Resource obfuscation complete");
            }
        } else {
            KBoxLog.info(TAG, "  Resource obfuscation disabled, skipping");
        }

        // ---- Stage 14: Packaging ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Packaging (write jar + inject runtime + integrity hash)");
        Packager packager = new Packager();
        packager.write(inputJar, outputJar, graph, mapping, jnicResult.libraryPath,
                jnicResult.packedBlob, nativeCryptoBlob, cfg, resMapping, resSeed);

        // ---- Stage 14b: Deobfuscation mapping output ----
        // When mappingFile is configured, emit a ProGuard-compatible mapping so
        // stack traces can be de-obfuscated. Runs after packaging so the final
        // class/resource names are captured.
        if (cfg.getMappingFile() != null && !cfg.getMappingFile().isEmpty()) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "Deobfuscation mapping output");
            com.kbox.core.name.MappingWriter.write(mapping, cfg, resMapping);
        }

        // ---- Stage 15: Done ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Complete");
        long totalMs = System.currentTimeMillis() - startMs;
        KBoxLog.info(TAG, "========================================================");
        KBoxLog.info(TAG, "Protection complete in " + (totalMs / 1000.0) + "s");
        KBoxLog.info(TAG, "Output: " + outputJar);
        KBoxLog.info(TAG, "========================================================");
        KBoxLog.complete("Done in " + (totalMs / 1000.0) + "s — " + totalClasses + " classes protected");
    }

    /** Prints a summary of which features are enabled/disabled. */
    private void printFeatureSummary() {
        KBoxLog.info(TAG, "Feature summary:");
        KBoxLog.info(TAG, "  [x] Rename identifiers:     " + cfg.isRenameIdentifiers());
        KBoxLog.info(TAG, "  [x] Whitebox/strings:     " + (cfg.isWhiteboxStrings() ? "whitebox"
                + (cfg.isObfuscateConstants() ? "+const-obf" : "") : cfg.isEncryptStrings() ? "on" : "off"));
        KBoxLog.info(TAG, "  [x] Control-flow obf:       " + cfg.isObfuscateControlFlow()
                + " (strength=" + cfg.getControlFlowStrength() + ")");
        KBoxLog.info(TAG, "  [x] Class encryption:       " + cfg.isEncryptClasses()
                + (cfg.isEncryptClasses() ? " (AES-256-GCM, anti-dump)" : ""));
        KBoxLog.info(TAG, "  [x] VMP:                    " + cfg.isEnableVmp());
        KBoxLog.info(TAG, "  [x] JNIC:                   " + cfg.isEnableJnic());
        KBoxLog.info(TAG, "  [x] Resource obfuscation:   " + cfg.isObfuscateResources());
        KBoxLog.info(TAG, "  [x] Kotlin metadata fix:   " + cfg.isFixKotlinMetadata());
        KBoxLog.info(TAG, "  [x] Anti-decompiler level: " + cfg.getAntiDecompilerLevel()
                + (cfg.getAntiDecompilerLevel() >= 3 ? " (max: goto-chain+ex-bomb+inner-cycle+cp-bomb)"
                    : cfg.getAntiDecompilerLevel() >= 2 ? " (medium: goto-chain+ex-bomb+inner-cycle)"
                    : cfg.getAntiDecompilerLevel() >= 1 ? " (light: goto-chain)"
                    : " (disabled)"));
        KBoxLog.info(TAG, "  [x] Anti-debug:            " + cfg.isAntiDebug()
                + (cfg.isAntiDebug() ? " (JDWP/JVMTI/timing/attach detection)" : ""));
        KBoxLog.info(TAG, "  [x] VMP self-check:        " + cfg.isVmpSelfCheck());
        KBoxLog.info(TAG, "  [x] Watermark:             " + (cfg.getWatermark() != null ? "'" + cfg.getWatermark() + "'" : "(none)"));
        KBoxLog.info(TAG, "  [x] Integrity check:      " + cfg.isIntegrityCheck()
                + (cfg.isIntegrityCheck() ? " (SHA-256, anti-repackage)" : ""));
        KBoxLog.info(TAG, "  [x] Exception-jump obf:    " + cfg.isExceptionJumpObf());
        KBoxLog.info(TAG, "  [x] Native anti-hook:      " + cfg.isNativeAntiHook()
                + (cfg.isNativeAntiHook() ? " (entry integrity + env scrub)" : ""));
        KBoxLog.info(TAG, "  [x] Null-guard:            " + cfg.isNullGuard()
                + (cfg.isNullGuard() ? " (getResourceAsStream NPE prevention)" : ""));
        KBoxLog.info(TAG, "  [x] Keep prefixes:         " + cfg.getKeepPrefixes());
        KBoxLog.info(TAG, "--------------------------------------------------------");
    }

    /** Translates & injects VMP code for every configured vmpMethod that is supported. */
    @SuppressWarnings("unchecked")
    private void injectVmp(ClassGraph graph) {
        VmpMethodInjector injector = new VmpMethodInjector();
        Map<String, VmpTranslator.Result> perMethod = new HashMap<>();
        int total = cfg.getVmpMethods().size();
        int idx = 0;
        KBoxLog.info(TAG, "  VMP methods to find: " + total
                + " keys: " + new ArrayList<>(cfg.getVmpMethods()));
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            ClassNode cn = e.getValue();
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                String key = ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
                boolean isVmp = cfg.getVmpMethods().contains(key);
                if (isVmp) {
                    KBoxLog.debug(TAG, "  VMP MATCH: " + key + " -> " + cn.name + "." + mn.name + mn.desc);
                }
                if (!isVmp) continue;
                if (!VmpTranslator.isSupported(mn)) {
                    KBoxLog.warn("vmp", "Method not VMP-supported: " + key + " (falling back)");
                    continue;
                }
                try {
                    VmpTranslator.Result r = VmpTranslator.translate(mn);

                    // Apply post-translation obfuscation passes (dead-branch injection).
                    // The pipeline is gated on obfuscateControlFlow and only applies the
                    // stack-safe bogus pass; flatten/substitute are disabled because they
                    // corrupt VMP bytecode (see VmpPassPipeline.apply javadoc).
                    try {
                        com.kbox.core.vmp.VmpPassPipeline.Result passes =
                                com.kbox.core.vmp.VmpPassPipeline.apply(
                                        r.code, r.exceptions, cfg.isObfuscateControlFlow());

                        // SMT verification: check equivalence of original vs transformed.
                        try {
                            com.kbox.core.verification.SmtVerifier.verify(
                                    "vmp-passes", r.code, passes.code);
                        } catch (Exception smtEx) {
                            KBoxLog.warn("vmp", "SMT verification skipped: " + smtEx.getMessage());
                        }

                        // Rebuild the result with the transformed code. The bogus pass adds
                        // dead-branch instructions, so recompute maxLocals from the
                        // transformed code to keep the interpreter's locals[] allocation safe.
                        int newMaxLocals = com.kbox.core.vmp.VmpPassPipeline
                                .computeMaxLocals(passes.code);
                        r = new VmpTranslator.Result(passes.code, r.cpRaw,
                                Math.max(r.maxLocals, newMaxLocals), r.maxStack, r.argCount,
                                passes.exceptions, r.retSort);
                    } catch (Exception passEx) {
                        KBoxLog.warn("vmp", "VMP passes failed for " + key
                                + ": " + passEx.getMessage() + " (using original code)");
                    }

                    perMethod.put(cn.name + "#" + mn.name + "#" + mn.desc, r);
                    idx++;
                    KBoxLog.progress(100 * idx / Math.max(total, 1),
                            "Translated " + idx + "/" + total + ": " + key);
                } catch (Exception ex) {
                    KBoxLog.warn("vmp", "VMP translate failed for " + key + ": " + ex.getMessage());
                }
            }
        }
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            injector.rewrite(e.getValue(), perMethod);
        }
        KBoxLog.info(TAG, "  VMP: " + perMethod.size() + " methods injected");
    }

    /**
     * Remaps native/VMP method keys after identifier renaming.  Keys are stored
     * in {@code owner#name#desc} format (see {@code ProtectionConfig.memberKey}).
     * This rewrites both owner and method name using the mapping so that
     * JNI_OnLoad's FindClass finds the renamed class and method.
     */
    private static void remapNativeMethodKeys(com.kbox.core.config.ProtectionConfig cfg,
                                              Mapping mapping) {
        Map<String, String> classMap = mapping.getClassMap();
        if (classMap.isEmpty()) return;

        KBoxLog.debug(TAG, "  remapNativeMethodKeys: classMap has " + classMap.size() + " entries");

        List<String> oldNative = new ArrayList<>(cfg.getNativeMethods());
        cfg.getNativeMethods().clear();
        for (String key : oldNative) {
            // key format: owner#name#desc
            int hash1 = key.indexOf('#');
            if (hash1 <= 0) { cfg.getNativeMethods().add(key); continue; }
            String oldOwner = key.substring(0, hash1);
            String rest = key.substring(hash1 + 1); // "name#desc"
            int hash2 = rest.indexOf('#');
            if (hash2 <= 0) { cfg.getNativeMethods().add(key); continue; }
            String oldName = rest.substring(0, hash2);
            String desc = rest.substring(hash2 + 1); // desc

            String newOwner = classMap.getOrDefault(oldOwner.replace('.', '/'), oldOwner).replace('/', '.');
            String newName = mapping.mapMethod(oldOwner.replace('.', '/'), oldName, desc);

            String newKey = newOwner + "#" + newName + "#" + desc;
            KBoxLog.debug(TAG, "  remap native: " + key + " -> " + newKey);
            cfg.getNativeMethods().add(newKey);
        }

        List<String> oldVmp = new ArrayList<>(cfg.getVmpMethods());
        cfg.getVmpMethods().clear();
        for (String key : oldVmp) {
            int hash1 = key.indexOf('#');
            if (hash1 <= 0) { cfg.getVmpMethods().add(key); continue; }
            String oldOwner = key.substring(0, hash1);
            String rest = key.substring(hash1 + 1);
            int hash2 = rest.indexOf('#');
            if (hash2 <= 0) { cfg.getVmpMethods().add(key); continue; }
            String oldName = rest.substring(0, hash2);
            String desc = rest.substring(hash2 + 1);

            String newOwner = classMap.getOrDefault(oldOwner.replace('.', '/'), oldOwner).replace('/', '.');
            String newName = mapping.mapMethod(oldOwner.replace('.', '/'), oldName, desc);
            String newKey = newOwner + "#" + newName + "#" + desc;
            KBoxLog.debug(TAG, "  remap vmp: " + key + " -> " + newKey);
            cfg.getVmpMethods().add(newKey);
        }
    }
}
