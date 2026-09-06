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
    private static final int TOTAL_STAGES = 24;

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

        // Native shell hardening (beyond kboxShield): arm the build-time native
        // guards (M1 string erasure, M2 control-flow mutation, vendor-scatter).
        // The static level is read by every native compile path below.
        com.kbox.core.nativeshell.NativeShellGuard.pump(cfg.getNativeShell());

        // ---- Brainfuck chaos mode (brainfuckLoader) ----
        // A standalone opt-in scheme (防内存Dump / 防静态分析): the whole output
        // jar is converted to classes.bf.rle (with an embedded name->(offset,len)
        // index header parsed only in native memory) and reassembled in native
        // memory at startup. It replaces the jar layout, so every feature that
        // depends on plain loadable classes / a guard loader is incompatible and
        // is forced off here (the Java-level passes — control flow, strings,
        // renaming, anti-decompiler — stay fully active).
        // NOTE: these flags are restored if the BF mode later degrades (library/
        // mod/Spring Boot input), so a degraded run keeps full class/resource
        // protection.
        final boolean wantClassEnc = cfg.isEncryptClasses();
        final boolean wantResObf = cfg.isObfuscateResources();
        if (cfg.isBrainfuckLoader()) {
            if (cfg.isEncryptClasses()) {
                cfg.setEncryptClasses(false);
                KBoxLog.info(TAG, "  [BF] encryptClasses forced off (classes live in the BF blob)");
            }
            if (cfg.isObfuscateResources()) {
                cfg.setObfuscateResources(false);
                KBoxLog.info(TAG, "  [BF] obfuscateResources forced off (resources live in the BF blob)");
            }
            // VMP and JNIC are now BF-coexistent:
            //  - VMP: its runtime (VmpInterpreter/VmpMethod/ChaCha20/HardwareKeyRing)
            //    is injected as PLAIN jar entries resolvable via BfSecureLoader's
            //    parent loader; VMP-translated blob classes call into them directly.
            //  - JNIC: its native lib ships as META-INF/kbox/jnic.bin (NOT native.bin,
            //    which holds the BF decoder); BfSecureLoader loads it and registers
            //    natives per class via NativeLoader.registerNatives0(Class).
            // We keep them enabled and let BfSecureLoader drive their runtime setup.
        }

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

        // Self-obfuscation guard: when the input jar IS this obfuscator itself
        // (it carries kbox-core), class-body encryption and resource renaming
        // would install ResourceGuardClassLoader over the engine's own classes,
        // loading a second copy of ProtectionConfig etc. in the guard loader and
        // causing ClassCastException at startup. Detect and force them off so the
        // self-protected jar stays a RUNNABLE obfuscator (all other protections —
        // rename, strings, CF3, VMP full, JNIC, BFVM, BrainfuckShield, Shield —
        // remain at full strength).
        boolean selfObfuscation = graph.getClasses().containsKey(
                "com/kbox/core/ProtectionPipeline");
        if (selfObfuscation) {
            if (cfg.isEncryptClasses()) {
                cfg.setEncryptClasses(false);
                KBoxLog.info(TAG, "  [SELF] encryptClasses forced off (self-obfuscation: "
                        + "avoid double-loading engine classes via guard loader)");
            }
            if (cfg.isObfuscateResources()) {
                cfg.setObfuscateResources(false);
                KBoxLog.info(TAG, "  [SELF] obfuscateResources forced off (self-obfuscation: "
                        + "keep engine resource paths stable)");
            }
        }

        // ---- Route① hardening: per-build random key seed ---------------------
        // Generate a 32-byte CSPRNG seed for THIS build and make it the factor
        // feed for every key derivation (HardwareKeyRing). The packager embeds
        // the same bytes as META-INF/kbox/seed.bin, so the run JVM re-derives the
        // identical keys while each build ships a DIFFERENT seed — a seed captured
        // from one jar does not unlock any other jar (defeats cross-build
        // re-derivation, the static-seed gap).
        {
            byte[] seed = new byte[32];
            new java.security.SecureRandom().nextBytes(seed);
            com.kbox.runtime.HardwareKeyRing.attachBuildSeed(seed);
            KBoxLog.debug(TAG, "  Per-build key seed installed (" + seed.length + "B, random per build)");
        }

        // Brainfuck chaos mode suitability guards (need the analyzed graph).
        // When the input cannot be bootstrapped by BfSecureLoader (no Main-Class,
        // Spring Boot fat jar, or a loader-scanning mod), we GRACEFULLY DEGRADE to
        // non-BF full protection instead of failing the whole build: rename +
        // strings + VMP + JNIC + BFVM + BrainfuckShield + Shield all stay active,
        // only the Brainfuck-RLE blob loader is skipped. This honors neverFail=true
        // so library/mod inputs (a legitimate category) are never hard-blocked.
        if (cfg.isBrainfuckLoader()) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "Brainfuck chaos (防内存Dump)");
            String reason = null;
            if (graph.getManifestMainClass() == null) {
                reason = "input jar has no Main-Class (library / mod / plugin — "
                        + "not a standalone executable jar)";
            } else if (graph.isSpringBootFatJar()) {
                reason = "Spring Boot fat jar (nested BOOT-INF/lib jars cannot be hidden)";
            } else if (graph.getManifest() != null && new String(
                    graph.getManifest(), StandardCharsets.UTF_8).contains("TweakClass:")) {
                reason = "Forge/Fabric mod loader detected (loader scans raw jar bytes)";
            }
            if (reason != null) {
                KBoxLog.warn(TAG, "  [BF] Brainfuck mode incompatible: " + reason);
                KBoxLog.warn(TAG, "  [BF] Degrading to non-BF full protection "
                        + "(rename+strings+VMP+JNIC+BFVM+BrainfuckShield+Shield remain active). "
                        + "Set brainfuckLoader=false to silence this.");
                cfg.setBrainfuckLoader(false);
                // Restore class-encryption / resource-obfuscation that were
                // force-disabled earlier only because the BF blob replaces the
                // jar layout — in degraded non-BF mode they are compatible again.
                if (wantClassEnc) {
                    cfg.setEncryptClasses(true);
                }
                if (wantResObf) {
                    cfg.setObfuscateResources(true);
                }
            } else {
                KBoxLog.info(TAG, "  [BF] protecting " + totalClasses + " classes inside "
                        + "a Brainfuck-RLE payload (no plain class bytes on disk)");
            }
        }

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

        // ---- Stage 1d: SilentShield intelligent protection + adaptability audit ----
        // Runs before the reflection scan / keep derivation / any transform so the
        // automatically assigned keep/degrade/exclude actions are in place before
        // every downstream pass commits decisions. Only adds conservative keep rules
        // and GUI/JNIC-excludes; never breaks a jar. The audit report (weakness
        // catalog driven: other obfuscators' adaptability weaknesses -> hardening)
        // is the deep self-inspection deliverable.
        com.kbox.core.silentshield.SilentShield.Result ss = null;
        java.util.List<com.kbox.core.silentshield.AuditFinding> allFindings = new ArrayList<>();
        if (cfg.isSilentShield()) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "SilentShield adaptability audit (intelligent)");
            try {
                Path ssReport = cfg.getSilentShieldReport() != null
                        ? Path.of(cfg.getSilentShieldReport()) : workDir.resolve("silentshield-report.txt");
                ss = new com.kbox.core.silentshield.SilentShield().run(graph, cfg, ssReport);
                KBoxLog.info(TAG, "  SilentShield: " + ss.findings.size() + " findings, "
                        + ss.appliedActions + " actions applied, weakness catalog="
                        + com.kbox.core.silentshield.WeaknessCatalog.get().size() + " entries");
                KBoxLog.info(TAG, "  Report: " + ss.reportFile);
                allFindings.addAll(ss.findings);
            } catch (Exception e) {
                KBoxLog.warn(TAG, "SilentShield audit failed: " + e.getMessage()
                        + " (continuing without)");
            }
        }

        // ---- ModernStackAdapter: 现代技术栈主动适配 (JDK 8..25 / Kotlin 协程 /
        //      multi-release / JPMS / GraalVM)。把协程状态机等易碎点排除 JNIC/VMP+控制流。
        com.kbox.core.silentshield.ModernStackAdapter.Result stackResult = null;
        if (cfg.isModernStackAdapt()) {
            stackResult = new com.kbox.core.silentshield.ModernStackAdapter().run(graph, cfg);
            allFindings.addAll(stackResult.findings);
        }

        // ---- 商业级适配性验收报告：四支柱 + 现代技术栈 + JDK 8..25 + 10 年来源矩阵。----
        // 汇总 SilentShield 发现 + ModernStackAdapter 结果，输出供合规审查的验收报告。
        if ((cfg.getAdaptabilityReport() != null || cfg.getSilentShieldReport() != null)
                && stackResult != null) {
            boolean anyAdapt = cfg.isSilentShield() || cfg.isModernStackAdapt();
            if (anyAdapt) {
                try {
                    Path reportPath = cfg.getAdaptabilityReport() != null
                            ? Path.of(cfg.getAdaptabilityReport())
                            : workDir.resolve("adaptability-report.txt");
                    int applied = ss != null ? ss.appliedActions : 0;
                    com.kbox.core.silentshield.AdaptabilityReport.render(graph, cfg,
                            new com.kbox.core.silentshield.AdaptabilityReport.Data(
                                    allFindings, applied, stackResult),
                            reportPath);
                    KBoxLog.info(TAG, "  Adaptability report: " + reportPath);
                } catch (Exception e) {
                    KBoxLog.warn(TAG, "Adaptability report failed: " + e.getMessage());
                }
            }
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

        // ---- Stage 6a: S2 opaque state-machine fake branches (kboxDedeobfShieldV1) ----
        // Inflates the CFG with constant-outcome chained-state guards + dead poison
        // blocks, run right after control-flow so JNIC/VMP later see the inflated graph.
        if (cfg.getOpaqueStateMachine() > 0) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "S2 opaque state-machine");
            new com.kbox.core.obfu.OpaqueStateObfuscator(graph, cfg).apply();
        }

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

        // ---- Stage 6h: Intertwined constant expressions (mbaConstants) ----
        // Opt-in alternative to the shared-decryptor constant pass: expands each
        // inline int constant into a fresh verified random expression tree, so there
        // is no single decryptor signature / table to grep or replay. Stage counter
        // is only bumped when active to keep progress labels truthful.
        if (cfg.getMbaConstants() > 0) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "Intertwined constant expressions");
            new com.kbox.core.obfu.MbaConstantObfuscator(graph, cfg).apply();
        }

        // ---- Stage 6i: S4 honeypot bait (kboxDedeobfShieldV1 static decoys) ----
        // Runs AFTER const-obfuscation so the injected fake tables/round-keys stay as
        // visible, tempting literals (the bait is meant to be found), and BEFORE
        // identifier renaming so the bait is woven into the final rename topology.
        if (cfg.getHoneypotLevel() > 0) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "S4 honeypot bait");
            new com.kbox.core.obfu.HoneypotInjector(graph, cfg).apply();
        }

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

        // ---- Stage 8b: Reflection gate (Phase2-L6b) ----
        // Wraps every Class.forName(String) call site with an FNV-1a allowlist check
        // (seeded from graph classes + keep-set). Runs after string encryption so the
        // synthetic holder's "_allow" int[] and the injected checks are themselves
        // opaque; JDK/boot prefixes pass, everything unmapped throws SecurityException.
        new com.kbox.core.reflection.ReflectionGateInjector(graph, cfg).apply();

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

        // ---- Stage 9b: VM原生化 (compile kbox_vmp_core.c -> vmp.bin) ----
        // Layer-4 hardening: moves the VMP interpreter body out of Java bytecode
        // into a packed native library (META-INF/kbox/vmp.bin). The runtime seam
        // (VmpInterpreterNative) executes VMP methods natively when the blob is
        // present and falls back to the byte-identical Java interpreter otherwise,
        // so a failed/missing native build never changes a protected app's output.
        byte[] vmpBlob = null;
        if (cfg.isEnableVmp() && cfg.isEnableVmpNative()) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "VM原生化 (native VMP interpreter)");
            try {
                vmpBlob = com.kbox.core.jnic.NativeCompiler.compileVmp(workDir, cfg.getCc());
                if (vmpBlob == null) {
                    KBoxLog.info(TAG, "  VM原生化 inactive — using byte-identical Java interpreter");
                } else {
                    KBoxLog.info(TAG, "  VMP native blob (packed): " + vmpBlob.length + " bytes");
                }
            } catch (Throwable t) {
                KBoxLog.warn(TAG, "  VM原生化 compile failed: " + t.getMessage()
                        + " (Java interpreter fallback)");
            }
        }

        // ---- Stage 10: Anti-analysis passes ----
        KBoxLog.stage(++stage, TOTAL_STAGES, "Anti-analysis (anti-decompiler + watermark + exception-jump)");
        new com.kbox.core.controlflow.AntiDecompiler(graph, cfg).apply();
        new com.kbox.core.controlflow.Watermarker(graph, cfg).apply();
        new com.kbox.core.controlflow.ExceptionJumpObfuscator(graph, cfg).apply();

        // ---- Stage 12c: kboxDedeobfShieldV1 dynamic-guard injection (S3/D/C/X build side) ----
        // Arms KBoxDedeobfGuard (D1-D5/C1/C2 + sentinel + X2 build-signature binding) from
        // the kept entry classes. Runs after renaming/transforms so injected references use
        // the final names and are not shredded by earlier passes. Prologue-only, stack-neutral.
        {
            boolean anyDedeobf = cfg.getSentinelInterleave() > 0 || cfg.getStackFrameRedirect() > 0
                    || cfg.getEntropyTimeAnchor() > 0 || cfg.getSelfWipeSections() > 0
                    || cfg.getProcessHeartbeat() > 0 || cfg.getHoneypotPe() > 0
                    || cfg.getOneTimeSemantic() > 0 || cfg.getLineageChain() > 0
                    || cfg.getSelfRefAuth() > 0 || cfg.getMultiRep() > 0
                    || cfg.getPolyGold() > 0 || cfg.getSignalPoison() > 0
                    || cfg.getBuildSigBind() > 0;
            if (anyDedeobf) {
                KBoxLog.stage(++stage, TOTAL_STAGES, "kboxDedeobfShieldV1 dynamic-guard injection (S3/D/C/X)");
                new com.kbox.core.obfu.DedeobfShieldInjector(graph, cfg).apply();
            }
        }

        // ---- Stage 12b: Null-guard injection ----
        // Injects null checks after Class.getResourceAsStream() calls so that
        // obfuscated resource paths returning null don't cause downstream NPE.
        KBoxLog.stage(++stage, TOTAL_STAGES, "Null-guard injection (getResourceAsStream safety)");
        new com.kbox.core.controlflow.ResourceNullGuardTransformer(graph, cfg).apply();

        // ---- Stage 9c: BFVM full method virtualization ----
        // Opt-in per-method via bfvmMethod / enableBfvm. Each selected method body is
        // compiled to an executable Brainfuck program (pure data initialiser) and its
        // body replaced by a thin stub calling the Brainfuck VM at runtime
        // (com.kbox.runtime.bfvm). Runs AFTER every other body-mutating pass so the
        // virtualized form is final; methods claimed by VMP/JNIC, ctors and bodies BFVM
        // cannot translate are skipped and keep their current obfuscated body.
        if (cfg.isEnableBfvm() && !cfg.getBfvmMethods().isEmpty()) {
            KBoxLog.stage(++stage, TOTAL_STAGES, "BFVM full method virtualization");
            new com.kbox.core.bfvm.BfvmMethodInjector(
                    cfg.getBfvmMethods(), cfg.getVmpMethods(), cfg.getNativeMethods())
                    .apply(graph);
        }

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
        // Phase3-L2a: EPL binning manifest — build once from the FINAL (post-rename)
        // native/VMP method sets so the audit file cross-references the shipped jar.
        byte[] epdManifest = com.kbox.core.analysis.AutoJnicVmpSelector
                .buildEpdManifest(graph, cfg);
        if (cfg.isBrainfuckLoader()) {
            // Brainfuck chaos mode: build the native decoder and assemble the
            // BF-protected jar (classes + resources hidden inside the payload).
            // One random symbol set per build is shared by BOTH the packer and
            // the native decoder, so every build ships a distinct program /
            // decoder pair (build-to-build polymorphism on the BF side too).
            com.kbox.core.brainfuck.BfSymbolSet bfSym =
                    com.kbox.core.brainfuck.BfSymbolSet.random();
            byte[] bfNativeBlob = com.kbox.core.brainfuck.BfNativeBuilder
                    .build(workDir, cfg.getCc(), bfSym).packedBlob;
            Packager packager = new Packager();
            packager.writeBrainfuck(inputJar, outputJar, graph, mapping,
                    bfNativeBlob, jnicResult.packedBlob, cfg, bfSym, vmpBlob, epdManifest);
        } else {
            Packager packager = new Packager();
            packager.write(inputJar, outputJar, graph, mapping, jnicResult.libraryPath,
                    jnicResult.packedBlob, nativeCryptoBlob, cfg, resMapping, resSeed,
                    vmpBlob, epdManifest);
        }

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
        KBoxLog.info(TAG, "  [x] BFVM (full BF VM):     " + cfg.isEnableBfvm()
                + (cfg.isEnableBfvm() ? " (" + cfg.getBfvmMethods().size() + " methods)" : ""));
        KBoxLog.info(TAG, "  [x] BrainfuckShield(2nd VM):" + cfg.isBrainfuckShield()
                + (cfg.isBrainfuckShield() ? " (tape-dialect L3, level=" + cfg.getBrainfuckShieldLevel() + ")" : ""));
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
        // BrainfuckShield（二次虚拟化）: 每构建随机 buildSalt + 强度。buildSalt 内嵌于
        // 磁带 header，运行期从 header 读回，无需任何跨进程共享的稳定键；方言由
        // 每方法 K + buildSalt 派生，故方法间/构建间全异。
        int bfLevel = cfg.isBrainfuckShield() ? Math.max(1, cfg.getBrainfuckShieldLevel()) : 0;
        int bfBuildSalt = bfLevel > 0
                ? com.kbox.core.brainfuckshield.BfMethodInjector.newBuildSalt() : 0;
        VmpMethodInjector injector = new VmpMethodInjector(bfLevel, bfBuildSalt);
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
                    VmpTranslator.Result r = VmpTranslator.translate(mn, cfg.getVmpInterleave());

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

        // BFVM method keys are remapped exactly like VMP keys: the BFVM stage runs
        // after renaming, so the configured owner/method must match the renamed class.
        List<String> oldBfvm = new ArrayList<>(cfg.getBfvmMethods());
        cfg.getBfvmMethods().clear();
        for (String key : oldBfvm) {
            int hash1 = key.indexOf('#');
            if (hash1 <= 0) { cfg.getBfvmMethods().add(key); continue; }
            String oldOwner = key.substring(0, hash1);
            String rest = key.substring(hash1 + 1);
            int hash2 = rest.indexOf('#');
            if (hash2 <= 0) { cfg.getBfvmMethods().add(key); continue; }
            String oldName = rest.substring(0, hash2);
            String desc = rest.substring(hash2 + 1);

            String newOwner = classMap.getOrDefault(oldOwner.replace('.', '/'), oldOwner).replace('/', '.');
            String newName = mapping.mapMethod(oldOwner.replace('.', '/'), oldName, desc);
            String newKey = newOwner + "#" + newName + "#" + desc;
            KBoxLog.debug(TAG, "  remap bfvm: " + key + " -> " + newKey);
            cfg.getBfvmMethods().add(newKey);
        }
    }
}
