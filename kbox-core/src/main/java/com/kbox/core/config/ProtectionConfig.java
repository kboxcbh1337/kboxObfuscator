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
    /** BFVM（完整方法虚拟化）: opt-in per-method via {@code bfvmMethod}. 把每个选中的
     *  方法体编译成可执行的 Brainfuck 程序（纯数据初始化器），运行期经
     *  {@code com.kbox.runtime.bfvm} 的 Brainfuck VM 解释执行。是 BrainfuckShield
     *  （VMP 磁带化）之外的独立虚拟化路线：把真实 JVM 字节码整体变成 BF 程序。 */
    private boolean enableBfvm = false;
    /** VortexVM/L2 VM interleave strength (0 = disabled). Inserts irregular {@code NOP}
     *  micro-ops between translated VMP instructions so the interpreter stream is never a
     *  linear, analysable opcode sequence. Max useful strength: 4. */
    private int vmpInterleave = 0;
    /** BrainfuckShield（二次虚拟化，仅对 VMP 方法生效）: 把每个 VMP 方法的 ChaCha20
     *  密文流按 per-build/per-method 随机<em>私有方言</em>重编码成「磁带程序」（KBFT）
     *  存入 {@code $vmp_<n>} 字段。运行期 {@code BfInterpreter} 先逐格回放解码才能交给
     *  {@code VmpInterpreter} 执行。对抗「AI 写通用转译器」：每构建/每方法方言全异。
     *  依赖 {@link #enableVmp}。强度 1..3（诱饵密度/膨胀率），0=关闭。 */
    private boolean brainfuckShield = false;
    /** BrainfuckShield 强度 0..3（0=关闭，随 {@link #brainfuckShield} 联动）。 */
    private int brainfuckShieldLevel = 3;
    private boolean enableVmpNative = false;      // opt-in: compile kbox_vmp_core.c -> vmp.bin (VM原生化)
    /** Phase2-L6b: runtime reflection gate. Wrap every {@code Class.forName(String)}
     *  call site with a FNV-1a allowlist check (seeded from graph classes + keep-set);
     *  JDK/boot prefixes pass, everything unmapped throws SecurityException("KBox"). */
    private boolean reflectionGate = false;
    private boolean enableJnic = false;           // opt-in: per-method via marker
    private boolean obfuscateResources = false;   // opt-in: rename + encrypt non-class files
    /** Ultimate chaos mode: pack every class + resource into a Brainfuck-RLE blob
     *  that is only decodable through the packed native decoder
     *  ({@code META-INF/kbox/bf-native.bin}). The jar ships no readable .class /
     *  resource bytes — plaintext exists only in native memory, never in the Java
     *  heap, so a heap dump yields nothing but RLE noise. Conflicts with JNIC,
     *  class encryption and resource obfuscation (auto-disabled at run time). */
    private boolean brainfuckLoader = false;
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
    /**
     * Intertwined-expression constant obfuscation level.
     * {@code 0}=off (default), {@code 1}=basic, {@code 2}=deep. When >0 this is an
     * <em>alternative</em> to {@link #obfuscateConstants}: each inline int constant is
     * expanded into a fresh, verified random expression tree (no shared decryptor, no
     * single table to leak). Requires {@code mbaConstants} in the config; the shared
     * table pass is skipped while it is active.
     */
    private int mbaConstants = 0;
    /**
     * S4 honeypot bait level, 0..3 (0=off).
     * {@code kboxDedeobfShieldV1} static bait: inject synthetic classes packed
     * with fake key material, fake "license"/AES-modelling tables and dead
     * crypto-shaped methods. The bait is never reachable from real logic, so a
     * reverse-engineer who pivots into it spends hours mining a decoy goldmine
     * while the actual secrets live elsewhere. {@code 1}=per build a few classes,
     * {@code 2}=more, larger tables, {@code 3}=aggressive multi-bait + fake holder
     * that mimics the const-obfuscation holder signature.
     */
    private int honeypotLevel = 0;
    /**
     * S2 opaque state-machine fake-branch level, 0..3 (0=off).
     * {@code kboxDedeobfShieldV1} CFG inflation: before a selected subset of real
     * conditional/unconditional branches, inject a chained runtime state-machine
     * opaque predicate whose outcome is provably constant (never alters real flow),
     * plus a dead "poison" block. Static data-flow analysis that models a single
     * pass must now simulate a stateful churn function to decide reachability,
     * while the actual control flow is unchanged (stack-neutral, COMPUTE_FRAMES-safe).
     */
    private int opaqueStateMachine = 0;
    /**
     * S5 blob two-layer mock fill level, 0..3 (0=off).
     * {@code kboxDedeobfShieldV1} packaging decoys: in addition to the normal anti-
     * unpack decoys, inject a second tier of <em>valid-looking</em> pseudo-classes
     * (real CAFEBABE, never in the real payload index so never executed) plus a fake
     * second-level mock index / native blob. A tool that dumps or recompiles
     * "<code>**&#47;*.class</code>" or enumerates the blob by name now chokes on a
     * decoy goldmine and cannot distinguish real entries from mock ones from the
     * container alone. Higher levels => more mock classes + a fake native blob.
     */
    private int blobMockFill = 0;
    /**
     * S1 method-body splitting level, 0..3 (0=off).
     * {@code kboxDedeobfShieldV1} body splitting: split eligible straight-line static
     * methods at a stack-empty seam into two synthetic segment methods threaded through
     * a shared {@code int[]} cache, so the body is recombined across method boundaries.
     * Eligibility is strict and semantics-preserving; irregular bodies are untouched.
     */
    private int methodSplit = 0;

    // === kboxDedeobfShieldV1 — S3/D/C/X 门控（0..3，0=off） ===
    /** S3 sentinel dual-interpreter interleave level (0=off). Arms a Java+native
     *  dual-microcode cross-validation sentinel inside the VMP seam so a single
     *  interpreter hammer cannot replay/fake its execution. */
    private int sentinelInterleave = 0;
    /** D1 stack-frame redirection level (0=off). Hides the true call-stack depth
     *  from Agent stack-walk / JVMTI by anchoring a native TLS "frame spine". */
    private int stackFrameRedirect = 0;
    /** D2 execution-entropy/time-anchor level (0=off). Throttle/poison based on
     *  runtime time + entropy anchors, with a threshold guard so benign jitter on
     *  real hardware never trips a false positive. */
    private int entropyTimeAnchor = 0;
    /** D3 hot/cold section self-wipe level (0=off). Cold decode/decrypt sections
     *  are self-wiped (overwritten + FlushInstructionCache) after use so used
     *  plaintext never persists in the section. */
    private int selfWipeSections = 0;
    /** D4 multi-process chained heartbeat level (0=off). Parent/child heartbeat
     *  chain; a dropped beat poisons the lineage. */
    private int processHeartbeat = 0;
    /** D5 implicit honeypot PE level (0=off). Ships/looks for a decoy MZ image to
     *  mislead unpackers/hook scanners. */
    private int honeypotPe = 0;
    /** C1 one-time semantic instance level (0=off). The semantic table is
     *  regenerated in-place once and never persisted in plaintext. */
    private int oneTimeSemantic = 0;
    /** C2 lineage session chain level (0=off). KbnlKey upgraded to a serial
     *  one-way ancestor chain (each session key is a PRF of the previous). */
    private int lineageChain = 0;
    /** C3 self-referential auth sandbox level (0=off). Extends verifySelf to a
     *  native-anchored fixed point so the verifier itself is verified. */
    private int selfRefAuth = 0;
    /** C4 formalized multi-representation level (0=off, most-expensive regression).
     *  Data-driven double-indexed handler dispatch across multiple representations
     *  with a conversion gate between them. */
    private int multiRep = 0;
    /** C5 computational gilding level (0=off). Polynomial normalization rewrite of
     *  selected constants to camouflage semantic anchors. */
    private int polyGold = 0;
    /** X1 signal-linked poison level (0=off). A watchdog links entry signals to a
     *  poison latch consumed by nuke rules on the native side. */
    private int signalPoison = 0;
    /** X2 build-time version signature binding level (0=off). Binds a build signature
     *  (over the output jar) into the manifest and verifies at runtime. */
    private int buildSigBind = 0;

    /** Parallel pipeline threads (0 = auto = CPU cores). */
    private int parallelThreads = 0;
    /** Use GPU (Aparapi/OpenCL) for bulk string-encryption when available. */
    private boolean gpuAccel = false;

    /**
     * When {@code true} (default), the {@code silentShield} intelligent protection
     * system runs an in-depth adaptability audit before any transformation pass:
     * it detects 25 families of "other obfuscators' adaptability weaknesses"
     * (reflection, serialization, SPI, lambda/MethodHandle, generics, resources,
     * callback interfaces, Swing EDT callbacks, native methods, entry points, …),
     * looks each up in the built-in weakness catalog ({@code WeaknessCatalog}),
     * and automatically lands conservative keep / degrade / exclude actions into
     * this config — so problems are prevented rather than discovered at runtime.
     * Only adds keep rules; never breaks a jar.
     */
    private boolean silentShield = true;
    /** Path for the SilentShield audit report. {@code null} = write to the work dir. */
    private String silentShieldReport = null;
    /** 现代技术栈自动适配（现代JDK特性/Kotlin协程/multi-release/JPMS/GraalVM，JDK 8..25 感知）。
     *  默认随 {@link #silentShield} 联动：在深度自检之后运行，做主动的保守排除。 */
    private boolean modernStackAdapt = true;
    /** 商业级适配性验收报告输出路径（10年矩阵+四支柱+JDK 8..25）。{@code null} = 写入 work dir。 */
    private String adaptabilityReport = null;

    /**
     * Optional path to a deobfuscation mapping file (ProGuard-style). When set,
     * the obfuscator writes class/method/field rename mappings plus the resource
     * name mapping to this file after all transforms complete. This lets a
     * release/build pipeline (or an IDE debugger with a mapping-aware stack
     * trace tool) reverse the obfuscation for stack traces and diagnostics.
     * <p>{@code null} (default) means no mapping file is written.
     */
    private String mappingFile = null;
    /** Z9 incremental obfuscation: path to a previous MappingWriter output. When
     *  set, the renamer reuses the old class/member names for entries present in
     *  both builds, so class names stay stable across versions (debuggable,
     *  reproducible protections). {@code null} (default) = fresh random names. */
    private String useMapping = null;
    // --- Strength knobs ---
    /** 1=light, 2=medium, 3=aggressive. Higher means more opaque predicates / bogus branches. */
    private int controlFlowStrength = 2;
    /** S6 flattener EPL sweet-spot: only flatten methods whose real (non-label)
     *  instruction count is within [flattenerMinInsns, flattenerMaxInsns]. A huge
     *  flattened switch risks StackMapTable precision blow-up (the primary static
     *  weakness ZKM avoids by selecting); a tiny method gains nothing from a
     *  dispatcher. Default window [16, 256] selects genuine business methods. */
    private int flattenerMinInsns = 16;
    private int flattenerMaxInsns = 256;
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
    /** Methods marked for BFVM full virtualization: "owner.name desc". When non-empty
     *  and {@link #enableBfvm} is on, each listed method body is compiled to an
     *  executable Brainfuck program and executed through the Brainfuck VM at runtime. */
    private final Set<String> bfvmMethods = new HashSet<>();
    /** Class name prefixes that are eligible for native conversion (whitelist).
     *  When non-empty, only classes whose name starts with one of these prefixes
     *  are eligible for JNIC auto-selection or VMP auto-selection. */
    private final Set<String> nativeEligiblePrefixes = new HashSet<>();
    /**
     * Class name prefixes that must be excluded from JNIC/VMP native/virtual
     * conversion (blacklist). Unlike {@link #keepPrefixes}, these classes are
     * STILL renamed and every other body transform (control flow, typeConfusion,
     * MBA, strings) still runs; only the native-conversion / virtualization pass
     * is skipped. Used for self-hosting, where sinking the engine's own analysis /
     * string-encryption / obfuscator brain methods to native causes
     * {@code UnsatisfiedLinkError} when the self-obfuscated engine later runs
     * real obfuscation.
     */
    private final Set<String> nativeExcludePrefixes = new HashSet<>();

    // --- S8 JNIC EPL-driven layering ---
    // Default false: when nativeMethod/nativeMethods are configured explicitly, the
    // JNIC auto-selector is skipped (configured set wins). True: even with explicit
    // methods set, the EPL-driven auto-selector ALSO runs, augmenting the set with
    // the eligible medium/large methods (stub + native-bearer "全量铺开"). It still
    // honours the existing coverage cap (JNIC_MAX=50 unless nativeCoverage=full)
    // and drops any method already claimed by VMP.
    private boolean jnicEplDriven = false;

    // --- Native toolchain ---
    private String cc;            // path to C compiler; null = autodetect

    /** Native shell hardening level, 0..3 (0=off). Gates the compile-time
     *  NativeShellGuard pass applied to every generated native source:
     *  <ul>
     *   <li>1 = M1 全量字符串加密（函数体内字符串字面量→逐构建 XOR 静态数组）</li>
     *   <li>2 = +M2 关键函数控制流变异 + hypervisor 厂商 FNV/关键常量打散</li>
     *   <li>3 = +M3 IAT/导入隐藏（kernel32/ntdll 按哈希名解析）+ M4 壳函数运行期自校验 + 多态 NOP 插润</li>
     *  </ul>
     */
    private int nativeShell = 3;

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
    public boolean isEnableBfvm() { return enableBfvm; }
    public void setEnableBfvm(boolean v) { enableBfvm = v; }
    public int getVmpInterleave() { return vmpInterleave; }
    public void setVmpInterleave(int v) { vmpInterleave = Math.max(0, v); }
    public boolean isBrainfuckShield() { return brainfuckShield; }
    public void setBrainfuckShield(boolean v) { brainfuckShield = v; }
    public int getBrainfuckShieldLevel() { return brainfuckShieldLevel; }
    public void setBrainfuckShieldLevel(int v) { brainfuckShieldLevel = Math.max(0, Math.min(3, v)); }
    public boolean isReflectionGate() { return reflectionGate; }
    public void setReflectionGate(boolean v) { reflectionGate = v; }
    public boolean isEnableVmpNative() { return enableVmpNative; }
    public void setEnableVmpNative(boolean v) { enableVmpNative = v; }
    public boolean isVmpProtectRuntime() { return vmpProtectRuntime; }
    public void setVmpProtectRuntime(boolean v) { vmpProtectRuntime = v; }
    public boolean isEnableJnic() { return enableJnic; }
    public void setEnableJnic(boolean v) { enableJnic = v; }
    public boolean isObfuscateResources() { return obfuscateResources; }
    public void setObfuscateResources(boolean v) { obfuscateResources = v; }
    public boolean isBrainfuckLoader() { return brainfuckLoader; }
    public void setBrainfuckLoader(boolean v) { brainfuckLoader = v; }
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
    public int getMbaConstants() { return mbaConstants; }
    public void setMbaConstants(int v) { mbaConstants = Math.max(0, Math.min(2, v)); }
    public int getHoneypotLevel() { return honeypotLevel; }
    public void setHoneypotLevel(int v) { honeypotLevel = Math.max(0, Math.min(3, v)); }
    public int getOpaqueStateMachine() { return opaqueStateMachine; }
    public void setOpaqueStateMachine(int v) { opaqueStateMachine = Math.max(0, Math.min(3, v)); }
    public int getBlobMockFill() { return blobMockFill; }
    public void setBlobMockFill(int v) { blobMockFill = Math.max(0, Math.min(3, v)); }
    public int getMethodSplit() { return methodSplit; }
    public void setMethodSplit(int v) { methodSplit = Math.max(0, Math.min(3, v)); }

    // === kboxDedeobfShieldV1 — S3/D/C/X 门控 getters/setters ===
    public int getSentinelInterleave() { return sentinelInterleave; }
    public void setSentinelInterleave(int v) { sentinelInterleave = Math.max(0, Math.min(3, v)); }
    public int getStackFrameRedirect() { return stackFrameRedirect; }
    public void setStackFrameRedirect(int v) { stackFrameRedirect = Math.max(0, Math.min(3, v)); }
    public int getEntropyTimeAnchor() { return entropyTimeAnchor; }
    public void setEntropyTimeAnchor(int v) { entropyTimeAnchor = Math.max(0, Math.min(3, v)); }
    public int getSelfWipeSections() { return selfWipeSections; }
    public void setSelfWipeSections(int v) { selfWipeSections = Math.max(0, Math.min(3, v)); }
    public int getProcessHeartbeat() { return processHeartbeat; }
    public void setProcessHeartbeat(int v) { processHeartbeat = Math.max(0, Math.min(3, v)); }
    public int getHoneypotPe() { return honeypotPe; }
    public void setHoneypotPe(int v) { honeypotPe = Math.max(0, Math.min(3, v)); }
    public int getOneTimeSemantic() { return oneTimeSemantic; }
    public void setOneTimeSemantic(int v) { oneTimeSemantic = Math.max(0, Math.min(3, v)); }
    public int getLineageChain() { return lineageChain; }
    public void setLineageChain(int v) { lineageChain = Math.max(0, Math.min(3, v)); }
    public int getSelfRefAuth() { return selfRefAuth; }
    public void setSelfRefAuth(int v) { selfRefAuth = Math.max(0, Math.min(3, v)); }
    public int getMultiRep() { return multiRep; }
    public void setMultiRep(int v) { multiRep = Math.max(0, Math.min(3, v)); }
    public int getPolyGold() { return polyGold; }
    public void setPolyGold(int v) { polyGold = Math.max(0, Math.min(3, v)); }
    public int getSignalPoison() { return signalPoison; }
    public void setSignalPoison(int v) { signalPoison = Math.max(0, Math.min(3, v)); }
    public int getBuildSigBind() { return buildSigBind; }
    public void setBuildSigBind(int v) { buildSigBind = Math.max(0, Math.min(3, v)); }

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
    public String getUseMapping() { return useMapping; }
    public void setUseMapping(String v) { useMapping = (v == null || v.isEmpty()) ? null : v; }

    public boolean isSilentShield() { return silentShield; }
    public void setSilentShield(boolean v) { silentShield = v; }
    public int getFlattenerMinInsns() { return flattenerMinInsns; }
    public void setFlattenerMinInsns(int v) { if (v > 0) flattenerMinInsns = v; }
    public int getFlattenerMaxInsns() { return flattenerMaxInsns; }
    public void setFlattenerMaxInsns(int v) { if (v > 0) flattenerMaxInsns = v; }
    public boolean isJnicEplDriven() { return jnicEplDriven; }
    public void setJnicEplDriven(boolean v) { jnicEplDriven = v; }
    public String getSilentShieldReport() { return silentShieldReport; }
    public void setSilentShieldReport(String v) { silentShieldReport = (v == null || v.isEmpty()) ? null : v; }
    public boolean isModernStackAdapt() { return modernStackAdapt; }
    public void setModernStackAdapt(boolean v) { modernStackAdapt = v; }
    public String getAdaptabilityReport() { return adaptabilityReport; }
    public void setAdaptabilityReport(String v) { adaptabilityReport = (v == null || v.isEmpty()) ? null : v; }

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
    public Set<String> getBfvmMethods() { return bfvmMethods; }
    public Set<String> getNativeEligiblePrefixes() { return nativeEligiblePrefixes; }
    public Set<String> getNativeExcludePrefixes() { return nativeExcludePrefixes; }
    /** Returns {@code true} if JNIC/VMP must not convert the given class. */
    public boolean isExcludedFromNative(String internalName) {
        if (internalName == null || nativeExcludePrefixes.isEmpty()) return false;
        String dotted = internalName.replace('/', '.');
        for (String p : nativeExcludePrefixes) {
            if (p == null || p.isEmpty()) continue;
            if (dotted.startsWith(p) || internalName.startsWith(p)) return true;
        }
        return false;
    }
    /** Returns {@code true} if the class may be considered for JNIC/VMP
     *  auto-selection, honouring the whitelist {@link #nativeEligiblePrefixes}
     *  (empty whitelist = every non-excluded class is eligible). */
    public boolean isNativeEligible(String internalName) {
        if (isExcludedFromNative(internalName)) return false;
        if (nativeEligiblePrefixes.isEmpty()) return true;
        String dotted = internalName.replace('/', '.');
        for (String p : nativeEligiblePrefixes) {
            if (p == null || p.isEmpty()) continue;
            if (dotted.startsWith(p) || internalName.startsWith(p)) return true;
        }
        return false;
    }
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
    public int getNativeShell() { return nativeShell; }
    public void setNativeShell(int v) { nativeShell = v; }

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
        c.enableBfvm = enableBfvm;
        c.vmpInterleave = vmpInterleave;
        c.brainfuckShield = brainfuckShield;
        c.brainfuckShieldLevel = brainfuckShieldLevel;
        c.enableVmpNative = enableVmpNative;
        c.reflectionGate = reflectionGate;
        c.enableJnic = enableJnic;
        c.obfuscateResources = obfuscateResources;
        c.brainfuckLoader = brainfuckLoader;
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
        c.bfvmMethods.addAll(bfvmMethods);
        c.nativeEligiblePrefixes.addAll(nativeEligiblePrefixes);
        c.nativeExcludePrefixes.addAll(nativeExcludePrefixes);
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
        c.mbaConstants = mbaConstants;
        c.parallelThreads = parallelThreads;
        c.gpuAccel = gpuAccel;
        c.silentShield = silentShield;
        c.silentShieldReport = silentShieldReport;
        c.modernStackAdapt = modernStackAdapt;
        c.adaptabilityReport = adaptabilityReport;
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
                + ", classEnc=" + encryptClasses + ", vmp=" + enableVmp + ", vmpInterleave=" + vmpInterleave
                + ", bfvm=" + enableBfvm + "(" + bfvmMethods.size() + ")"
                + ", bfShield=" + brainfuckShield + "(" + brainfuckShieldLevel + ")"
                + ", reflGate=" + reflectionGate
                + ", jnic=" + enableJnic + ", native=" + nativeMethods.size()
                + ", resources=" + obfuscateResources
                + ", bfLoader=" + brainfuckLoader
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
                + ", mbaConst=" + mbaConstants
                + ", jnicFull=" + jnicFullCoverage
                + ", autoKeep=" + autoKeepRules
                + ", silentShield=" + silentShield
                + ", stackAdapt=" + modernStackAdapt
                + ", libPrefixes=" + libraryClassifier.getLibraryPrefixes().size()
                + ", userPrefixes=" + libraryClassifier.getUserPrefixes().size()
                + ", keepAttrs=" + keepAttributes + "}";
    }

    // === One-shot "everything at maximum strength" preset (全开·可开关) ===
    private boolean allMax = false;
    public boolean isAllMax() { return allMax; }
    public void setAllMax(boolean v) { allMax = v; }

    /**
     * Applies the maximum-strength preset to EVERY option in one shot.
     * This is the "全开" toggle: one config line (`allMax = true`) turns on all
     * Java-layer transforms, VMP(full)+native VMP, JNIC(full), BrainfuckShield,
     * native shell M3, every kboxDedeobfShieldV1 S/D/C/X layer at level 3, plus
     * auto-adaptation so ANY project type (standalone / library / MC mod /
     * Spring Boot / Kotlin) degrades gracefully instead of failing.
     *
     * <p>Semantics: config lines AFTER {@code allMax = true} override individual
     * keys, so put it first and override only what the target project needs
     * (e.g. {@code controlFlowStrength = 2} for very large inputs,
     * {@code encryptClasses = false} for Mixin mods).
     *
     * <p>Not forced here: {@code brainfuckLoader} (changes the jar layout; the
     * pipeline auto-degrades it when incompatible), {@code cc} (machine path),
     * {@code bfvmMethod}/{@code vmpMethod}/{@code nativeMethod} (method lists are
     * project-specific; VMP/JNIC still auto-select when coverage is full).
     */
    public void applyMaxStrength() {
        allMax = true;
        // ---- naming / strings ----
        renameIdentifiers = true;
        renamePackages = true;
        obfuscateEntryPoint = true;
        encryptStrings = true;
        stringEncryptionStrength = 3;
        whiteboxStrings = true;
        scatterStrings = true;
        fixedXorKey = true;
        // ---- control flow / constants / types ----
        obfuscateControlFlow = true;
        controlFlowStrength = 3;
        exceptionJumpObf = true;
        hideCallGraph = true;
        fakeDebugInfo = true;
        methodInlineExtract = true;
        eraseAnnotations = true;
        obfuscateConstants = true;
        mbaConstants = 2;
        typeConfusionStrength = 2;
        // ---- anti analysis / debug ----
        antiDecompilerLevel = 3;
        antiDebug = true;
        vmpSelfCheck = true;
        integrityCheck = true;
        nativeAntiHook = true;
        nullGuard = true;
        // ---- VMP + native VMP ----
        enableVmp = true;
        vmpFullCoverage = true;
        vmpProtectRuntime = true;
        enableVmpNative = true;
        // ---- JNIC ----
        enableJnic = true;
        jnicFullCoverage = true;
        jnicEplDriven = true;
        // ---- BFVM / BrainfuckShield（BFVM 需 bfvmMethod；无则无害） ----
        enableBfvm = true;
        brainfuckShield = true;
        brainfuckShieldLevel = 3;
        // ---- native shell ----
        nativeShell = 3;
        // ---- class encryption / resources（BF 模式下自动降档，降级时恢复） ----
        encryptClasses = true;
        obfuscateResources = true;
        // ---- kboxDedeobfShieldV1：S1-S5 / D1-D5 / C1-C5 / X1-X2 全拉满 ----
        methodSplit = 3;
        opaqueStateMachine = 3;
        sentinelInterleave = 3;
        honeypotLevel = 3;
        blobMockFill = 3;
        stackFrameRedirect = 3;
        entropyTimeAnchor = 3;
        selfWipeSections = 3;
        processHeartbeat = 3;
        honeypotPe = 3;
        oneTimeSemantic = 3;
        lineageChain = 3;
        selfRefAuth = 3;
        multiRep = 3;
        polyGold = 3;
        signalPoison = 3;
        buildSigBind = 3;
        // ---- reflection gate（自动 allowlist） ----
        reflectionGate = true;
        // ---- auto-adaptation / resilience ----
        autoAdaptMinecraft = true;
        silentShield = true;
        modernStackAdapt = true;
        neverFail = true;
        rollbackToOriginalBytes = true;
        autoKeepRules = true;
        fixKotlinMetadata = true;
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
