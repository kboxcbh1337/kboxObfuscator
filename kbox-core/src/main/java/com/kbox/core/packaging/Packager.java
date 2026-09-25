package com.kbox.core.packaging;

import com.kbox.core.KBoxException;
import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.brainfuck.BfSymbolSet;
import com.kbox.core.brainfuck.BrainfuckPacker;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import com.kbox.core.name.Mapping;
import com.kbox.core.resource.ResourceEncryptor;
import com.kbox.core.resource.ResourceMapping;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Final assembler: writes the protected classes, copies resources (with their
 * class-name references updated), copies nested lib jars from a Spring Boot
 * input, refreshes the manifest and copies the native library next to the jar.
 *
 * <p>Layout preserved for Spring Boot fat jars:
 * {@code BOOT-INF/classes/...} + {@code BOOT-INF/lib/<original>.jar}.
 */
public final class Packager {

    private static final String TAG = "package";

    /**
     * Verifies a serialized class byte array using ASM's CheckClassAdapter.
     * This is equivalent to the JVM verifier: it checks type safety, stack
     * map frames, exception handler types, and control flow consistency.
     *
     * <p>Library classes (Mixin, Minecraft, etc.) are skipped because they
     * reference classes not on our classpath. Only user-authored classes
     * undergo full verification.
     *
     * @return null if verification passes or is skipped, or an error message string.
     */
    static String verifyClassBytes(byte[] classBytes, String className) {
        // Fast skip: library classes whose dependencies aren't on our classpath.
        if (className.startsWith("org/spongepowered/")
                || className.startsWith("net/minecraft/")
                || className.startsWith("com/mojang/")
                || className.startsWith("java/")
                || className.startsWith("javax/")) {
            return null;
        }

        // Quick pre-scan: skip if the class references Mixin-shaded ASM
        // (org/spongepowered/asm/lib/*). These fail class-loading in the verifier.
        try {
            String cpCheck = new String(classBytes, 0, Math.min(classBytes.length, 4096),
                    java.nio.charset.StandardCharsets.ISO_8859_1);
            if (cpCheck.contains("org/spongepowered/asm/lib/")) {
                return null; // skip — Mixin-shaded ASM not on classpath
            }
        } catch (Exception ignored) {}

        try {
            ClassReader cr = new ClassReader(classBytes);
            // Use CheckClassAdapter to verify bytecode structure and type safety.
            // The PrintWriter collects diagnostics — we only care about actual
            // bytecode corruption, not classpath limitations (Minecraft classes
            // are never on the obfuscation classpath).
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            CheckClassAdapter.verify(cr, false, pw);
            pw.flush();
            String result = sw.toString();
            if (!result.isEmpty()) {
                // Filter out classpath issues: Minecraft/Forge classes not on
                // our classpath. These are NOT bytecode corruption — they will
                // resolve fine at runtime with the full Minecraft classpath.
                if (result.contains("ClassNotFoundException")
                        || result.contains("TypeNotPresentException")
                        || result.contains("TypeNotPresent")) {
                    return null; // Classpath limitation, not a real verifier error
                }
                // Any OTHER warning is a real bytecode issue.
                return "[VERIFY-WARN] " + className.substring(className.lastIndexOf('/') + 1)
                        + ": " + result.trim().replaceAll("\\s+", " ");
            }
            return null; // OK
        } catch (Exception e) {
            Throwable root = e;
            while (root.getCause() != null) root = root.getCause();
            if (root instanceof ClassNotFoundException
                    || root instanceof java.lang.TypeNotPresentException) {
                return null; // Classpath limitation
            }
            return "[VERIFY-FAIL] " + className.substring(className.lastIndexOf('/') + 1)
                    + ": " + e.getMessage();
        }
    }

    /**
     * Classpath-independent corruption detector. Runs ASM's {@link Analyzer}
     * with a {@link BasicInterpreter} (which treats every reference as a plain
     * object, so NO external classpath — Minecraft/skija/viaversion — is
     * needed) and checks that every return instruction has a legal stack size.
     *
     * <p>This catches the specific corruption seen from control-flow /
     * decoy / string transforms where a value is left on the operand stack at
     * a {@code RETURN} (e.g. a dangling invokedynamic result). COMPUTE_FRAMES
     * faithfully records that non-empty stack, and the JVM then rejects the
     * method with {@code VerifyError: Instruction type does not match stack
     * map}. The structural {@link CheckClassAdapter} pass (dataflow=false)
     * does NOT catch this — only real dataflow analysis does.
     *
     * @return an error message, or {@code null} if the method stack sizes are
     *         legal.
     */
    @SuppressWarnings("unchecked")
    static String checkStackAtReturn(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            ClassNode cn = new ClassNode();
            cr.accept(cn, 0);
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                Frame<BasicValue>[] frames;
                try {
                    frames = new Analyzer<>(new BasicInterpreter()).analyze(cn.name, mn);
                } catch (AnalyzerException ae) {
                    return "[STACK-FAIL] " + cn.name + "." + mn.name + mn.desc
                            + ": " + ae.getMessage();
                }
                int idx = 0;
                for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null;
                     ins = ins.getNext(), idx++) {
                    int op = ins.getOpcode();
                    int want;
                    switch (op) {
                        case Opcodes.RETURN: want = 0; break;
                        case Opcodes.IRETURN: case Opcodes.FRETURN:
                        case Opcodes.ARETURN: want = 1; break;
                        // Frame.getStackSize() counts stack VALUES, not slots: a
                        // long/double occupies one entry (carrying size 2), so a
                        // LRETURN/DRETURN is correct with exactly 1 value. Using
                        // 2 here flagged EVERY long/double-returning method as
                        // "non-empty stack at return" — the original, unmodified
                        // jar alone shows 1911 such false positives — and rolled
                        // those classes back to unprotected bytes.
                        case Opcodes.LRETURN: case Opcodes.DRETURN: want = 1; break;
                        default: continue;
                    }
                    Frame<BasicValue> f = frames[idx];
                    if (f != null && f.getStackSize() != want) {
                        return "[STACK-FAIL] non-empty stack at return in "
                                + cn.name + "." + mn.name + " (stack=" + f.getStackSize() + ")";
                    }
                }
            }
        } catch (Exception e) {
            // Unparseable at this stage — let the structural verifier / JVM
            // decide; do not fail the build on a parse hiccup.
            return null;
        }
        return null;
    }

    /**
     * Compares the EMBEDDED stack-map frames of a serialized class against the
     * frames recomputed by ASM's data-flow {@link Analyzer}. A mismatch of
     * stack <em>size</em> at any frame position is exactly the corruption the
     * JVM rejects with {@code VerifyError: Current frame's stack size doesn't
     * match stackmap}.
     *
     * <p>{@link checkStackAtReturn} only inspects the recomputed frame at each
     * {@code RETURN} and never compares it to the embedded StackMapTable, so a
     * stale/wrong embedded frame (e.g. a frame that claims an extra object on
     * the stack after a control-flow / exception-table transform) sails
     * through undetected. This check closes that gap.
     *
     * <p>It is classpath-independent: {@link BasicInterpreter} treats every
     * reference as a plain one-slot value, so no external classpath
     * (Minecraft/skija/viaversion) is needed. The class is read with
     * {@code EXPAND_FRAMES} so every frame is a {@code F_FULL} carrying its
     * complete stack, making the stack-size comparison exact.
     *
     * @return an error message, or {@code null} if every embedded frame matches
     *         the recomputed data-flow.
     */
    @SuppressWarnings("unchecked")
    static String checkFrameConsistency(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            ClassNode cn = new ClassNode();
            cr.accept(cn, ClassReader.EXPAND_FRAMES);
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                Frame<BasicValue>[] frames;
                try {
                    frames = new Analyzer<>(new BasicInterpreter()).analyze(cn.name, mn);
                } catch (AnalyzerException ae) {
                    return "[STACK-FAIL] " + cn.name + "." + mn.name + mn.desc
                            + ": " + ae.getMessage();
                }
                int idx = 0;
                for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null;
                     ins = ins.getNext(), idx++) {
                    if (!(ins instanceof FrameNode)) continue;
                    FrameNode fn = (FrameNode) ins;
                    int embeddedStack = fn.stack == null ? 0 : fn.stack.size();
                    Frame<BasicValue> f = frames[idx];
                    if (f == null) continue; // unreachable position — verifier ignores it
                    if (embeddedStack != f.getStackSize()) {
                        return "[FRAME-MISMATCH] " + cn.name + "." + mn.name + mn.desc
                                + " stackmap_stack=" + embeddedStack
                                + " != computed_stack=" + f.getStackSize();
                    }
                }
            }
        } catch (Exception e) {
            // Unparseable at this stage — let the structural verifier / JVM
            // decide; do not fail the build on a parse hiccup.
            return null;
        }
        return null;
    }

    public void write(Path inputJar, Path outputJar, ClassGraph graph,
                      Mapping mapping, Path nativeLib,
                      ProtectionConfig cfg) throws IOException {
        write(inputJar, outputJar, graph, mapping, nativeLib, null, null, cfg, null, null, null, null, null);
    }

    /**
     * Full assembly with optional resource obfuscation. When {@code resMapping}
     * is non-null (and resource obfuscation is enabled), the resources in
     * {@code graph} have already been renamed/encrypted by {@code ResourceEncryptor};
     * here we additionally write:
     * <ul>
     *   <li>{@code META-INF/kbox/resources.map} — the encrypted mapping blob.</li>
     *   <li>{@code META-INF/kbox/resource-guard.bin} — the AES-256 seed.</li>
     *   <li>Inject {@code ResourceGuardLauncher} + {@code ResourceGuardClassLoader}
     *       runtime classes.</li>
     *   <li>Substitute {@code Main-Class} with the launcher, stashing the
     *       original (renamed) main class in {@code Original-Main-Class}.</li>
     * </ul>
     *
     * @param nativeBlob packed (LZ77+ChaCha20) native library blob, written to
     *                   {@code META-INF/kbox/native.bin}. When non-null, the
     *                   raw {@code nativeLib} is <em>not</em> copied next to the
     *                   jar (the lib is recovered at runtime by
     *                   {@link com.kbox.runtime.NativeLoader}).
     * @param nativeCryptoBlob packed native HKDF/decrypt library blob, written to
     *                        {@code META-INF/kbox/native-crypto.bin}. When
     *                        non-null, {@link com.kbox.runtime.NativeCrypto} (and
     *                        its unpack dependency {@code ChaCha20}) are injected
     *                        so the hardware-bound master key is derived in native
     *                        code. When null, the runtime falls back to the
     *                        byte-identical Java HKDF path.
     */
    public void write(Path inputJar, Path outputJar, ClassGraph graph,
                      Mapping mapping, Path nativeLib, byte[] nativeBlob,
                      byte[] nativeCryptoBlob,
                      ProtectionConfig cfg,
                      ResourceMapping resMapping, byte[] resSeed,
                      byte[] vmpBlob,
                      byte[] epdManifest,
                      com.kbox.core.packaging.NativeLibPacker.Result natLibs) throws IOException {
        Path parent = outputJar.getParent();
        if (parent != null) Files.createDirectories(parent);
        Map<String, String> classMap = mapping != null ? mapping.getClassMap() : java.util.Collections.emptyMap();
        // Reverse class map (renamed → original) so a rollback can resolve the
        // ORIGINAL bytes for a class whose graph key is the RENAMED name.
        Map<String, String> reverseClassMap = new java.util.HashMap<>();
        for (Map.Entry<String, String> en : classMap.entrySet()) {
            reverseClassMap.putIfAbsent(en.getValue(), en.getKey());
        }
        boolean resourceGuard = cfg.isObfuscateResources() && resMapping != null;
        // Detect Forge/Fabric mods: these frameworks scan ALL class bytes
        // in the jar with ClassReader at boot time.  Encrypted classes
        // (which start with "KBCE" instead of "CAFEBABE") cause
        // ArrayIndexOutOfBoundsException inside ClassReader.<init> and
        // the mod fails to load.  Therefore we silently disable class
        // encryption for mod jars (identified by the TweakClass manifest
        // attribute used by Forge LaunchWrapper / Mixin).
        boolean isForgeMod = graph.getManifest() != null
                && new String(graph.getManifest(), StandardCharsets.UTF_8).contains("TweakClass:");
        boolean classGuard = cfg.isEncryptClasses() && !isForgeMod;
        if (cfg.isEncryptClasses() && isForgeMod) {
            KBoxLog.warn(TAG, "encryptClasses disabled: Forge/FML scans raw jar bytes "
                    + "via ClassReader and cannot parse AES-GCM encrypted classes. "
                    + "Use encryptClasses only with standalone jars (java -jar).");
        }
        // Forge/FML uses its own LaunchWrapper ClassLoader chain, which
        // bypasses KBox's ResourceGuardClassLoader.  Obfuscated resource
        // paths cannot be resolved, leading to NPE at runtime when
        // Class.getResourceAsStream() returns null for renamed resources.
        if (cfg.isObfuscateResources() && isForgeMod) {
            KBoxLog.warn(TAG, "obfuscateResources disabled: Forge/FML uses its own "
                    + "ClassLoader chain which cannot resolve KBox-obfuscated "
                    + "resource paths. Use obfuscateResources only with standalone jars.");
            resourceGuard = false;
        }
        boolean needGuard = resourceGuard || classGuard;
        // Class encryption seed: reuse the resource seed, or generate a new one.
        byte[] classSeed = null;
        java.util.Set<String> encryptedClassNames = null;
        try (ZipFile in = new ZipFile(inputJar.toFile());
             ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(outputJar))) {

            boolean springBoot = graph.isSpringBootFatJar();
            String clsRoot = springBoot ? "BOOT-INF/classes/" : "";
            // protectNativeLibs 是否真的产出了原生库 blob（决定启动器接管与条目替换）。
            boolean natLibsActive = natLibs != null && !natLibs.entries.isEmpty();
            ResourceReferenceUpdater ru = new ResourceReferenceUpdater(classMap);
            ManifestUpdater mu = new ManifestUpdater(classMap);
            mu.setSpringBootFatJar(springBoot);

            // 1. Write classes (renamed paths). If class encryption is on,
            //    eligible classes are AES-GCM encrypted with a magic header.
            Map<String, byte[]> written = new LinkedHashMap<>();
            if (classGuard) {
                classSeed = resSeed != null ? resSeed : newSeed();
                encryptedClassNames = new java.util.TreeSet<>();
            }
            int rolledBack = 0;
            int verifyFails = 0;

            // --- Fix cross-package access after identifier renaming ---
            // Identifier renaming may scatter classes that were originally
            // in the same package into different packages.  Package-private
            // classes lose accessibility → IllegalAccessError at runtime.
            // Scan all instructions and widen to public where needed.
            fixCrossPackageClassAccess(graph, classMap);

            // --- Repair dangling member references after identifier renaming ---
            // Some references to members declared in an interface (accessed via
            // an implementing class) or inherited through a super-interface can
            // escape NameObfuscator's resolve pass and keep their ORIGINAL name
            // while the declaration was renamed -> NoSuchFieldError /
            // NoSuchMethodError at runtime. Resolve every field/method reference
            // against the FINAL renamed graph and rewrite any dangling one to the
            // actual declaring member's renamed name.
            repairDanglingMemberReferences(graph, mapping);

            // --- Native (JNIC) plain-class closure ---
            // JNIC owner classes are pre-loaded by the SYSTEM classloader BEFORE
            // the resource-guard loader exists, so every class transitively
            // reachable from a JNIC owner must be written PLAIN (never encrypted).
            // If any such dependency were encrypted (KBCE magic), the system
            // loader reads raw bytes and dies with ClassFormatError.
            Set<String> nativePlainClosure = computeJnicPlainClosure(graph, cfg, reverseClassMap);

            // --- Parent-delegated library classes (single-loader guarantee) ---
            // Library-classified in-jar classes (org.objectweb.asm.*, kotlin.*, any
            // third-party prefix) must be loaded by the PARENT (app) loader, never
            // re-defined locally by the guard loader. Otherwise a bytecode engine
            // like ASM ends up with two copies (app-loader + guard-loader) and any
            // cross-loader class hand-off throws ClassCastException — exactly what
            // killed self-obfuscated KBox when its own ASM ran under the guard.
            // Library classes are never renamed/encrypted, so the graph key IS the
            // runtime internal name. Strongest at self-host time: single ASM copy.
            java.util.Set<String> parentDelegate = new java.util.LinkedHashSet<>();
            if (needGuard) {
                for (String k : graph.getClasses().keySet()) {
                    if (cfg.isLibraryClass(k)) parentDelegate.add(k);
                }
                // protectNativeLibs: 声明 native 方法的类必须由父（系统）加载器定义。
                // 原生库由 NativeLoader 在系统加载器命名空间下 System.load，而 JNI 符号
                // 只在「定义该类的加载器」命名空间内解析；守卫加载器对非 JDK 类是 parent-last
                // （自行 defineClass），若这些类被它定义，调用 native 方法必抛
                // UnsatisfiedLinkError（实测）。JNIC 用 jnic-classes.list 解决同一问题，
                // 业务原生库的声明类无法预知，故泛化为「所有含 native 方法的类」。
                if (natLibsActive) {
                    int natCls = 0;
                    for (Map.Entry<String, ClassNode> ce : graph.getClasses().entrySet()) {
                        if (!declaresNativeMethod(ce.getValue())) continue;
                        String renamed = mapName(classMap, ce.getKey());
                        if (parentDelegate.add(renamed)) natCls++;
                    }
                    if (natCls > 0) {
                        KBoxLog.info(TAG, "Parent-delegating " + natCls
                                + " class(es) declaring native methods (native lib JNI symbol resolution)");
                    }
                }
            }

            // Remove resource-guard runtime classes from the graph before
            // serialization.  They were loaded by VmpRuntimeProtector for
            // VMP injection into decryption logic, but the original compiler
            // frames may have missing StackMapTable entries (javac bug).
            // injectResourceGuardClasses will re-serialize fresh copies with
            // version 49 (inference verifier, no StackMapTable required).
            java.util.Set<String> guardSkip = new java.util.HashSet<>();
            if (needGuard) {
                guardSkip.addAll(discoverGuardClasses());
            }

            for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
                if (guardSkip.contains(e.getKey())) {
                    continue; // written by injectResourceGuardClasses later
                }
                // Classes that came from a nested BOOT-INF/lib jar are analysis-only:
                // their bytes are shipped verbatim inside that nested jar, so
                // re-emitting them here would duplicate every library class into
                // BOOT-INF/classes/ (a real 60 MB -> 121 MB bloat) and shadow the
                // nested jars on the application classpath.
                if (graph.getNestedJarClasses().contains(e.getKey())) {
                    continue;
                }
                String oldInternal = e.getKey();
                String newInternal = mapName(classMap, oldInternal);
                String entryName = clsRoot + newInternal + ".class";
                byte[] bytes = serialize(e.getValue(), graph, cfg);
                if (bytes == null) {
                    // Serialization failed entirely. Roll back to original bytes
                    // when the flag is on (default), so the build never produces
                    // a broken jar — worst case the class is unobfuscated.
                    if (cfg.isRollbackToOriginalBytes()) {
                        byte[] orig = lookupOriginalBytes(oldInternal, reverseClassMap, graph);
                        if (orig != null) {
                            bytes = remapRollbackBytes(orig, mapping, graph);
                            rolledBack++;
                            KBoxLog.warn(TAG, "Rolled back " + newInternal
                                    + " to original bytes (serialization failed)");
                        } else {
                            KBoxLog.warn(TAG, "Skipping class " + newInternal
                                    + " (serialization failed, no original bytes)");
                            continue;
                        }
                    } else {
                        KBoxLog.warn(TAG, "Skipping class " + newInternal + " (serialization failed)");
                        continue;
                    }
                }

                // === JVM Bytecode Verification (CheckClassAdapter) ===
                // After serialization, run ASM's built-in verifier to detect
                // type-safety violations BEFORE they hit the JVM's VerifyError.
                // This catches: Bad type on operand stack, incompatible exception
                // handler types, corrupt StackMapTable data, etc.
                // On failure, roll back to the original (pre-obfuscation) bytes.
                String verifyErr = verifyClassBytes(bytes, newInternal);
                if (verifyErr == null) {
                    // Structural CheckClassAdapter (dataflow=false) does NOT catch
                    // "value left on stack at RETURN". Run a classpath-independent
                    // dataflow check that does, and roll back if it fires.
                    verifyErr = checkStackAtReturn(bytes);
                }
                if (verifyErr == null) {
                    // Compare embedded StackMapTable frames against the
                    // recomputed data-flow. A stale embedded frame (extra/missing
                    // stack item) is exactly the corruption the JVM rejects with
                    // "Current frame's stack size doesn't match stackmap".
                    verifyErr = checkFrameConsistency(bytes);
                }
                if (verifyErr != null) {
                    byte[] orig = lookupOriginalBytes(oldInternal, reverseClassMap, graph);
                    // Regression gate. [STACK-FAIL] comes from a dataflow oracle
                    // (Analyzer + BasicInterpreter) that ALSO mis-flags the
                    // pristine input — 285 methods of the raw LiquidBounce jar,
                    // almost all Kotlin coroutine state machines — because it
                    // reports an inflated stack size for them. A verdict that
                    // reproduces on the untouched original bytes is therefore an
                    // oracle artifact, not damage we introduced: keep the
                    // protected bytes instead of throwing the hardening away.
                    if (orig != null && verifyErr.startsWith("[STACK-FAIL]")
                            && checkStackAtReturn(orig) != null) {
                        verifyErr = null;
                    }
                }
                if (verifyErr != null) {
                    // TEMP-DIAG: dump the verify-failing transformed bytes for analysis.
                    try {
                        java.nio.file.Files.write(
                                java.nio.file.Paths.get("kbox-verify-dump-" + newInternal.replace('/', '_') + ".class"),
                                bytes);
                    } catch (Exception ignoredDump) {}
                    byte[] orig = lookupOriginalBytes(oldInternal, reverseClassMap, graph);
                    if (orig != null) {
                        KBoxLog.warn(TAG, "Verify failed: " + verifyErr
                                + " — rolling back to original bytes");
                        bytes = remapRollbackBytes(orig, mapping, graph);
                        verifyFails++;
                    }
                }
                if (classGuard && shouldEncryptClass(e.getValue(), graph, newInternal,
                        oldInternal, cfg, nativePlainClosure)) {
                    try {
                        bytes = encryptClassBody(bytes, classSeed, licenseMaterial(cfg));
                        encryptedClassNames.add(newInternal);
                    } catch (Exception ex) {
                        KBoxLog.warn(TAG, "Class encryption failed for " + newInternal + ": " + ex.getMessage());
                    }
                }
                putEntry(out, entryName, bytes);
                written.put(newInternal, bytes);
            }
            KBoxLog.info(TAG, "Wrote " + written.size() + " classes"
                    + (encryptedClassNames != null ? " (" + encryptedClassNames.size() + " encrypted)" : "")
                    + (rolledBack > 0 ? " (" + rolledBack + " rolled back to original)" : "")
                    + (verifyFails > 0 ? " (" + verifyFails + " verify-failed, rolled back)" : ""));

            // 2. Copy resources. Framework text files (META-INF/services/*,
            //    spring.factories, AutoConfiguration.imports) go through
            //    ResourceReferenceUpdater for class-name rewriting. Everything
            //    else (binary resources, already-renamed/encrypted files) is
            //    written as raw bytes so we never corrupt a PNG/JKS blob.
            int resCount = 0;
            for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
                String path = e.getKey();
                byte[] bytes = e.getValue();
                if (path.equals("META-INF/MANIFEST.MF")) continue;
                // Jar 内自带原生库已由 protectNativeLibs 打包成 META-INF/kbox/natlib/*.bin，
                // 明文条目不再写入产物 jar（避免明文 dll/so 外泄）。
                if (natLibs != null && natLibs.contains(path)) continue;
                if (isFrameworkText(path)) {
                    String res = ru.rewrite(path, bytes);
                    int nul = res.indexOf('\u0000');
                    String newPath = nul >= 0 ? res.substring(0, nul) : path;
                    String newContent = nul >= 0 ? res.substring(nul + 1) : new String(bytes, StandardCharsets.UTF_8);
                    putEntry(out, clsRoot + newPath, newContent.getBytes(StandardCharsets.UTF_8));
                } else {
                    // Binary or already-processed resource: write raw bytes.
                    // Resource keys are LOGICAL paths (a Spring Boot fat jar strips
                    // the BOOT-INF/classes/ prefix when reading, see
                    // DependencyAnalyzer); re-add clsRoot so the entry lands where
                    // the runtime classloader actually looks for it.
                    putEntry(out, clsRoot + path, bytes);
                }
                resCount++;
            }
            KBoxLog.info(TAG, "Wrote " + resCount + " resources");

            // 3. Manifest. When resource guard or class guard is on:
            //    - For standalone jars (Main-Class present): substitute with launcher.
            //    - For Forge mods (TweakClass present): prepend decrypt tweaker.
            String launcherClass = (resourceGuard || classGuard || natLibsActive)
                    ? "com.kbox.runtime.ResourceGuardLauncher" : null;
            // Only prepend TweakClass when class encryption is on AND the jar
            // has a TweakClass (i.e., it's a Forge/Fabric mod, not standalone jar).
            boolean hasTweakClass = graph.getManifest() != null
                    && new String(graph.getManifest(), StandardCharsets.UTF_8).contains("TweakClass:");
            String tweakerClass = (classGuard && hasTweakClass)
                    ? "com.kbox.runtime.KBoxClassDecryptTweaker" : null;
            // Spring Boot jars hook the launcher in through Start-Class (Main-Class
            // must stay the boot loader), so the class to remap is Start-Class.
            String entryClass = springBoot ? graph.getManifestStartClass()
                                           : graph.getManifestMainClass();
            if (entryClass == null) entryClass = graph.getManifestMainClass();
            byte[] manifest = mu.update(graph.getManifest(),
                    dotted(entryClass), launcherClass, tweakerClass);
            // Entry-point obfuscation: mask the real main class name in the
            // manifest so a static dump can't trivially spot the application's
            // main() class. Only applied when the launcher substitution occurred
            // (i.e. standalone jars with Main-Class), and only when enabled.
            if (launcherClass != null && manifest != null && cfg.isObfuscateEntryPoint()) {
                manifest = obfuscateEntryPoint(manifest);
            }
            if (manifest != null) putEntry(out, "META-INF/MANIFEST.MF", manifest);
            // Per-build key seed: embed the build-injected 32-byte seed so the run
            // JVM's HardwareKeyRing reads the SAME seed and re-derives the same
            // blob keys (build↔run agreement), while each build ships a unique seed.
            {
                byte[] bseed = com.kbox.runtime.HardwareKeyRing.currentBuildSeed();
                if (bseed != null && bseed.length == 32) {
                    putEntry(out, clsRoot + "META-INF/kbox/seed.bin", bseed);
                }
            }
            // Engine tamper seal: bind this output to the CURRENT engine license
            // session. If the engine license gate was stripped/bypassed, the
            // session key is random, so the seal fingerprints a unlicensed build.
            try {
                putEntry(out, "KBox-Engine-Seal", sealOutput(cfg, inputJar));
            } catch (Throwable ignoredSeal) { }

            // 4. Inject runtime classes needed by the protected bytecode.
            // A SINGLE shared set prevents duplicate entries when the same runtime
            // class is required by more than one feature (e.g. ChaCha20 by both
            // the VMP keystream and the JNIC native loader).
            java.util.Set<String> rtInjected = new java.util.HashSet<>();
            int rtCount = injectRuntimeClasses(out, clsRoot, cfg, graph, rtInjected);
            // 4a. Licensing: embed the (masked) publisher public key + verifier.
            if (cfg.isLicensed()) {
                rtCount += injectRuntimeClassesLicensing(out, clsRoot, cfg, graph, rtInjected);
            }
            if (needGuard) {
                rtCount += injectResourceGuardClasses(out, clsRoot, graph);
                if (resourceGuard) {
                    writeResourceGuardMetadata(out, clsRoot, resMapping, resSeed);
                }
                if (classGuard && encryptedClassNames != null) {
                    writeClassGuardMetadata(out, clsRoot, encryptedClassNames, classSeed);
                }
                // Library-classified in-jar classes (asm/kotlin/third-party) must be
                // loaded by the PARENT loader, never re-defined locally by the guard
                // loader, or ASM-style engines land with two copies -> ClassCastException.
                writeParentDelegateList(out, clsRoot, parentDelegate);
            } else if (launcherClass != null) {
                // protectNativeLibs-only（无资源/类加密）: Main-Class 仍交给
                // ResourceGuardLauncher（它在 seed 缺失时直接透传原 main）。启动器
                // main() 无条件调用 AntiDebug/IntegrityChecker，且其字节码引用
                // ResourceGuardClassLoader（类型校验期即解析），故需连同整套
                // ResourceGuard* 类一起注入。
                rtCount += injectResourceGuardClasses(out, clsRoot, graph);
                rtCount += injectOne(out, clsRoot, "com/kbox/runtime/AntiDebug", rtInjected, graph);
                rtCount += injectOne(out, clsRoot, "com/kbox/runtime/IntegrityChecker", rtInjected, graph);
            }
            // 4b. JNIC: write the packed native blob + inject NativeLoader/ChaCha20.
            if (nativeBlob != null) {
                putEntry(out, clsRoot + "META-INF/kbox/native.bin", nativeBlob);
                writeJnicClassList(out, clsRoot, cfg);
                rtCount += injectNativeLoaderClasses(out, clsRoot, graph, rtInjected);
                KBoxLog.info(TAG, "Wrote packed native blob ("
                        + nativeBlob.length + " bytes) -> META-INF/kbox/native.bin");
            }
            // 4c. Native crypto: write the packed HKDF/decrypt library + inject
            //     NativeCrypto (plus ChaCha20, which NativeCrypto.unpack needs).
            //     Purely additive; when the blob is absent the runtime uses the
            //     byte-identical Java HKDF path, so this block is optional.
            if (nativeCryptoBlob != null) {
                putEntry(out, clsRoot + "META-INF/kbox/native-crypto.bin", nativeCryptoBlob);
                rtCount += injectOne(out, clsRoot, "com/kbox/runtime/NativeCrypto", rtInjected, graph);
                rtCount += injectOne(out, clsRoot, "com/kbox/runtime/ChaCha20", rtInjected, graph);
                rtCount += injectOne(out, clsRoot, "com/kbox/runtime/KbnlKey", rtInjected, graph);
                KBoxLog.info(TAG, "Wrote packed native crypto blob ("
                        + nativeCryptoBlob.length + " bytes) -> META-INF/kbox/native-crypto.bin");
            }
            // 4d. VM原生化: write the packed native VMP interpreter (vmp.bin). The
            //     runtime seam VmpInterpreterNative loads it on demand; when the blob
            //     is absent (compile disabled/failed) the byte-identical Java
            //     interpreter runs instead, so this block is strictly additive.
            if (vmpBlob != null) {
                putEntry(out, clsRoot + "META-INF/kbox/vmp.bin", vmpBlob);
                // The seam (VmpInterpreterNative.tryExecute) depends on
                // NativeLoader.loadVmp(), which must be present even when JNIC is
                // off/empty (otherwise NoClassDefFoundError silently kills the
                // native path and we fall back to Java). Inject the loader classes
                // alongside the blob.
                rtCount += injectNativeLoaderClasses(out, clsRoot, graph, rtInjected);
                KBoxLog.info(TAG, "Wrote packed VMP native blob ("
                        + vmpBlob.length + " bytes) -> META-INF/kbox/vmp.bin");
            }
            // 4e. protectNativeLibs: jar 内自带原生库（.dll/.so/.dylib）加壳产物。
            //     每个库一个 KBNL blob（META-INF/kbox/natlib/N.bin），清单
            //     natlibs.list 记录「逻辑路径|blob路径|扩展名」，运行时
            //     NativeLoader.loadNativeLibs() 按 OS 匹配扩展名解密落盘加载。
            //     明文原生库从不进入产物 jar。
            if (natLibsActive) {
                for (com.kbox.core.packaging.NativeLibPacker.Entry en : natLibs.entries) {
                    putEntry(out, clsRoot + en.blobPath, natLibs.blobs.get(en.blobPath));
                }
                StringBuilder lb = new StringBuilder();
                for (com.kbox.core.packaging.NativeLibPacker.Entry en : natLibs.entries) {
                    lb.append(en.logicalPath).append('|')
                      .append(en.blobPath).append('|')
                      .append(en.ext).append('\n');
                }
                putEntry(out, clsRoot + "META-INF/kbox/natlibs.list",
                        lb.toString().getBytes(StandardCharsets.UTF_8));
                rtCount += injectNativeLoaderClasses(out, clsRoot, graph, rtInjected);
                KBoxLog.info(TAG, "Wrote " + natLibs.entries.size()
                        + " packed native lib blob(s) -> META-INF/kbox/natlib/*.bin (+ natlibs.list)");
            }
            if (epdManifest != null && epdManifest.length > 0) {
                putEntry(out, clsRoot + "META-INF/kbox/method_epd.bin", epdManifest);
                KBoxLog.info(TAG, "Wrote EPL binning manifest ("
                        + epdManifest.length + " bytes) -> META-INF/kbox/method_epd.bin");
            }
            if (cfg.isIntegrityCheck()) {
                writeIntegrityHash(out, written, clsRoot);
            }
            if (rtCount > 0) {
                KBoxLog.info(TAG, "Injected " + rtCount + " runtime classes");
            }
            // Every KBox-owned helper referenced by the classes we just wrote must
            // actually be in the output. Several passes synthesize per-build
            // helpers (string/constant holders, type-confusion carriers, ...) and
            // rewrite call sites to point at them; a dropped helper only shows up
            // as a bare NoClassDefFoundError at runtime, with no hint about which
            // pass lost it. Turn that into a build error instead.
            verifyKboxReferenceClosure(written, rtInjected, guardSkip);
            // Anti-unpack decoys: harmless entries that confuse extractor tools
            // (dir/file masquerade, bad-CRC bait, decoy native lib) without affecting
            // the running app. Only when resource obfuscation is active (max mode).
            if (cfg.isObfuscateResources()) {
                writeAntiUnpackDecoys(out);
            }
            // S5 (kboxDedeobfShieldV1): second-tier mock fill decoys (gated).
            if (cfg.getBlobMockFill() > 0) {
                writeMockFill(out, cfg);
            }

            // 5. Spring Boot: copy nested lib jars verbatim from input.
            if (springBoot) {
                Enumeration<? extends ZipEntry> en = in.entries();
                while (en.hasMoreElements()) {
                    ZipEntry ze = en.nextElement();
                    if (ze.isDirectory() || !ze.getName().startsWith("BOOT-INF/lib/")) continue;
                    if (!ze.getName().endsWith(".jar")) continue;
                    // STORED (uncompressed), NOT deflated — see putStoredEntry.
                    putStoredEntry(out, ze.getName(), readAll(in.getInputStream(ze)));
                }
                Enumeration<? extends ZipEntry> en2 = in.entries();
                while (en2.hasMoreElements()) {
                    ZipEntry ze = en2.nextElement();
                    if (ze.isDirectory()) continue;
                    String n = ze.getName();
                    if (n.startsWith("org/springframework/boot/loader/") && n.endsWith(".class")) {
                        putEntry(out, n, readAll(in.getInputStream(ze)));
                    }
                }
                // Structural entries the boot loader resolves BEFORE any application
                // code runs. These must survive verbatim:
                //   * BOOT-INF/classpath.idx — Boot 3.2+ builds the launched
                //     classloader's URL set from this index. If it is missing or
                //     renamed, the classpath comes up EMPTY and every
                //     BOOT-INF/classes|lib lookup fails with ClassNotFoundException.
                //   * BOOT-INF/layers.idx — layered-jar metadata (same reasoning).
                Enumeration<? extends ZipEntry> en3 = in.entries();
                while (en3.hasMoreElements()) {
                    ZipEntry ze = en3.nextElement();
                    String n = ze.getName();
                    if (n.equals("BOOT-INF/classpath.idx") || n.equals("BOOT-INF/layers.idx")) {
                        putEntry(out, n, readAll(in.getInputStream(ze)));
                    }
                }
                // Directory entries, all of them. Two independent reasons:
                //   1. BOOT-INF/classes/ and BOOT-INF/lib/ ARE the boot loader's
                //      nested classpath roots — without those two directory entries
                //      no application class can be loaded at all.
                //   2. Spring's component scan resolves
                //      "classpath*:com/example/**/*.class" by asking the loader for
                //      the package directory ("com/example/") and walking it. With
                //      the package directories missing the scan yields NOTHING, so
                //      every @Component/@Service/@Repository silently disappears and
                //      the app dies later with NoSuchBeanDefinitionException — a
                //      failure that looks nothing like a packaging problem.
                // The analyzer skips directories generically, so re-emit them here.
                Enumeration<? extends ZipEntry> en4 = in.entries();
                while (en4.hasMoreElements()) {
                    ZipEntry ze = en4.nextElement();
                    if (ze.isDirectory()) {
                        putEntry(out, ze.getName(), new byte[0]);
                    }
                }
            }
        }

        // 6. Copy native lib next to the output jar — only when we did NOT pack
        //    it into META-INF/kbox/native.bin. When a packed blob is present, the
        //    raw .dll/.so never ships in or next to the jar.
        if (nativeBlob == null && nativeLib != null && Files.exists(nativeLib)) {
            Path target = outputJar.resolveSibling(nativeLib.getFileName());
            Files.copy(nativeLib, target, StandardCopyOption.REPLACE_EXISTING);
            KBoxLog.info(TAG, "Copied native lib to " + target);
        }
        KBoxLog.info(TAG, "Wrote protected jar: " + outputJar);
    }

    /**
     * Assembles a <b>Brainfuck chaos</b> protected jar ({@code brainfuckLoader}).
     *
     * <p>Unlike {@link #write}, no class or resource file is written in the
     * clear. The whole (already obfuscated) jar content is DEFLATE'd, turned
     * into a Brainfuck program and RLE-compressed into
     * {@code META-INF/kbox/classes.bf.rle}; the name&rarr;(offset,len) index is
     * embedded as a signed header at the head of that raw blob and parsed only
     * inside the native decode heap (no separate index file, no offset reaches
     * Java). The jar itself contains only:</p>
     *
     * <ul>
     *   <li>the manifest ({@code Main-Class} = {@code BfSecureLoader},
     *       {@code Original-Main-Class} = renamed entry point),</li>
     *   <li>the single Brainfuck payload,</li>
     *   <li>the packed native decoder ({@code META-INF/kbox/native.bin}) and</li>
     *   <li>the plain KBox runtime classes (loader + NativeLoader + ChaCha20 +
     *       whatever the active features need).</li>
     * </ul>
     *
     * <p>No {@code CAFEBABE} magic, no readable class names, no resources exist
     * in the jar. {@link com.kbox.runtime.BfSecureLoader} reconstructs everything
     * in native memory at startup.</p>
     *
     * @param inputJar    original input jar (for the engine seal).
     * @param outputJar   destination jar.
     * @param nativeBlob  packed decoder blob from
     *                    {@link com.kbox.core.brainfuck.BfNativeBuilder}; must
     *                    be non-null (there is no fall-back path).
     * @param sym         the per-build Brainfuck symbol set — must be the SAME
     *                    instance passed to {@link BfNativeBuilder#build} so the
     *                    payload encoding and the native decoder agree.
     */
    public void writeBrainfuck(Path inputJar, Path outputJar, ClassGraph graph,
                               Mapping mapping, byte[] nativeBlob,
                               byte[] jnicBlob, ProtectionConfig cfg,
                               BfSymbolSet sym, byte[] vmpBlob,
                               byte[] nativeCryptoBlob,
                               byte[] epdManifest) throws IOException {
        Path parent = outputJar.getParent();
        if (parent != null) Files.createDirectories(parent);
        if (nativeBlob == null) {
            throw new IOException("KBox-BF: native decoder blob missing — "
                    + "could not build/compile kbox_bf_loader.c");
        }
        Map<String, String> classMap = mapping != null
                ? mapping.getClassMap() : java.util.Collections.emptyMap();
        Map<String, String> reverseClassMap = new java.util.HashMap<>();
        for (Map.Entry<String, String> en : classMap.entrySet()) {
            reverseClassMap.putIfAbsent(en.getValue(), en.getKey());
        }

        // BF-MC hybrid (opt-in): detect the loader and keep its critical surface
        // plaintext — loader metadata (protectedResources) + entry classes + the
        // mixin package (keepPrefixes) are written as readable jar entries; every
        // other class still hides inside the Brainfuck-RLE blob. Entry classes get
        // BfSecureLoader.attach() injected into <clinit> so the blob is decoded the
        // moment the loader first touches the mod.
        boolean hybrid = cfg.isBrainfuckMcHybrid();
        java.util.Set<String> plainClasses = new java.util.HashSet<>();    // renamed internal names kept plaintext
        java.util.Set<String> plainResources = new java.util.HashSet<>();  // resource paths kept plaintext
        if (hybrid) {
            try {
                com.kbox.core.minecraft.MinecraftModDetector mc =
                        new com.kbox.core.minecraft.MinecraftModDetector(graph, cfg);
                com.kbox.core.minecraft.MinecraftModDetector.Result r = mc.detect();
                if (r.isMod()) {
                    plainResources.addAll(r.protectedResources);
                    for (String dotted : r.entryClasses) {
                        plainClasses.add(dotted.replace('.', '/'));
                    }
                    for (String prefix : r.keepPrefixes) {
                        for (String internal : graph.getClasses().keySet()) {
                            if (internal.startsWith(prefix)) plainClasses.add(internal);
                        }
                    }
                    KBoxLog.info(TAG, "BF hybrid keeps plaintext: "
                            + plainClasses.size() + " classes, " + plainResources.size()
                            + " resource paths (" + r.loader + ")");
                } else {
                    KBoxLog.warn(TAG, "BF hybrid: no MC loader detected — all classes go into the blob");
                }
            } catch (Throwable t) {
                KBoxLog.warn(TAG, "BF hybrid detection failed: " + t.getMessage()
                        + " — all classes go into the blob");
            }
        }

        // 1. Same correctness repairs as the normal path.
        fixCrossPackageClassAccess(graph, classMap);
        repairDanglingMemberReferences(graph, mapping);

        // 2. Serialize every graph class into the blob map (renamed keys).
        //    Hybrid mode: loader-critical classes (entry classes + mixin package)
        //    are serialized as PLAINTEXT jar entries instead of the blob, with
        //    BfSecureLoader.attach() injected into <clinit>.
        Map<String, byte[]> classes = new LinkedHashMap<>();
        Map<String, byte[]> plainClassBytes = new LinkedHashMap<>();
        int rolledBack = 0;
        int verifyFails = 0;
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            String oldInternal = e.getKey();
            String newInternal = mapName(classMap, oldInternal);
            if (hybrid && plainClasses.contains(oldInternal)) {
                // Keep this class readable by the mod loader.
                injectBfAttach(e.getValue());
                byte[] pbytes = serialize(e.getValue(), graph, cfg);
                if (pbytes != null) {
                    plainClassBytes.put(newInternal, pbytes);
                    continue;
                }
                KBoxLog.warn(TAG, "BF hybrid skip (serialization failed) " + newInternal
                        + " — falling through to blob");
            }
            byte[] bytes = serialize(e.getValue(), graph, cfg);
            if (bytes == null) {
                if (cfg.isRollbackToOriginalBytes()) {
                    byte[] orig = lookupOriginalBytes(oldInternal, reverseClassMap, graph);
                    if (orig != null) {
                        bytes = remapRollbackBytes(orig, mapping, graph);
                        rolledBack++;
                    } else {
                        KBoxLog.warn(TAG, "BF skip " + newInternal
                                + " (serialization failed, no original bytes)");
                        continue;
                    }
                } else {
                    KBoxLog.warn(TAG, "BF skip " + newInternal + " (serialization failed)");
                    continue;
                }
            }
            String verifyErr = verifyClassBytes(bytes, newInternal);
            if (verifyErr == null) verifyErr = checkStackAtReturn(bytes);
            if (verifyErr == null) verifyErr = checkFrameConsistency(bytes);
            if (verifyErr != null) {
                KBoxLog.warn(TAG, "BF verify-fail " + newInternal + ": " + verifyErr);
                try { java.nio.file.Files.write(java.nio.file.Paths.get("_bf-vfdump-" + newInternal.replace('/', '_') + ".class"), bytes); } catch (Throwable t) {}
                byte[] orig = lookupOriginalBytes(oldInternal, reverseClassMap, graph);
                if (orig != null) {
                    bytes = remapRollbackBytes(orig, mapping, graph);
                    verifyFails++;
                }
            }
            classes.put(newInternal, bytes);
        }
        KBoxLog.info(TAG, "BF packed " + classes.size() + " classes"
                + (rolledBack > 0 ? " (" + rolledBack + " rolled back)" : "")
                + (verifyFails > 0 ? " (" + verifyFails + " verify-failed)" : ""));

        // 3. Resources (BF disables resource obfuscation, so names are original).
        //    Framework text files (services/spring.factories) still get their
        //    class references rewritten to the renamed names. They are kept as
        //    PLAINTEXT jar entries (not in the blob): ServiceLoader/Spring
        //    resolve them via the URL-based ClassLoader APIs (getResources),
        //    which the BF loader cannot serve from the blob without injecting a
        //    URLStreamHandler class. Plaintext framework text leaks only
        //    (renamed) class names, on par with the manifest / native blobs.
        Map<String, byte[]> resources = new LinkedHashMap<>();
        Map<String, byte[]> plainFramework = new LinkedHashMap<>();
        ResourceReferenceUpdater ru = new ResourceReferenceUpdater(classMap);
        for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            String path = e.getKey();
            byte[] bytes = e.getValue();
            if (path.equals("META-INF/MANIFEST.MF")) continue;
            // Hybrid mode: loader-critical metadata (fabric.mod.json, mods.toml,
            // mixins.json, pack.mcmeta, FMLAT/accesswidener, ...) stays plaintext
            // verbatim — the loader parses these raw, so a rewritten/obfuscated
            // copy would break discovery even when the entry classes are kept.
            if (hybrid && plainResources.contains(path)) {
                plainFramework.put(path, bytes);
                continue;
            }
            if (isFrameworkText(path)) {
                String res = ru.rewrite(path, bytes);
                int nul = res.indexOf('\u0000');
                String newPath = nul >= 0 ? res.substring(0, nul) : path;
                String newContent = nul >= 0 ? res.substring(nul + 1)
                        : new String(bytes, StandardCharsets.UTF_8);
                plainFramework.put(newPath, newContent.getBytes(StandardCharsets.UTF_8));
            } else {
                resources.put(path, bytes);
            }
        }

        // 4. Engine runtime classes go INTO the blob (not plain jar entries), so
        //    the protection engine itself is not trivially decompilable. Only the
        //    bootstrap triad (BfSecureLoader + NativeLoader + ChaCha20) stays
        //    plaintext — it must run before the blob can be decoded at all.
        int rtBlob = collectRuntimeClassesForBlob(cfg, graph, classes, resources);
        if (rtBlob > 0) {
            KBoxLog.info(TAG, "BF moved " + rtBlob
                    + " engine runtime classes into the blob (no plaintext engine)");
        }

        // 5. Deflate -> Brainfuck -> RLE + index. The symbol set is per-build
        //    (randomized for each build and baked into the native decoder), so
        //    no two KBox-BF builds ship a byte-identical payload.
        BrainfuckPacker.Result packed = BrainfuckPacker.pack(classes, resources, sym);

        // 5. Assemble the tiny jar.
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(outputJar))) {
            String clsRoot = ""; // Brainfuck mode is standalone-jar only.
            ManifestUpdater mu = new ManifestUpdater(classMap);
            byte[] manifest = mu.update(graph.getManifest(),
                    dotted(graph.getManifestMainClass()),
                    "com.kbox.runtime.BfSecureLoader");
            // NOTE: entry-point obfuscation (obfuscateEntryPoint) is intentionally
            // NOT applied — BfSecureLoader reads Original-Main-Class verbatim.
            if (manifest != null) putEntry(out, "META-INF/MANIFEST.MF", manifest);
            // Per-build key seed (BF mode): embedded as a plain jar entry so the
            // run JVM's HardwareKeyRing reads the same seed and re-derives the
            // same blob keys without re-hiding it inside the BF payload.
            {
                byte[] bseed = com.kbox.runtime.HardwareKeyRing.currentBuildSeed();
                if (bseed != null && bseed.length == 32) {
                    putEntry(out, "META-INF/kbox/seed.bin", bseed);
                }
            }

            for (Map.Entry<String, byte[]> pf : plainFramework.entrySet()) {
                putEntry(out, pf.getKey(), pf.getValue());
            }
            if (!plainFramework.isEmpty()) {
                KBoxLog.info(TAG, "BF kept framework text as plain jar entries: "
                        + plainFramework.keySet());
            }
            // Hybrid mode: loader-critical classes written as plaintext .class
            // entries (with BfSecureLoader.attach() in <clinit>).
            if (!plainClassBytes.isEmpty()) {
                for (Map.Entry<String, byte[]> pc : plainClassBytes.entrySet()) {
                    putEntry(out, pc.getKey() + ".class", pc.getValue());
                }
                KBoxLog.info(TAG, "BF hybrid wrote " + plainClassBytes.size()
                        + " loader-critical classes as plain jar entries");
            }

            putEntry(out, "META-INF/kbox/classes.bf.rle", packed.rleBytes);
            // NOTE: no separate index.dat is shipped. The name->(offset,len) index
            // is embedded as a signed header at the head of the classes.bf.rle raw
            // blob and parsed only inside the native decode heap; Java never sees
            // offsets, so nothing on disk/heap enumerates the payload for a dumper.
            putEntry(out, "META-INF/kbox/native.bin", nativeBlob);
            // JNIC co-existence: the JNIC native lib ships under its OWN path so the
            // BF decoder (native.bin) and the JNIC lib don't collide. BfSecureLoader
            // loads it via NativeLoader.loadJnic() and registers natives per class.
            if (jnicBlob != null) {
                putEntry(out, "META-INF/kbox/jnic.bin", jnicBlob);
                KBoxLog.info(TAG, "BF packed JNIC native lib -> META-INF/kbox/jnic.bin ("
                        + jnicBlob.length + " bytes)");
            }
            // VM原生化: the native VMP interpreter ships under its own path so it
            // never collides with the BF decoder (native.bin) or the JNIC lib
            // (jnic.bin). VmpInterpreterNative (inside the blob) loads it on demand
            // via NativeLoader.loadVmp() and falls back to the Java interpreter if
            // the blob was not compiled for this build.
            if (vmpBlob != null) {
                putEntry(out, "META-INF/kbox/vmp.bin", vmpBlob);
                KBoxLog.info(TAG, "BF packed VMP native lib -> META-INF/kbox/vmp.bin ("
                        + vmpBlob.length + " bytes)");
            }
            // Native crypto layer (string-decrypt sink + HKDF): the AES holder
            // decryptor references NativeCrypto.decryptString when the blob was
            // compiled, so both the blob and the class must ship in BF mode too —
            // otherwise every protected string resolves to a NoClassDefFoundError
            // and the decryptor's catch-all falls back to garbage (noise).
            if (nativeCryptoBlob != null) {
                putEntry(out, "META-INF/kbox/native-crypto.bin", nativeCryptoBlob);
                KBoxLog.info(TAG, "BF packed native crypto lib -> META-INF/kbox/native-crypto.bin ("
                        + nativeCryptoBlob.length + " bytes)");
            }
            if (epdManifest != null && epdManifest.length > 0) {
                putEntry(out, "META-INF/kbox/method_epd.bin", epdManifest);
                KBoxLog.info(TAG, "BF packed EPL manifest -> META-INF/kbox/method_epd.bin ("
                        + epdManifest.length + " bytes)");
            }
            try {
                putEntry(out, "KBox-Engine-Seal", sealOutput(cfg, inputJar));
            } catch (Throwable ignoredSeal) { }

            // Only the minimal bootstrap set ships as plain jar entries:
            // BfSecureLoader (the Main-Class the JVM loads first), NativeLoader
            // (unpacks the encrypted native decoder) and ChaCha20 (+ its nested
            // Keystream, which ChaCha20 references at runtime). Every other
            // engine class (VmpInterpreter, JnicIndy, IntegrityChecker, ...)
            // lives inside the Brainfuck blob. HardwareKeyRing is a required
            // EXCEPTION: KbnlKey's domain seeds are now hardware-rooted
            // (KEY 出域), so KbnlKey derives from HardwareKeyRing.fingerprint()
            // AT BOOT TIME while decoding native.bin — before the blob is
            // decodable. Injecting it as a boot entry lets the parent (system)
            // class loader resolve it first, so the bootstrap never reaches into
            // the blob for it (no circular dependency). It stays listed in the
            // blob collect too; parent-first delegation simply ignores the copy.
            java.util.Set<String> rtInjected = new java.util.HashSet<>();
            int rtCount = 0;
            // When white-box string encryption is on, the plaintext boot classes
            // are themselves ZKM-style hardened: their String literals are
            // encrypted (replaced with a per-string-salt decryptor call into a
            // synthetic holder) and each non-init method gains an opaque predicate,
            // so the constant pool no longer carries readable bootstrap strings.
            boolean obfBoot = cfg.isWhiteboxStrings();
            com.kbox.core.stringenc.BootstrapObfuscator bootObs =
                    obfBoot ? new com.kbox.core.stringenc.BootstrapObfuscator() : null;
            if (bootObs != null) {
                rtCount += injectBootClass(out, clsRoot, bootObs.holderInternal(),
                        bootObs.holderBytes(), rtInjected);
            }
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/BfSecureLoader", rtInjected, graph, bootObs);
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/BfBlobInputStream", rtInjected, graph, bootObs);
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/NativeLoader", rtInjected, graph, bootObs);
            // NativeLoader.unpack() needs KbnlKey.derive() before the blob is
            // decodable, so KbnlKey must also ship as a plain boot class.
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/KbnlKey", rtInjected, graph, bootObs);
            // KbnlKey.derive() is hardware-rooted (KEY 出域) and resolves
            // HardwareKeyRing.fingerprint() at that same pre-blob moment, so
            // HardwareKeyRing must be boot-loadable too (see comment above).
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/HardwareKeyRing", rtInjected, graph, bootObs);
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/ChaCha20", rtInjected, graph, bootObs);
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/ChaCha20$Keystream", rtInjected, graph, bootObs);
            // NativeCrypto is the optional native string-decrypt sink + HKDF seam;
            // when the native-crypto blob was compiled the AES holder calls it, so
            // it must be boot-loadable in BF mode too (it depends only on KbnlKey /
            // ChaCha20 / BfSecureLoader, all already boot classes above). When the
            // blob is absent the holder stays pure Java and never references it.
            rtCount += injectBoot(out, clsRoot, "com/kbox/runtime/NativeCrypto", rtInjected, graph, bootObs);
            if (rtCount > 0) {
                if (bootObs != null) {
                    KBoxLog.info(TAG, "BF boot obfuscation: " + bootObs.encrypted()
                            + " strings encrypted, " + bootObs.predicates() + " opaque predicates");
                }
                KBoxLog.info(TAG, "BF injected " + rtCount + " bootstrap classes");
            }
            // S5 (kboxDedeobfShieldV1): second-tier mock fill decoys in the BF jar.
            if (cfg.getBlobMockFill() > 0) {
                writeMockFill(out, cfg);
            }
        }
        KBoxLog.info(TAG, "Wrote Brainfuck-protected jar: " + outputJar
                + " (rle=" + packed.rleBytes.length + ")");
    }

    /**
     * Injects the runtime classes required by the JNIC packed-blob loader:
     * {@code NativeLoader} (reads + decrypts + decompresses + loads) and
     * {@code ChaCha20} (the keystream cipher). Classes already present in the
     * input jar (self-protection case) are skipped.
     */
    private int injectNativeLoaderClasses(ZipOutputStream out, String clsRoot,
                                          ClassGraph graph, java.util.Set<String> injected) throws IOException {
        int count = 0;
        count += injectOne(out, clsRoot, "com/kbox/runtime/NativeLoader", injected, graph);
        // NativeLoader.unpack() derives the KBNL container key at runtime via
        // KbnlKey.derive(blobSalt); KbnlKey is a hard dep of the loader and must
        // ride beside it (the blob is not yet decodable at that point).
        count += injectOne(out, clsRoot, "com/kbox/runtime/KbnlKey", injected, graph);
        // KbnlKey.derive() is hardware-rooted (KEY 出域) and resolves
        // HardwareKeyRing.fingerprint() while unpacking the KBNL container; the
        // JNIC blob is not yet decodable at that point, so HardwareKeyRing must
        // ride as a plain class beside the loader too.
        count += injectOne(out, clsRoot, "com/kbox/runtime/HardwareKeyRing", injected, graph);
        // JnicIndy resolves invokedynamic call sites inside native-ized method
        // bodies (bootstrap reproduction via MethodHandles), so it ships whenever
        // JNIC is enabled. ChaCha20 guards the loader keystream path.
        count += injectOne(out, clsRoot, "com/kbox/runtime/JnicIndy", injected, graph);
        count += injectOne(out, clsRoot, "com/kbox/runtime/ChaCha20", injected, graph);
        return count;
    }

    // ------------------------------------------------------------------
    // Entry-point obfuscation (task 5)
    // ------------------------------------------------------------------

    /**
     * Masks the {@code Original-Main-Class} manifest value so a static dump of the
     * jar cannot trivially reveal the application's {@code main()} class. The real
     * (renamed) class name is XOR-masked with a per-build random 16-byte seed; the
     * seed travels beside it in the {@code Entry-Guard-Seed} attribute at runtime
     * so the launcher can un-mask it. This is *obfuscation* (defeats casual name
     * recovery / automated manifest-parsing), not cryptography — the seed ships in
     * the jar, exactly like the class-encryption seed.
     */
    private byte[] obfuscateEntryPoint(byte[] manifest) {
        String s = new String(manifest, StandardCharsets.UTF_8);
        int i = s.indexOf("Original-Main-Class:");
        if (i < 0) return manifest;
        int end = s.indexOf('\n', i);
        int afterEnd = (end < 0) ? s.length() : end;
        while (afterEnd < s.length()
                && (s.charAt(afterEnd) == '\r' || s.charAt(afterEnd) == '\n')) afterEnd++;
        String val = s.substring(i + "Original-Main-Class:".length(), end < 0 ? s.length() : end).trim();
        if (val.isEmpty()) return manifest;

        byte[] seed = new byte[16];
        new java.security.SecureRandom().nextBytes(seed);
        String enc = entryNameCodec(val.getBytes(StandardCharsets.UTF_8), seed);
        String replacement = "Original-Main-Class: " + enc + "\r\n"
                + "Entry-Guard-Seed: " + java.util.Base64.getEncoder().encodeToString(seed) + "\r\n";
        s = s.substring(0, i) + replacement + s.substring(afterEnd);
        KBoxLog.info(TAG, "Obfuscated entry point (Original-Main-Class masked, seed in Entry-Guard-Seed)");
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * XOR-masks {@code in} with the deterministic keystream derived from a 16-byte
     * seed. Because it is a symmetric XOR the same routine recovers the plaintext
     * at runtime. The keystream is a FNV64-seeded xorshift64 chain — dependency
     * free (the runtime side has no ChaCha20 guarantee when neither class
     * encryption nor JNIC is enabled).
     */
    private static String entryNameCodec(byte[] in, byte[] seed) {
        byte[] out = new byte[in.length];
        long s = 0x6A09E667F3BCC909L;
        for (byte b : seed) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
        for (int i = 0; i < in.length; i++) {
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27;
            s *= 0x2545F4914F6CDD1DL;
            out[i] = (byte) (in[i] ^ (byte) (s >>> 32));
        }
        return java.util.Base64.getEncoder().encodeToString(out);
    }

    /** True when a resource is text and may contain class-name references. */
    private static boolean isFrameworkText(String path) {
        return path.startsWith("META-INF/services/")
                || path.endsWith("spring.factories")
                || path.endsWith("AutoConfiguration.imports");
    }

    /**
     * Injects every {@code ResourceGuard*} runtime class (launcher, loader, and
     * any inner/anonymous classes) by auto-discovering them from the classpath.
     * This avoids brittle hand-listing of {@code $Entry}, {@code $1}, etc.
     *
     * <p>Classes already present in the input jar (self-protection case) are
     * skipped to avoid duplicate-entry {@link java.util.zip.ZipException}s —
     * they were already written in the main class loop.
     */
    private int injectResourceGuardClasses(ZipOutputStream out, String clsRoot,
                                           ClassGraph graph) throws IOException {
        java.util.Collection<String> internals = discoverGuardClasses();
        int count = 0;
        for (String internal : internals) {
            // Do NOT skip classes already in the graph. They were written
            // in Step 1 with raw compiler frames which may have missing
            // StackMapTable entries. reSerializeRuntimeClass strips frames
            // and downgrades to V1_5 so the JVM uses inference verification.
            byte[] raw = loadClasspathResource(internal + ".class");
            if (raw == null) {
                System.err.println("[DEBUG guardInject] skip " + internal + " (class not found on cp)");
                KBoxLog.warn(TAG, internal + ".class not found on classpath");
                continue;
            }
            System.err.println("[DEBUG guardInject] processing " + internal + " rawLen=" + raw.length);
            // Re-serialize to ensure correct StackMapTable frames.
            byte[] bytes = reSerializeRuntimeClass(raw, internal);
            if (bytes == null) {
                bytes = raw; // fallback to raw bytes
            }
            putEntry(out, clsRoot + internal + ".class", bytes);
            count++;
        }
        return count;
    }

    /**
     * Lists internal names ({@code com/kbox/runtime/ResourceGuard...}) for every
     * ResourceGuard class on the classpath, by resolving the code source of the
     * launcher class and enumerating either the jar entries or the directory.
     */
    private java.util.Collection<String> discoverGuardClasses() {
        java.util.TreeSet<String> out = new java.util.TreeSet<>();
        try {
            java.net.URL url = Packager.class.getClassLoader()
                    .getResource("com/kbox/runtime/ResourceGuardLauncher.class");
            if (url == null) {
                url = ClassLoader.getSystemResource("com/kbox/runtime/ResourceGuardLauncher.class");
            }
            if (url == null) return out;
            if ("jar".equals(url.getProtocol())) {
                java.util.zip.ZipFile zf = new java.util.zip.ZipFile(
                        new java.io.File(((java.net.JarURLConnection) url.openConnection()).getJarFileURL().toURI()));
                java.util.Enumeration<? extends java.util.zip.ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    String n = en.nextElement().getName();
                    if (n.startsWith("com/kbox/runtime/ResourceGuard") && n.endsWith(".class")) {
                        String internal = n.substring(0, n.length() - ".class".length());
                        System.err.println("[DEBUG discoverGuard] found: " + internal);
                        out.add(internal);
                    }
                }
                zf.close();
            } else if ("file".equals(url.getProtocol())) {
                java.io.File dir = new java.io.File(url.toURI()).getParentFile();
                java.io.File[] files = dir.listFiles(
                        (d, name) -> name.startsWith("ResourceGuard") && name.endsWith(".class"));
                if (files != null) {
                    for (java.io.File f : files) {
                        String n = f.getName();
                        out.add("com/kbox/runtime/" + n.substring(0, n.length() - ".class".length()));
                    }
                }
            }
        } catch (Exception e) {
            KBoxLog.warn(TAG, "Guard class discovery failed: " + e.getMessage()
                    + " (falling back to known set)");
            out.add("com/kbox/runtime/ResourceGuardLauncher");
            out.add("com/kbox/runtime/ResourceGuardClassLoader");
            out.add("com/kbox/runtime/ResourceGuardClassLoader$Entry");
            out.add("com/kbox/runtime/ResourceGuardClassLoader$1");
        }
        return out;
    }

    /**
     * Writes the encrypted {@code resources.map} and the seed file into
     * {@code META-INF/kbox/} of the protected jar.
     */
    private void writeResourceGuardMetadata(ZipOutputStream out, String clsRoot,
                                            ResourceMapping mapping, byte[] seed) throws IOException {
        if (mapping == null || seed == null) return;
        byte[] mapBytes = mapping.serialize();
        byte[] encryptedMap;
        try {
            encryptedMap = encryptMap(mapBytes, seed);
        } catch (Exception e) {
            KBoxLog.warn(TAG, "Failed to encrypt resources.map: " + e.getMessage() + " (writing plaintext)");
            encryptedMap = mapBytes;
        }
        putEntry(out, clsRoot + "META-INF/kbox/resources.map", encryptedMap);
        putEntry(out, clsRoot + "META-INF/kbox/resource-guard.bin", seed);
        KBoxLog.info(TAG, "Wrote resource guard metadata (mapping=" + mapping.size() + " entries)");
    }

    /** Computes a SHA-256 over the exact bytes written for every non-runtime class
     *  and writes it as {@code META-INF/kbox/integrity.hash}.
     *
     *  <p><b>Signature parity.</b> Input must be byte-identical to what the runtime
     *  {@code IntegrityChecker} recomputes, otherwise even an honest jar looks
     *  tampered. Both sides therefore hash, in ascending name order, the tuple
     *  {@code (entryName, contentBytes)} where {@code entryName = clsRoot + internal + ".class"}
     *  — using {@code written} (the very bytes that were {@code putEntry} into the
     *  jar) rather than re-serializing, so encryption / rollback / non-determinism
     *  can never split the two signatures. KBox runtime classes are excluded on
     *  both sides; they are injected verbatim and may legitimately differ per build. */
    private void writeIntegrityHash(ZipOutputStream out, java.util.Map<String, byte[]> written,
                                    String clsRoot) throws IOException {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            // Ascending entry-name order, matching IntegrityChecker's TreeSet.
            java.util.TreeSet<String> sorted = new java.util.TreeSet<>(written.keySet());
            int hashed = 0;
            for (String internal : sorted) {
                if (internal.startsWith("com/kbox/runtime/")) continue; // runtime excluded
                String entryName = clsRoot + internal + ".class";
                md.update(entryName.getBytes(StandardCharsets.UTF_8));
                md.update(written.get(internal));
                hashed++;
            }
            byte[] hash = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            putEntry(out, clsRoot + "META-INF/kbox/integrity.hash",
                    sb.toString().getBytes(StandardCharsets.UTF_8));
            KBoxLog.info(TAG, "Wrote integrity hash (" + hashed + " classes)");
        } catch (Exception e) {
            KBoxLog.warn(TAG, "Integrity hash computation failed: " + e.getMessage());
        }
    }

    /**
     * Asserts that every KBox-owned class referenced by the written classes is
     * actually present in the output.
     *
     * <p>Per-build synthetic helpers (string/constant holders, type-confusion
     * carriers, honeypot holders) are created inside a pass and referenced from
     * rewritten call sites. If one is dropped, the artifact still builds fine and
     * only fails at runtime with a bare {@code NoClassDefFoundError} naming the
     * helper — which says nothing about which pass lost it. Failing here keeps a
     * broken jar from ever being shipped.
     *
     * @param written      internal name -> written bytes for every class from the
     *                     input jar (already in renamed space).
     * @param injected     internal names of the runtime classes we injected.
     * @param guardClasses internal names written by the resource/class guard.
     */
    private void verifyKboxReferenceClosure(Map<String, byte[]> written,
                                            java.util.Set<String> injected,
                                            java.util.Set<String> guardClasses) {
        java.util.Set<String> present = new java.util.HashSet<>(written.keySet());
        if (injected != null) present.addAll(injected);
        if (guardClasses != null) present.addAll(guardClasses);

        java.util.TreeMap<String, String> missing = new java.util.TreeMap<>();
        for (Map.Entry<String, byte[]> e : written.entrySet()) {
            java.util.Set<String> refs = new java.util.HashSet<>();
            collectTypeRefs(e.getValue(), refs);
            for (String r : refs) {
                if (!isKboxOwned(r) || present.contains(r)) continue;
                missing.putIfAbsent(r, e.getKey());
            }
        }
        if (missing.isEmpty()) return;

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> m : missing.entrySet()) {
            sb.append("\n  ").append(m.getKey())
              .append("   (referenced by ").append(m.getValue()).append(')');
        }
        throw new com.kbox.core.KBoxException("Protected jar would reference "
                + missing.size() + " missing KBox runtime class(es); refusing to "
                + "write a broken artifact:" + sb);
    }

    /** True for the internal names of KBox-synthesized runtime helpers. */
    private static boolean isKboxOwned(String internal) {
        return internal.startsWith("com/kbox/runtime/")
                || internal.startsWith("com/kbox/shield/")
                || internal.startsWith("com/kbox/honey/")
                || internal.startsWith("com/kbox/mock/");
    }

    /**
     * Lightweight scan for every type internal-name a class file refers to
     * (superclass, interfaces, descriptors, owners of field/method/type
     * instructions, invokedynamic bootstrap targets). Deliberately reads the
     * class with {@link org.objectweb.asm.ClassReader} instead of the tree API so
     * it also works on classes whose tree parse is heavy, and so a class we
     * cannot parse never aborts the audit.
     */
    private static void collectTypeRefs(byte[] bytes, java.util.Set<String> refs) {
        try {
            new org.objectweb.asm.ClassReader(bytes).accept(
                    new org.objectweb.asm.ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {
                        @Override
                        public void visit(int version, int access, String name, String sig,
                                          String superName, String[] ifaces) {
                            if (superName != null) refs.add(superName);
                            if (ifaces != null) java.util.Collections.addAll(refs, ifaces);
                        }

                        @Override
                        public org.objectweb.asm.FieldVisitor visitField(
                                int access, String name, String desc, String sig, Object value) {
                            collectDescRefs(desc, refs);
                            return null;
                        }

                        @Override
                        public org.objectweb.asm.MethodVisitor visitMethod(
                                int access, String name, String desc, String sig, String[] ex) {
                            collectDescRefs(desc, refs);
                            if (ex != null) java.util.Collections.addAll(refs, ex);
                            return new org.objectweb.asm.MethodVisitor(org.objectweb.asm.Opcodes.ASM9) {
                                @Override
                                public void visitTypeInsn(int opcode, String type) {
                                    if (type != null) refs.add(type);
                                }

                                @Override
                                public void visitMethodInsn(int opcode, String owner, String name,
                                                            String desc, boolean itf) {
                                    if (owner != null) refs.add(owner);
                                    collectDescRefs(desc, refs);
                                }

                                @Override
                                public void visitFieldInsn(int opcode, String owner,
                                                           String name, String desc) {
                                    if (owner != null) refs.add(owner);
                                    collectDescRefs(desc, refs);
                                }

                                @Override
                                public void visitLdcInsn(Object value) {
                                    if (value instanceof org.objectweb.asm.Type) {
                                        collectDescRefs(((org.objectweb.asm.Type) value).getDescriptor(), refs);
                                    }
                                }

                                @Override
                                public void visitInvokeDynamicInsn(String name, String desc,
                                                                   org.objectweb.asm.Handle bsm, Object... args) {
                                    collectDescRefs(desc, refs);
                                    if (bsm != null) {
                                        refs.add(bsm.getOwner());
                                        collectDescRefs(bsm.getDesc(), refs);
                                    }
                                    for (Object a : args) {
                                        if (a instanceof org.objectweb.asm.Type) {
                                            collectDescRefs(((org.objectweb.asm.Type) a).getDescriptor(), refs);
                                        } else if (a instanceof org.objectweb.asm.Handle) {
                                            refs.add(((org.objectweb.asm.Handle) a).getOwner());
                                        }
                                    }
                                }

                                @Override
                                public void visitMultiANewArrayInsn(String desc, int dims) {
                                    collectDescRefs(desc, refs);
                                }
                            };
                        }
                    }, org.objectweb.asm.ClassReader.SKIP_FRAMES | org.objectweb.asm.ClassReader.SKIP_DEBUG);
        } catch (Throwable ignored) {
            // Unparseable class: the writer already rolled it back to its original
            // bytes, and there is nothing to audit here.
        }
    }

    // ===== Anti-Dump: class body encryption =====

    /**
     * True when the class carries an annotation from a package whose runtime
     * provider may read class files as resources rather than loading them
     * (Spring component scanning, JPA/EE metadata readers, Jackson).
     */
    private static boolean hasFrameworkAnnotation(ClassNode cn) {
        if (cn == null) return false;
        return hasFrameworkAnnotation(cn.visibleAnnotations)
                || hasFrameworkAnnotation(cn.invisibleAnnotations);
    }

    private static boolean hasFrameworkAnnotation(java.util.List<?> annotations) {
        if (annotations == null) return false;
        for (Object o : annotations) {
            if (!(o instanceof org.objectweb.asm.tree.AnnotationNode)) continue;
            String d = ((org.objectweb.asm.tree.AnnotationNode) o).desc;
            if (d == null) continue;
            if (d.startsWith("Lorg/springframework/")
                    || d.startsWith("Ljakarta/")
                    || d.startsWith("Ljavax/")
                    || d.startsWith("Lcom/fasterxml/jackson/")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Compute the transitive dependency closure of every JNIC owner class.
     * These classes must remain plain (unencrypted) because the JVM pre-loads
     * JNIC owners through the system classloader, which cannot decrypt KBCE.
     *
     * <p>Runs at packaging time, AFTER renaming. The ClassGraph reference map
     * is keyed by pre-rename internal names, so we re-extract references from
     * the (already renamed) ClassNodes to guarantee name-space consistency.
     */
    private static Set<String> computeJnicPlainClosure(ClassGraph graph, ProtectionConfig cfg,
                                                        Map<String, String> reverseClassMap) {
        if (graph == null || cfg.getNativeMethods().isEmpty()) return null;
        // By packaging time the graph keys ARE the RENAMED internal names (the
        // pipeline replaces classes with remapped ClassNodes, and remapNativeMethodKeys
        // rewrote cfg.getNativeMethods() into renamed space too). So compute the whole
        // closure in RENAMED space: collectClassRefs on a renamed ClassNode yields renamed
        // refs, which match graph keys and the oldInternal passed to shouldEncryptClass.
        Map<String, Set<String>> adj = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            java.util.Set<String> refs = new java.util.LinkedHashSet<>();
            collectClassRefs(e.getValue(), refs);
            adj.put(e.getKey(), refs);
        }
        java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
        int queueSeeds = 0;
        int foundAdjCells = 0;
        for (String key : cfg.getNativeMethods()) {
            int hashIdx = key.indexOf('#');
            if (hashIdx <= 0) continue;
            String seed = key.substring(0, hashIdx).replace('.', '/'); // renamed owner
            queue.add(seed);
            queueSeeds++;
            if (adj.containsKey(seed)) foundAdjCells++;
        }
        java.util.Set<String> closure = new java.util.LinkedHashSet<>();
        while (!queue.isEmpty()) {
            String c = queue.poll();
            if (!closure.add(c)) continue;
            Set<String> next = adj.get(c);
            if (next != null) queue.addAll(next);
        }
        KBoxLog.info(TAG, "JNIC plain-closure: " + closure.size() + " classes"
                + (queueSeeds > 0 ? " (seeded from " + queueSeeds + " owners," : " (")
                + " foundAdjCells=" + foundAdjCells
                + ", hasW=" + closure.contains("com/kbox/core/w") + ")");
        return closure;
    }

    /** Collects every class referenced by a (renamed) ClassNode, in final name space. */
    private static void collectClassRefs(ClassNode cn, Set<String> refs) {
        if (cn.superName != null && cn.superName.indexOf('/') >= 0) refs.add(cn.superName);
        for (Object o : cn.interfaces) {
            String s = String.valueOf(o);
            if (s.indexOf('/') >= 0) refs.add(s);
        }
        for (Object fo : cn.fields) {
            org.objectweb.asm.tree.FieldNode f = (org.objectweb.asm.tree.FieldNode) fo;
            collectDescRefs(f.desc, refs);
        }
        for (Object mo : cn.methods) {
            MethodNode m = (MethodNode) mo;
            collectDescRefs(m.desc, refs);
            for (AbstractInsnNode insn : m.instructions) {
                if (insn instanceof org.objectweb.asm.tree.TypeInsnNode) {
                    String s = ((org.objectweb.asm.tree.TypeInsnNode) insn).desc;
                    if (s != null && s.indexOf('/') >= 0) refs.add(s);
                } else if (insn instanceof org.objectweb.asm.tree.FieldInsnNode) {
                    org.objectweb.asm.tree.FieldInsnNode f = (org.objectweb.asm.tree.FieldInsnNode) insn;
                    if (f.owner.indexOf('/') >= 0) refs.add(f.owner);
                    collectDescRefs(f.desc, refs);
                } else if (insn instanceof org.objectweb.asm.tree.MethodInsnNode) {
                    org.objectweb.asm.tree.MethodInsnNode mi = (org.objectweb.asm.tree.MethodInsnNode) insn;
                    if (mi.owner.indexOf('/') >= 0) refs.add(mi.owner);
                    collectDescRefs(mi.desc, refs);
                } else if (insn instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode) {
                    org.objectweb.asm.tree.InvokeDynamicInsnNode id = (org.objectweb.asm.tree.InvokeDynamicInsnNode) insn;
                    if (id.bsm != null && id.bsm.getOwner().indexOf('/') >= 0) refs.add(id.bsm.getOwner());
                    collectDescRefs(id.desc, refs);
                    for (Object bs : id.bsmArgs) {
                        if (bs instanceof org.objectweb.asm.Handle) {
                            String h = ((org.objectweb.asm.Handle) bs).getOwner();
                            if (h.indexOf('/') >= 0) refs.add(h);
                        }
                    }
                } else if (insn instanceof org.objectweb.asm.tree.LdcInsnNode) {
                    Object cst = ((org.objectweb.asm.tree.LdcInsnNode) insn).cst;
                    if (cst instanceof org.objectweb.asm.Type) {
                        String t = ((org.objectweb.asm.Type) cst).getInternalName();
                        if (t != null && t.indexOf('/') >= 0) refs.add(t);
                    } else if (cst instanceof org.objectweb.asm.Handle) {
                        String h = ((org.objectweb.asm.Handle) cst).getOwner();
                        if (h.indexOf('/') >= 0) refs.add(h);
                    }
                }
            }
        }
    }

    /** Adds every class name referenced inside an internal/method descriptor to {@code refs}. */
    private static void collectDescRefs(String desc, Set<String> refs) {
        if (desc == null) return;
        int i = 0;
        while ((i = desc.indexOf('L', i)) >= 0) {
            int end = desc.indexOf(';', i);
            if (end < 0) break;
            String name = desc.substring(i + 1, end);
            if (name.indexOf('/') >= 0) refs.add(name);
            i = end + 1;
        }
    }

    /** True when the class (by new internal name) is eligible for encryption. */
    private static boolean shouldEncryptClass(String newInternal, String oldInternal,
                                              ProtectionConfig cfg, Set<String> nativePlainClosure) {
        return shouldEncryptClass(null, null, newInternal, oldInternal, cfg, nativePlainClosure);
    }

    private static boolean shouldEncryptClass(ClassNode cn, ClassGraph graph,
                                              String newInternal, String oldInternal,
                                              ProtectionConfig cfg, Set<String> nativePlainClosure) {
        // Never encrypt KBox runtime classes — they must load before the guard.
        if (newInternal.startsWith("com/kbox/runtime/")) return false;
        // Never encrypt a class that a runtime framework PARSEs as a resource.
        //
        // Spring's component scan does not call loadClass: it reads every candidate
        // .class through the classloader and feeds the bytes to its own ASM
        // ClassReader, and for "classpath*:" scans PathMatchingResourcePatternResolver
        // reaches the raw jar entry directly, bypassing the guard loader entirely.
        // Ciphertext (the masked-KBCE header) therefore reaches Spring's ClassReader,
        // which aborts the scan with "Incompatible class format ... during classpath
        // scanning" — the app then loses every @Component/@Service/@Repository bean.
        // Classes carrying framework annotations, and Spring Data repository
        // interfaces (whose query methods are parsed by name), are exactly the ones
        // that must stay parseable on disk.
        if (hasFrameworkAnnotation(cn)) return false;
        if (com.kbox.core.name.RetentionDecision.isSpringDataRepository(graph, newInternal)) return false;
        // Never encrypt any class in the transitive dependency closure of a
        // JNIC owner — those classes are resolved through the system loader
        // which cannot decrypt KBCE-encrypted bytes (ClassFormatError).
        if (nativePlainClosure != null && nativePlainClosure.contains(oldInternal)) return false;
        // Never encrypt the entry point main class — the launcher loads it via
        // Class.forName through the guard, but the guard itself is a runtime
        // class and is excluded above.
        for (String ep : cfg.getEntryPoints()) {
            if (newInternal.equals(ep.replace('.', '/'))) return false;
        }
        // Never encrypt Mixin-kept classes — MixinTweaker needs raw bytecode
        // to apply @Inject/@Redirect transformations before decryption.
        if (cfg.isKept(newInternal)) return false;
        // Never encrypt library classes — they're loaded by the framework ClassLoader.
        if (cfg.isLibraryClass(newInternal)) return false;
        // Never encrypt JNIC / VMP owner classes — their native code
        // triggers System.load() which resolves through the JVM-internal
        // ClassLoader chain, bypassing the guard's encrypted-class decrypt.
        String dotted = newInternal.replace('/', '.');
        for (String key : cfg.getNativeMethods()) {
            if (key.startsWith(dotted + "#")) return false;
        }
        for (String key : cfg.getVmpMethods()) {
            if (key.startsWith(dotted + "#")) return false;
        }
        // If prefixes are specified, only encrypt matching classes.
        if (!cfg.getEncryptClassPrefixes().isEmpty()) {
            for (String p : cfg.getEncryptClassPrefixes()) {
                if (dotted.startsWith(p) || newInternal.startsWith(p)) return true;
            }
            return false;
        }
        // No prefix filter: encrypt everything (runtime + entry + kept already excluded).
        return true;
    }

    /** Encrypts a class file's raw bytes with AES-GCM. Layout: [4-byte masked magic][12-byte IV][ciphertext+tag].
     *  The magic bytes are XOR-masked (NOT ASCII "KBCE") so the encrypted-class
     *  header can't be fingerprint-grepped in the jar (坑④). Readers use the same
     *  masked bytes. */
    private static byte[] encryptClassBody(byte[] classBytes, byte[] seed, byte[] licMaterial) throws Exception {
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update("KBox-ClassGuard-v1:".getBytes(StandardCharsets.UTF_8));
        md.update(seed);
        md.update(com.kbox.runtime.HardwareKeyRing.fingerprint()); // S3: bind to build machine (true HW ring)
        if (licMaterial != null) md.update(licMaterial); // license gate (S)
        byte[] key = md.digest();
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, 0, 32, "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(classBytes);
        ByteBuffer out = ByteBuffer.allocate(4 + 12 + ct.length);
        // Masked magic (NOT ASCII "KBCE"): 'K'^0x29, 'B'^0x7B, 'C'^0xA1, 'E'^0xC3
        out.put((byte) 0x62);
        out.put((byte) 0x39);
        out.put((byte) 0xE2);
        out.put((byte) 0x86);
        out.put(iv);
        out.put(ct);
        return out.array();
    }

    /** License gate material: SHA-256(appSecret) when the build is licensed, else null. */
    private static byte[] licenseMaterial(com.kbox.core.config.ProtectionConfig cfg) {
        if (!cfg.isLicensed() || cfg.getLicAppSecret() == null) return null;
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(parseHexLicense(cfg.getLicAppSecret()));
            return md.digest();
        } catch (Throwable t) {
            return null;
        }
    }

    /** Writes {@code META-INF/kbox/class-seed.bin} (32-byte seed) and {@code META-INF/kbox/encrypted-classes.list}. */
    private void writeClassGuardMetadata(ZipOutputStream out, String clsRoot,
                                         java.util.Set<String> encryptedNames,
                                         byte[] classSeed) throws IOException {
        putEntry(out, clsRoot + "META-INF/kbox/class-seed.bin", classSeed);
        StringBuilder sb = new StringBuilder();
        for (String n : encryptedNames) {
            sb.append(n).append('\n');
        }
        putEntry(out, clsRoot + "META-INF/kbox/encrypted-classes.list",
                sb.toString().getBytes(StandardCharsets.UTF_8));
        KBoxLog.info(TAG, "Wrote class guard metadata (" + encryptedNames.size() + " encrypted classes)");
    }

    /**
     * Writes {@code META-INF/kbox/jnic-classes.list} — one JNIC owner class
     * (internal name) per line. Runtime uses this list to detect native
     * classes without parsing anti-decompiler-mangled bytecode.
     */
    private void writeJnicClassList(ZipOutputStream out, String clsRoot,
                                    ProtectionConfig cfg) throws IOException {
        java.util.Set<String> classNames = new java.util.LinkedHashSet<>();
        for (String key : cfg.getNativeMethods()) {
            int hashIdx = key.indexOf('#');
            if (hashIdx > 0) {
                classNames.add(key.substring(0, hashIdx).replace('.', '/'));
            }
        }
        if (classNames.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        for (String n : classNames) {
            sb.append(n).append('\n');
        }
        putEntry(out, clsRoot + "META-INF/kbox/jnic-classes.list",
                sb.toString().getBytes(StandardCharsets.UTF_8));
        KBoxLog.info(TAG, "Wrote JNIC class list (" + classNames.size() + " classes) -> META-INF/kbox/jnic-classes.list");
    }

    /**
     * Writes {@code META-INF/kbox/parent-delegate.list} — one library internal
     * name per line. These classes must be resolved by the PARENT (app) loader,
     * never re-defined locally by the guard loader, to keep a single copy of
     * bytecode/lib classes across loaders (else ClassCastException).
     */
    private void writeParentDelegateList(ZipOutputStream out, String clsRoot,
                                         java.util.Set<String> parentDelegate) throws IOException {
        if (parentDelegate == null || parentDelegate.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        for (String n : parentDelegate) {
            sb.append(n).append('\n');
        }
        putEntry(out, clsRoot + "META-INF/kbox/parent-delegate.list",
                sb.toString().getBytes(StandardCharsets.UTF_8));
        KBoxLog.info(TAG, "Wrote parent-delegate list (" + parentDelegate.size()
                + " classes) -> META-INF/kbox/parent-delegate.list");
    }

    private static byte[] newSeed() {
        byte[] s = new byte[32];
        new java.security.SecureRandom().nextBytes(s);
        return s;
    }

    /** Encrypts the mapping blob with AES-GCM using the same scheme as resource bodies. */
    private static byte[] encryptMap(byte[] data, byte[] seed) throws Exception {
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] key = md.digest(seed);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, 0, 32, "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(data);
        ByteBuffer out = ByteBuffer.allocate(1 + iv.length + ct.length);
        out.put((byte) 0x4B);   // magic 'K'
        out.put(iv);
        out.put(ct);
        return out.array();
    }

    /**
     * Injects the KBox runtime classes from the kbox-core classpath into the
     * protected jar. {@code KBoxRuntime} is needed when string encryption is on
     * (the generated bytecode calls its {@code d}/{@code a} decryptors);
     * {@code VmpInterpreter} (+ inner {@code VmpMethod}) is needed when VMP is on.
     * Returns the number of classes injected.
     */
    private int injectRuntimeClasses(ZipOutputStream out, String clsRoot, ProtectionConfig cfg,
                                     ClassGraph graph, java.util.Set<String> injected) throws IOException {
        int count = 0;
        if (cfg.isEncryptStrings()) {
            count += injectOne(out, clsRoot, "com/kbox/runtime/KBoxRuntime", injected, graph);
            // KBoxRuntime now consults TamperShield.isTampered() (the union of
            // AntiDebug + IntegrityChecker + VmpInterpreter) instead of only the
            // debugger canary. AntiDebug is a hard dep and must ship with it.
            count += injectOne(out, clsRoot, "com/kbox/runtime/TamperShield", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/AntiDebug", injected, graph);
        }
        if (cfg.isEnableVmp()) {
            count += injectOne(out, clsRoot, "com/kbox/runtime/VmpInterpreter", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/VmpInterpreter$1", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/VmpInterpreter$Handler", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/VmpInterpreter$Ctx", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/VmpInterpreter$VmpMethod", injected, graph);
            // BrainfuckShield（二次虚拟化）: VmpMethod 构造期引用 BfInterpreter 把
            // $vmp_<n> 字段里的磁带程序（KBFT）逐格回放解码回密文流。只要 VMP 开启
            // 就必须随包，否则 VmpMethod.<init> 抛 CNFE。
            count += injectOne(out, clsRoot, "com/kbox/runtime/BfInterpreter", injected, graph);
            // BfRng: package-private nested PRNG used by BfInterpreter (vmpToCode / tape
            // decode). Its own class file; must ship with BfInterpreter in plaintext mode
            // or VMP tape decode throws CNFE.
            count += injectOne(out, clsRoot, "com/kbox/runtime/BfInterpreter$BfRng", injected, graph);
            // VmpInterpreter.execute() delegates to this optional native seam; it must
            // ship whenever VmpInterpreter is injected or the first VMP call would
            // NoClassDefFoundError even in the pure-Java fallback path.
            count += injectOne(out, clsRoot, "com/kbox/runtime/VmpInterpreterNative", injected, graph);
            // VmpInterpreter encrypts/decrypts the instruction stream with the
            // ChaCha20 keystream; its nested Keystream must ship too.
            count += injectOne(out, clsRoot, "com/kbox/runtime/ChaCha20", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/ChaCha20$Keystream", injected, graph);
        }
        // BFVM full virtualization runtime: BfRuntime.call is referenced by every
        // BFVM-transformed method stub, and it (transitively) needs BfInterpreter
        // (decode the BF program), VmCore (+ nested State/Cursor/Uninitialized) and
        // the self-contained Opcode/BfVmException. All must ship whenever BFVM is on,
        // or the first call to a virtualized method throws NoClassDefFoundError.
        if (cfg.isEnableBfvm() && !cfg.getBfvmMethods().isEmpty()) {
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/BfRuntime", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/BfInterpreter", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/VmCore", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/VmCore$Cursor", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/VmCore$State", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/VmCore$Uninitialized", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/Opcode", injected, graph);
            count += injectOne(out, clsRoot, "com/kbox/runtime/bfvm/BfVmException", injected, graph);
        }
        // Anti-debug and integrity classes are needed by the ResourceGuardLauncher,
        // which calls AntiDebug.check() and IntegrityChecker.check()
        // unconditionally from its main(). Inject whenever the launcher is in
        // play (resource guard or class guard), plus the explicit toggle on.
        boolean needGuard = cfg.isObfuscateResources() || cfg.isEncryptClasses();
        if (cfg.isAntiDebug() || cfg.isIntegrityCheck() || needGuard) {
            count += injectOne(out, clsRoot, "com/kbox/runtime/AntiDebug", injected, graph);
        }
        if (cfg.isIntegrityCheck() || needGuard) {
            count += injectOne(out, clsRoot, "com/kbox/runtime/IntegrityChecker", injected, graph);
        }
        // True hardware key ring: the class-key derivation now binds to
        // HardwareKeyRing.fingerprint() (real CPU/BIOS/board serials via HKDF),
        // so it must be present whenever class encryption is active. It is ALSO
        // a hard dependency of the VMP key-wrapping (VmpMethod unwraps K under
        // HardwareKeyRing.vmpMaster()), so inject it whenever VMP is on too —
        // otherwise VmpMethod.<init> throws CNFE and every protected method
        // degrades to a noise method. And since S7, KBNL string keys are
        // derived via KbnlKey.derive -> HardwareKeyRing.fingerprint(), so ANY
        // string-encrypted build (even plaintext packaging, no BF/VMP/JNIC)
        // must ship HardwareKeyRing or the string holder <clinit> throws CNFE.
        if (cfg.isEncryptStrings() || cfg.isEncryptClasses() || cfg.isEnableVmp() || cfg.isEnableJnic()) {
            count += injectOne(out, clsRoot, "com/kbox/runtime/HardwareKeyRing", injected, graph);
        }
        // kboxDedeobfShieldV1 dynamic guard: inject whenever any static/dynamic
        // layer is armed so the entry-poin arming seam resolves at runtime.
        if (cfg.getMethodSplit() > 0 || cfg.getOpaqueStateMachine() > 0
                || cfg.getHoneypotLevel() > 0 || cfg.getBlobMockFill() > 0
                || cfg.getSentinelInterleave() > 0 || cfg.getStackFrameRedirect() > 0
                || cfg.getEntropyTimeAnchor() > 0 || cfg.getSelfWipeSections() > 0
                || cfg.getProcessHeartbeat() > 0 || cfg.getHoneypotPe() > 0
                || cfg.getOneTimeSemantic() > 0 || cfg.getLineageChain() > 0
                || cfg.getSelfRefAuth() > 0 || cfg.getMultiRep() > 0
                || cfg.getPolyGold() > 0 || cfg.getSignalPoison() > 0
                || cfg.getBuildSigBind() > 0) {
            count += injectOne(out, clsRoot, "com/kbox/runtime/KBoxDedeobfGuard", injected, graph);
        }
        // Inject KBoxClassDecryptTweaker when class encryption is actually
        // active (not auto-disabled for Forge mods).  Forge mods are detected
        // by the presence of a TweakClass manifest attribute.
        if (cfg.isEncryptClasses() && !isForgeMod(graph)) {
            count += injectPatched(out, clsRoot, "com/kbox/runtime/KBoxClassDecryptTweaker",
                    injected, graph);
        }
        return count;
    }

    /** @return true when the class declares at least one {@code native} method. */
    private static boolean declaresNativeMethod(ClassNode cn) {
        if (cn == null || cn.methods == null) return false;
        for (org.objectweb.asm.tree.MethodNode mn : cn.methods) {
            if ((mn.access & org.objectweb.asm.Opcodes.ACC_NATIVE) != 0) return true;
        }
        return false;
    }

    /** @return true when the input jar is a Forge/Fabric mod (has TweakClass). */
    private static boolean isForgeMod(ClassGraph graph) {
        if (graph.getManifest() == null) return false;
        return new String(graph.getManifest(), StandardCharsets.UTF_8).contains("TweakClass:");
    }

    /**
     * BF blob variant of {@link #injectRuntimeClasses}: instead of writing the
     * engine runtime classes as plain jar entries, it places them inside the
     * {@code classes} / {@code resources} maps handed to
     * {@link com.kbox.core.brainfuck.BrainfuckPacker#pack}, so the protection
     * engine itself rides inside the Brainfuck payload. Only the bootstrap triad
     * ({@code BfSecureLoader}/{@code NativeLoader}/{@code ChaCha20}) may stay
     * plaintext, because it must run before the blob is decodable.
     *
     * <p>Classes that must NOT be collected here: the bootstrap triad, plus
     * anything referenced directly by the JNI {@code FindClass} from a context
     * the blob loader cannot satisfy. {@code JnicIndy} is deliberately collected
     * here — the native interpreter's {@code FindClass} runs from inside a
     * native method whose declaring class is a blob class, so it resolves via
     * {@code BfSecureLoader} and finds {@code JnicIndy} in the blob.
     */
    private int collectRuntimeClassesForBlob(ProtectionConfig cfg, ClassGraph graph,
                                             Map<String, byte[]> classes,
                                             Map<String, byte[]> resources) throws IOException {
        int count = 0;
        if (cfg.isEncryptStrings()) {
            count += collectOne(classes, graph, "com/kbox/runtime/KBoxRuntime");
            count += collectOne(classes, graph, "com/kbox/runtime/TamperShield");
            count += collectOne(classes, graph, "com/kbox/runtime/AntiDebug");
        }
        if (cfg.isEnableVmp()) {
            // VmpInterpreter + VmpMethod move into the blob. ChaCha20(+Keystream)
            // stay plaintext — NativeLoader needs ChaCha20 before the blob exists.
            // These six classes are force-collected so their bytes always come from
            // the freshly built (seamed) kbox-core jar, never a stale graph copy:
            // the native VM原生化 route (VmpInterpreter.execute -> tryExecute ->
            // VmpInterpreterNative) must survive into the blob or BF jars silently
            // fall back to the byte-identical Java interpreter.
            count += collectOne(classes, graph, "com/kbox/runtime/VmpInterpreter", true);
            count += collectOne(classes, graph, "com/kbox/runtime/VmpInterpreter$1", true);
            count += collectOne(classes, graph, "com/kbox/runtime/VmpInterpreter$Handler", true);
            count += collectOne(classes, graph, "com/kbox/runtime/VmpInterpreter$Ctx", true);
            count += collectOne(classes, graph, "com/kbox/runtime/VmpInterpreter$VmpMethod", true);
            // BrainfuckShield（二次虚拟化）: VmpMethod 构造期引用 BfInterpreter；BF 变体下
            // 它也进 blob，随构建期 BfDialect 两侧镜像保持 build/runtime 一致。
            count += collectOne(classes, graph, "com/kbox/runtime/BfInterpreter", true);
            // BfRng: package-private nested PRNG used by BfInterpreter; its own class file.
            count += collectOne(classes, graph, "com/kbox/runtime/BfInterpreter$BfRng", true);
            // Native seam referenced by VmpInterpreter.execute(); must ride along.
            count += collectOne(classes, graph, "com/kbox/runtime/VmpInterpreterNative", true);
        }
        // BFVM runtime: BfRuntime.call is referenced by every virtualized method stub;
        // in the BF blob variant the runtime rides inside the payload so it resolves via
        // the blob loader just like the protected classes.
        if (cfg.isEnableBfvm() && !cfg.getBfvmMethods().isEmpty()) {
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/BfRuntime");
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/BfInterpreter");
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/VmCore");
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/VmCore$Cursor");
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/VmCore$State");
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/VmCore$Uninitialized");
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/Opcode");
            count += collectOne(classes, graph, "com/kbox/runtime/bfvm/BfVmException");
        }
        boolean needGuard = cfg.isObfuscateResources() || cfg.isEncryptClasses();
        if (cfg.isAntiDebug() || cfg.isIntegrityCheck() || needGuard) {
            count += collectOne(classes, graph, "com/kbox/runtime/AntiDebug");
        }
        if (cfg.isIntegrityCheck() || needGuard) {
            count += collectOne(classes, graph, "com/kbox/runtime/IntegrityChecker");
        }
        if (cfg.isEncryptStrings() || cfg.isEncryptClasses() || cfg.isEnableVmp()) {
            count += collectOne(classes, graph, "com/kbox/runtime/HardwareKeyRing");
        }
        if (cfg.isEnableJnic()) {
            count += collectOne(classes, graph, "com/kbox/runtime/JnicIndy");
        }
        // kboxDedeobfShieldV1 dynamic guard rides the blob when any D/C/X layer is on.
        if (cfg.getMethodSplit() > 0 || cfg.getOpaqueStateMachine() > 0
                || cfg.getHoneypotLevel() > 0 || cfg.getBlobMockFill() > 0
                || cfg.getSentinelInterleave() > 0 || cfg.getStackFrameRedirect() > 0
                || cfg.getEntropyTimeAnchor() > 0 || cfg.getSelfWipeSections() > 0
                || cfg.getProcessHeartbeat() > 0 || cfg.getHoneypotPe() > 0
                || cfg.getOneTimeSemantic() > 0 || cfg.getLineageChain() > 0
                || cfg.getSelfRefAuth() > 0 || cfg.getMultiRep() > 0
                || cfg.getPolyGold() > 0 || cfg.getSignalPoison() > 0
                || cfg.getBuildSigBind() > 0) {
            count += collectOne(classes, graph, "com/kbox/runtime/KBoxDedeobfGuard");
        }
        if (cfg.isLicensed()) {
            count += collectOne(classes, graph, "com/kbox/runtime/LicVerifier");
            try {
                byte[] spki = parseHexLicense(cfg.getLicPublicKey());
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                com.kbox.runtime.LicVerifier.writeMaskedPublicKey(bo, spki);
                resources.put("META-INF/kbox/lic.pub", bo.toByteArray());
                KBoxLog.info(TAG, "Embedded masked license public key into BF blob ("
                        + spki.length + " bytes) + LicVerifier runtime");
            } catch (Exception e) {
                KBoxLog.warn(TAG, "License public key embed failed: " + e.getMessage());
            }
        }
        return count;
    }

    /** Adds one engine runtime class (from the kbox-core classpath) into the
     *  blob {@code classes} map. Self-protection case (input jar already carries
     *  the class) and duplicates are skipped. Returns 1 on success.
     *
     *  <p>When {@code force} is {@code true}, any entry the graph already placed
     *  in {@code classes} for {@code internal} is <b>overwritten</b> by the
     *  freshly loaded classpath bytes (re-serialized). This is required for the
     *  VM原生化 seam ({@code VmpInterpreter}/{@code VmpInterpreterNative}): a
     *  graph copy that was serialized from stale original bytes would silently
     *  drop the {@code tryExecute} native-routing call, making the BfSecureLoader
     *  run the byte-identical Java interpreter instead of the native one. Always
     *  forcing the seamed bytes guarantees the native seam survives the blob.</p>
     */
    private int collectOne(Map<String, byte[]> classes, ClassGraph graph,
                           String internal) throws IOException {
        return collectOne(classes, graph, internal, false);
    }

    private int collectOne(Map<String, byte[]> classes, ClassGraph graph,
                           String internal, boolean force) throws IOException {
        if (!force) {
            if (classes.containsKey(internal)) return 0;
            if (graph.getClasses().containsKey(internal)) return 0; // already in blob map
        }
        boolean wasPresent = classes.containsKey(internal)
                || graph.getClasses().containsKey(internal);
        byte[] raw = loadClasspathResource(internal + ".class");
        if (raw == null) {
            if (wasPresent) return 0;   // keep the existing graph bytes if classpath misses
            KBoxLog.warn(TAG, internal + ".class not found on classpath");
            return 0;
        }
        byte[] bytes = reSerializeRuntimeClass(raw, internal);
        if (bytes == null) bytes = raw;
        classes.put(internal, bytes);
        return 1;
    }

    /** Injects a single runtime class; returns 1 on success, 0 on miss or duplicate. */
    private int injectOne(ZipOutputStream out, String clsRoot, String internal,
                          java.util.Set<String> injected, ClassGraph graph) throws IOException {
        if (injected.contains(internal)) return 0;
        // If the input jar already contains this class (self-protection case),
        // it was already written in step 1 — skip to avoid duplicate entry.
        if (graph.getClasses().containsKey(internal)) {
            injected.add(internal);
            return 0;
        }
        byte[] raw = loadClasspathResource(internal + ".class");
        if (raw == null) {
            KBoxLog.warn(TAG, internal + ".class not found on classpath");
            return 0;
        }
        // Re-serialize the runtime class with proper StackMapTable frame
        // computation to avoid VerifyError ("Expecting a stackmap frame").
        // Raw compiler output may have incomplete frames for some code
        // patterns; COMPUTE_FRAMES recalculates them from scratch.
        byte[] bytes = reSerializeRuntimeClass(raw, internal);
        if (bytes != null) {
            putEntry(out, clsRoot + internal + ".class", bytes);
            injected.add(internal);
            return 1;
        }
        // Fallback: write raw bytes as-is.
        putEntry(out, clsRoot + internal + ".class", raw);
        injected.add(internal);
        return 1;
    }

    /**
     * Injects a bootstrap class like {@link #injectOne}, but first obfuscates it
     * (string encryption + opaque predicates) when {@code obs != null}, so the
     * boot classes ship hardened instead of the constants plaintext.
     *
     * <p>BF 专用：bootstrap 类（BfSecureLoader/NativeLoader/KbnlKey/ChaCha20/
     * HardwareKeyRing）是 JVM 先加载的明文 Main-Class 依赖，必须无条件从混淆器
     * classpath 注入**原始字节**。即使在自混淆场景（输入 jar 就是混淆器自身，
     * graph 里已含这些类），graph 中的同名副本也已进入 blob（classes.bf.rle）
     * 而非明文条目——若因「graph 已有」而跳过注入，产物将缺失明文 launcher，
     * JVM 报 ClassNotFoundException: com.kbox.runtime.BfSecureLoader。
     */
    private int injectBoot(ZipOutputStream out, String clsRoot, String internal,
                           java.util.Set<String> injected, ClassGraph graph,
                           com.kbox.core.stringenc.BootstrapObfuscator obs) throws IOException {
        if (injected.contains(internal)) return 0;
        byte[] raw = loadClasspathResource(internal + ".class");
        if (raw == null) {
            KBoxLog.warn(TAG, internal + ".class not found on classpath");
            return 0;
        }
        byte[] bytes = raw;
        /* BfSecureLoader must ship byte-identical to the build-time baseline:
         * the native decoder bakes FNV hashes of its key methods (main/
         * failIfAgentPresent/<init>/entry-read) and verifies them via JVMTI
         * GetBytecodes at startup. Skipping the BootstrapObfuscator rewrite
         * for THIS class keeps those bytes deterministic (an obfuscated main
         * would change its code[] and false-positive every clean artifact).
         * Its strings carry no secret, so the skipped hardening is harmless. */
        if (obs != null && !internal.equals("com/kbox/runtime/BfSecureLoader")) {
            bytes = obs.obfuscate(raw);
        }
        byte[] fin = reSerializeRuntimeClass(bytes, internal);
        if (fin != null) bytes = fin;
        putEntry(out, clsRoot + internal + ".class", bytes);
        injected.add(internal);
        return 1;
    }

    /** Writes a synthetic, pre-generated class entry (e.g. the boot decryptor holder). */
    private int injectBootClass(ZipOutputStream out, String clsRoot, String internal,
                                byte[] bytes, java.util.Set<String> injected) throws IOException {
        if (injected.contains(internal)) return 0;
        byte[] fin = reSerializeRuntimeClass(bytes, internal);
        if (fin != null) bytes = fin;
        putEntry(out, clsRoot + internal + ".class", bytes);
        injected.add(internal);
        return 1;
    }

    /** Licensing runtime injection: embed LicVerifier + HardwareKeyRing and write
     *  the masked public key resource the verifier un-wraps at runtime. */
    private int injectRuntimeClassesLicensing(java.util.zip.ZipOutputStream out, String clsRoot,
                                              com.kbox.core.config.ProtectionConfig cfg,
                                              ClassGraph graph, java.util.Set<String> injected) throws java.io.IOException {
        int count = 0;
        count += injectOne(out, clsRoot, "com/kbox/runtime/LicVerifier", injected, graph);
        count += injectOne(out, clsRoot, "com/kbox/runtime/HardwareKeyRing", injected, graph);
        // Write the masked public key (whitespace: not raw X.509 bytes on disk).
        try {
            byte[] spki = parseHexLicense(cfg.getLicPublicKey());
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            com.kbox.runtime.LicVerifier.writeMaskedPublicKey(bo, spki);
            putEntry(out, clsRoot + "META-INF/kbox/lic.pub", bo.toByteArray());
            KBoxLog.info(TAG, "Embedded masked license public key ("
                    + spki.length + " bytes) + LicVerifier runtime");
        } catch (Exception e) {
            KBoxLog.warn(TAG, "License public key embed failed: " + e.getMessage());
        }
        return count;
    }

    private static byte[] parseHexLicense(String hex) {
        if (hex == null) return new byte[0];
        String h = hex.trim();
        if (h.length() % 2 != 0) return new byte[0];
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /**
     * Derive a per-output engine tamper-seal. Binds the produced jar to the
     * input jar's content hash so the seal is deterministic per input and does
     * not depend on any engine license state.
     */
    private static byte[] sealOutput(com.kbox.core.config.ProtectionConfig cfg, Path inputJar) {
        java.security.MessageDigest md;
        try {
            md = java.security.MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            return new byte[0];
        }
        byte[] session;
        try {
            session = md.digest(java.nio.file.Files.readAllBytes(inputJar));
        } catch (Exception e) {
            session = new byte[32];
        }
        md.update(session);
        md.update("KBox|".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        md.update(System.getProperty("kbox.seed.salt", "kbox-1").getBytes(
                java.nio.charset.StandardCharsets.ISO_8859_1));
        return md.digest();
    }

    /**
     * Re-serializes a runtime class bytecode with COMPUTE_FRAMES to ensure
     * correct StackMapTable. The raw compiler output may have incomplete or
     * missing stack-map frames that cause VerifyError at runtime.
     *
     * <p><b>Deterministic</b>: identical {@code raw} always yields identical
     * output, so {@code BfNativeBuilder} reproduces exactly the bytes
     * {@code injectBoot} will write for the loader (used to bake the loader's
     * expected FNV hash into the native decoder). Public so the builder can
     * share the SAME implementation — any drift would break the native
     * loader-tamper check.
     *
     * @return re-serialized bytes, or null if class cannot be parsed
     */
    public static byte[] reSerializeRuntimeClass(byte[] raw, String internal) {
        try {
            org.objectweb.asm.ClassReader cr = new org.objectweb.asm.ClassReader(raw);
            org.objectweb.asm.tree.ClassNode cn = new org.objectweb.asm.tree.ClassNode();
            cr.accept(cn, org.objectweb.asm.ClassReader.EXPAND_FRAMES);

            // Target V1_7 to support CONSTANT_MethodType (tag 16).
            cn.version = org.objectweb.asm.Opcodes.V1_7;

            // First try COMPUTE_FRAMES — produces correct StackMapTable
            // for Java 7+ verification.
            try {
                org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(
                        org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
                cn.accept(cw);
                return cw.toByteArray();
            } catch (Exception frameEx) {
                // COMPUTE_FRAMES failed. Fall back: strip frames,
                // downgrade to V1_6 (inference verifier).
                stripFrameNodes(cn);
                cn.version = org.objectweb.asm.Opcodes.V1_6;
                org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(
                        org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
                cn.accept(cw);
                return cw.toByteArray();
            }
        } catch (Exception e) {
            KBoxLog.warn(TAG, "re-serialize failed for " + internal
                    + ": " + e.getMessage() + " — using raw bytes");
            return null;
        }
    }

    /**
     * Injects a runtime class like {@link #injectOne}, but first patches the
     * bytecode via {@link #patchDecryptTweaker} so that the injected class
     * implements {@code net/minecraft/launchwrapper/ITweaker} and
     * {@code net/minecraft/launchwrapper/IClassTransformer} without requiring
     * launchwrapper at the core's compile time.
     */
    private int injectPatched(ZipOutputStream out, String clsRoot, String internal,
                              java.util.Set<String> injected, ClassGraph graph) throws IOException {
        if (injected.contains(internal)) return 0;
        if (graph.getClasses().containsKey(internal)) {
            injected.add(internal);
            return 0;
        }
        byte[] bytes = loadClasspathResource(internal + ".class");
        if (bytes != null) {
            bytes = patchDecryptTweaker(bytes);
            putEntry(out, clsRoot + internal + ".class", bytes);
            injected.add(internal);
            return 1;
        }
        KBoxLog.warn(TAG, internal + ".class not found on classpath");
        return 0;
    }

    /**
     * Patches KBoxClassDecryptTweaker bytecode at injection time:
     * <ol>
     *   <li>Adds {@code net/minecraft/launchwrapper/ITweaker} and
     *       {@code net/minecraft/launchwrapper/IClassTransformer} to the
     *       class's interface list.</li>
     *   <li>Rewrites {@code injectIntoClassLoader(Ljava/lang/Object;)V} to
     *       {@code injectIntoClassLoader(Lnet/minecraft/launchwrapper/LaunchClassLoader;)V}
     *       so it matches the ITweaker interface contract.</li>
     * </ol>
     */
    private static byte[] patchDecryptTweaker(byte[] classBytes) {
        ClassReader cr = new ClassReader(classBytes);
        ClassWriter cw = new ClassWriter(0);
        cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public void visit(int version, int access, String name,
                              String signature, String superName, String[] interfaces) {
                // Append ITweaker and IClassTransformer to the interface list.
                String[] newInterfaces = java.util.Arrays.copyOf(
                        interfaces, interfaces.length + 2);
                newInterfaces[interfaces.length] = "net/minecraft/launchwrapper/ITweaker";
                newInterfaces[interfaces.length + 1] = "net/minecraft/launchwrapper/IClassTransformer";
                super.visit(version, access, name, signature, superName, newInterfaces);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name,
                                             String descriptor, String signature,
                                             String[] exceptions) {
                // Rewrite injectIntoClassLoader parameter from Object to LaunchClassLoader.
                if (name.equals("injectIntoClassLoader")
                        && descriptor.equals("(Ljava/lang/Object;)V")) {
                    descriptor = "(Lnet/minecraft/launchwrapper/LaunchClassLoader;)V";
                }
                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }
        }, 0);
        return cw.toByteArray();
    }

    /** Loads a class file resource from the kbox-core classpath, or null if absent. */
    private static byte[] loadClasspathResource(String resourcePath) throws IOException {
        ClassLoader cl = Packager.class.getClassLoader();
        InputStream is = cl.getResourceAsStream(resourcePath);
        if (is == null) {
            // Fall back to the system loader (some environments don't expose the class loader).
            is = ClassLoader.getSystemResourceAsStream(resourcePath);
        }
        if (is == null) return null;
        try {
            return readAll(is);
        } finally {
            is.close();
        }
    }

    /**
     * Serializes a ClassNode. Tries {@code COMPUTE_FRAMES | COMPUTE_MAXS} first
     * (the correct mode — recomputes all stack-map frames from scratch so every
     * transform we applied stays valid). If frame computation fails (most
     * commonly on the anti-decompiler's synthetic {@code _KboxAntiDec} class,
     * whose 500-entry exception bomb and dead-code goto-chains confuse ASM's
     * {@code Frame.merge}), fall back to {@code COMPUTE_MAXS} alone. The
     * fallback preserves existing frames for unmodified methods and writes no
     * StackMapTable for synthetic anti-decompiler methods — which is safe
     * because {@code _KboxAntiDec} is never loaded by the JVM at runtime (it
     * exists solely to crash decompiler UIs that scan every class).
     */
    private byte[] serialize(ClassNode cn, ClassGraph graph, ProtectionConfig cfg) {
        // Clean up invalid try-catch blocks: after CF, exception-jump, and
        // anti-decompiler transforms, some try-catch blocks may reference
        // LabelNodes that are no longer in the instruction list.  Orphaned
        // labels produce "Illegal exception table range" ClassFormatError
        // at JVM load time because start_pc/end_pc/handler_pc point to
        // non-existent bytecode offsets.
        cleanupTryCatchBlocks(cn);

        // Strip stale debug info. When fakeDebugInfo is enabled, the forged
        // LocalVariableTable is intentionally kept (it references real slots
        // and real labels, so it is verifier-safe and effective at misleading
        // decompilers). Otherwise strip it unconditionally — after any
        // transform the LocalVariableTable may reference slots that no longer
        // exist, causing VerifyError ("Local variable table overflow").
        if (cfg == null || !cfg.isFakeDebugInfo()) {
            stripDebugInfo(cn);
        }

        // Always strip stale frame nodes and recompute from scratch.
        // IMPORTANT: after identifier renaming, the ClassNode's name may differ
        // from the original name stored in the CF-modification tracker, causing
        // graph.isCfModified(cn.name) to return false even though the class was
        // modified.  The non-CF path (COMPUTE_MAXS with existing frames) can
        // then produce wrong maxLocals (e.g. astore_1 with maxLocals=1), which
        // causes VerifyError at runtime.  Stripping frames and using the CF
        // path unconditionally is slightly slower but always correct.
        stripFrameNodes(cn);

        // CF + compute frames path (preferred).
        try {
            byte[] result = serializeWithMode(cn, graph, true);
            if (result != null) return result;
        } catch (Exception | AssertionError e) {
            // ASM signals malformed input bytecode with AssertionError (an Error,
            // not an Exception) from Frame.putAbstractType during
            // computeAllFrames. Without it here the whole pipeline dies on one
            // bad class instead of rolling that class back to its original
            // bytes, which defeats the neverFail/rollbackToOriginalBytes contract.
            KBoxLog.warn(TAG, "COMPUTE_FRAMES failed for " + cn.name
                    + " (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
            dumpDiagnosticClass(cn, graph);
        }

        // COMPUTE_MAXS fallback (no frames recomputed) produces a class that is
        // ONLY safe when it is never loaded by the JVM: a version>=51 class with
        // a missing/wrong StackMapTable fails at runtime with VerifyError. The
        // only classes guaranteed never to be loaded are our synthetic
        // anti-decompiler classes (com/kbox/runtime/*). For any real, loadable
        // class we signal failure (null) and let the caller roll it back to its
        // original bytes, which always verify.
        if (isNeverLoadedSynthetic(cn.name)) {
            try {
                return serializeWithMode(cn, graph, false);
            } catch (Exception e2) {
                KBoxLog.warn(TAG, "COMPUTE_MAXS fallback failed for " + cn.name
                        + ": " + e2.getMessage());
                return null;
            }
        }
        return null;
    }

    /** TEMP-DIAG: dump the COMPUTE_FRAMES-failing class bytes for post-mortem analysis. */
    private static void dumpDiagnosticClass(ClassNode cn, ClassGraph graph) {
        try {
            int flags = ClassWriter.COMPUTE_MAXS;
            ClassWriter cw = graphAwareWriter(graph, flags);
            cn.accept(cw);
            byte[] bytes = cw.toByteArray();
            String file = "_cfdump-" + cn.name.replace('/', '_') + ".class";
            java.nio.file.Files.write(java.nio.file.Paths.get(file), bytes);
            KBoxLog.warn(TAG, "  [CF-DUMP] wrote " + file + " (" + bytes.length + " bytes)");
        } catch (Throwable t) {
            KBoxLog.warn(TAG, "  [CF-DUMP] failed to dump " + cn.name + ": " + t);
        }
    }

    /** True for kbox synthetic classes that exist only to crash decompiler UIs
     *  and are never loaded by the JVM at runtime. */
    private static boolean isNeverLoadedSynthetic(String internal) {
        return internal.startsWith("com/kbox/runtime/");
    }

    /**
     * After identifier renaming, classes that originally shared a package may
     * be scattered into different packages.  Package-private classes, methods,
     * fields, and constructors lose accessibility from their former
     * package-mates, causing {@code IllegalAccessError} at runtime.
     *
     * <p>Scans every instruction in every class for cross-package references
     * and widens non-public targets:
     * <ul>
     *   <li>Package-private <b>classes</b> → public</li>
     *   <li>Package-private / private <b>methods & constructors</b> → public</li>
     *   <li>Package-private / private <b>fields</b> → public</li>
     * </ul>
     *
     * @param graph    the class graph (all ClassNodes)
     * @param classMap old-internal → new-internal name mappings
     */
    private static void fixCrossPackageClassAccess(ClassGraph graph, Map<String, String> classMap) {
        if (classMap == null || classMap.isEmpty()) return;

        // Build index: newInternalName → ClassNode
        Map<String, ClassNode> byName = new java.util.HashMap<>();
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            String old = e.getKey();
            String newName = classMap.getOrDefault(old, old);
            byName.put(newName, e.getValue());
        }

        int widenedClass = 0;
        int widenedMethod = 0;
        int widenedField = 0;

        for (Map.Entry<String, ClassNode> entry : graph.getClasses().entrySet()) {
            ClassNode caller = entry.getValue();
            String callerNew = classMap.getOrDefault(entry.getKey(), entry.getKey());
            String callerPkg = packageOf(callerNew);

            for (org.objectweb.asm.tree.MethodNode mn :
                    (List<org.objectweb.asm.tree.MethodNode>) caller.methods) {
                if (mn.instructions == null) continue;
                for (org.objectweb.asm.tree.AbstractInsnNode insn = mn.instructions.getFirst();
                     insn != null; insn = insn.getNext()) {

                    String refOwner = null;
                    boolean isMethod = false, isField = false;
                    String refName = null, refDesc = null;

                    if (insn instanceof org.objectweb.asm.tree.TypeInsnNode) {
                        refOwner = ((org.objectweb.asm.tree.TypeInsnNode) insn).desc;
                    } else if (insn instanceof org.objectweb.asm.tree.MethodInsnNode) {
                        org.objectweb.asm.tree.MethodInsnNode mi =
                                (org.objectweb.asm.tree.MethodInsnNode) insn;
                        refOwner = mi.owner;
                        refName = mi.name;
                        refDesc = mi.desc;
                        isMethod = true;
                    } else if (insn instanceof org.objectweb.asm.tree.FieldInsnNode) {
                        org.objectweb.asm.tree.FieldInsnNode fi =
                                (org.objectweb.asm.tree.FieldInsnNode) insn;
                        refOwner = fi.owner;
                        refName = fi.name;
                        refDesc = fi.desc;
                        isField = true;
                    }
                    if (refOwner == null) continue;
                    if (refOwner.startsWith("[")) continue; // arrays

                    ClassNode target = byName.get(refOwner);
                    if (target == null) continue;
                    String targetPkg = packageOf(refOwner);
                    if (targetPkg.equals(callerPkg)) continue; // same package → ok

                    // --- Class-level access ---
                    if ((target.access & Opcodes.ACC_PUBLIC) == 0) {
                        target.access |= Opcodes.ACC_PUBLIC;
                        widenedClass++;
                    }

                    // --- Method-level access ---
                    if (isMethod) {
                        for (org.objectweb.asm.tree.MethodNode tm :
                                (List<org.objectweb.asm.tree.MethodNode>) target.methods) {
                            if (tm.name.equals(refName) && tm.desc.equals(refDesc)) {
                                if ((tm.access & Opcodes.ACC_PUBLIC) == 0) {
                                    // Widen from private / protected / package-private → public.
                                    // Preserve static, final, native, etc.
                                    tm.access = (tm.access & ~(Opcodes.ACC_PRIVATE
                                            | Opcodes.ACC_PROTECTED)) | Opcodes.ACC_PUBLIC;
                                    widenedMethod++;
                                }
                                break;
                            }
                        }
                    }

                    // --- Field-level access ---
                    if (isField) {
                        for (org.objectweb.asm.tree.FieldNode tf :
                                (List<org.objectweb.asm.tree.FieldNode>) target.fields) {
                            if (tf.name.equals(refName) && tf.desc.equals(refDesc)) {
                                if ((tf.access & Opcodes.ACC_PUBLIC) == 0) {
                                    tf.access = (tf.access & ~(Opcodes.ACC_PRIVATE
                                            | Opcodes.ACC_PROTECTED)) | Opcodes.ACC_PUBLIC;
                                    widenedField++;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (widenedClass > 0 || widenedMethod > 0 || widenedField > 0) {
            KBoxLog.info(TAG, "Cross-package access fix: "
                    + widenedClass + " classes, "
                    + widenedMethod + " methods, "
                    + widenedField + " fields widened to public");
        }
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash >= 0 ? internalName.substring(0, slash) : "";
    }

    /**
     * Repairs field/method references that become dangling after identifier
     * renaming. {@code NameObfuscator.KBoxRemapper.resolve*} walks the owner's
     * super + interface chain, but a reference to a member declared in an
     * interface (accessed via an implementing class) or via a super-interface
     * can occasionally escape and keep its ORIGINAL name while the declaration
     * was renamed — producing {@code NoSuchFieldError} /
     * {@code NoSuchMethodError} at runtime.
     *
     * <p>This pass re-resolves every reference against the FINAL renamed graph:
     * if the current {@code owner.name.desc} does not resolve, it walks the
     * owner's hierarchy and, when it finds a class that declares the member
     * under its ORIGINAL name, rewrites the reference {@code owner} and
     * {@code name} to the declaring class's renamed form.
     *
     * @param graph   the class graph (keys are the RENAMED class names)
     * @param mapping the rename mapping (original → renamed)
     */
    @SuppressWarnings("unchecked")
    private static void repairDanglingMemberReferences(ClassGraph graph, Mapping mapping) {
        if (mapping == null || mapping.getClassMap().isEmpty()) return;
        Map<String, String> reverse = new java.util.HashMap<>();
        for (Map.Entry<String, String> e : mapping.getClassMap().entrySet()) {
            reverse.putIfAbsent(e.getValue(), e.getKey());
        }
        int fixedField = 0, fixedMethod = 0;
        int dangling = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.methods == null) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode ins = mn.instructions.getFirst();
                     ins != null; ins = ins.getNext()) {
                    if (ins instanceof org.objectweb.asm.tree.FieldInsnNode) {
                        org.objectweb.asm.tree.FieldInsnNode fi =
                                (org.objectweb.asm.tree.FieldInsnNode) ins;
                        if (isExternalRef(fi.owner)) continue;
                        if (resolvesField(graph, fi.owner, fi.name, fi.desc)) continue;
                        dangling++;
                        String[] fix = resolveRenamedMember(graph, reverse, mapping,
                                fi.owner, fi.name, fi.desc, false);
                        if (fix != null && !fix[1].equals(fi.name)) {
                            KBoxLog.debug(TAG, "Repair field " + cn.name + "." + mn.name
                                    + ": " + fi.owner + "." + fi.name + fi.desc
                                    + " -> " + fix[0] + "." + fix[1]);
                            fi.owner = fix[0];
                            fi.name = fix[1];
                            fixedField++;
                        }
                    } else if (ins instanceof org.objectweb.asm.tree.MethodInsnNode) {
                        org.objectweb.asm.tree.MethodInsnNode mi =
                                (org.objectweb.asm.tree.MethodInsnNode) ins;
                        if (mi.name.charAt(0) == '<' || isExternalRef(mi.owner)) continue;
                        if (resolvesMethod(graph, mi.owner, mi.name, mi.desc)) continue;
                        dangling++;
                        String[] fix = resolveRenamedMember(graph, reverse, mapping,
                                mi.owner, mi.name, mi.desc, true);
                        if (fix != null && !fix[1].equals(mi.name)) {
                            KBoxLog.debug(TAG, "Repair method " + cn.name + "." + mn.name
                                    + ": " + mi.owner + "." + mi.name + mi.desc
                                    + " -> " + fix[0] + "." + fix[1]);
                            mi.owner = fix[0];
                            mi.name = fix[1];
                            fixedMethod++;
                        }
                    }
                }
            }
        }
        KBoxLog.info(TAG, "Dangling-ref repair pass: " + dangling + " dangling, "
                + fixedField + " fields fixed, " + fixedMethod + " methods fixed");
    }

    private static boolean isExternalRef(String owner) {
        return owner.startsWith("java/") || owner.startsWith("javax/") || owner.startsWith("sun/")
                || owner.startsWith("com/sun/") || owner.startsWith("jdk/") || owner.startsWith("com/google/")
                || owner.startsWith("org/apache/") || owner.startsWith("org/jetbrains/")
                || owner.startsWith("com/viaversion/") || owner.startsWith("io/netty/")
                || owner.startsWith("org/slf4j/") || owner.startsWith("org/objectweb/")
                || owner.startsWith("net/minecraft/") || owner.startsWith("com/mojang/")
                || owner.startsWith("net/fabricmc/") || owner.startsWith("org/spongepowered/")
                || owner.startsWith("net/neoforged/") || owner.startsWith("net/minecraftforge/")
                || owner.startsWith("org/bukkit/") || owner.startsWith("org/lwjgl/")
                || owner.startsWith("org/joml/");
    }

    /** True if {@code owner.name.desc} resolves to a member in {@code owner}'s
     *  renamed hierarchy (superclasses + interfaces). */
    private static boolean resolvesField(ClassGraph graph, String owner,
                                         String name, String desc) {
        return findMember(graph, owner, name, desc, false) != null;
    }

    private static boolean resolvesMethod(ClassGraph graph, String owner,
                                          String name, String desc) {
        return findMember(graph, owner, name, desc, true) != null;
    }

    /** BFS over owner's super + interface chain looking for a declared member. */
    private static String findMember(ClassGraph graph, String owner, String name,
                                     String desc, boolean isMethod) {
        java.util.Set<String> visited = new java.util.HashSet<>(8);
        java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
        queue.add(owner);
        visited.add(owner);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (cur.startsWith("java/")) continue;
            if (declares(graph, cur, name, desc, isMethod)) return cur;
            ClassNode cn = graph.getClasses().get(cur);
            if (cn == null) continue;
            if (cn.superName != null && visited.add(cn.superName)) queue.add(cn.superName);
            if (cn.interfaces != null) {
                for (String itf : (List<String>) cn.interfaces) {
                    if (visited.add(itf)) queue.add(itf);
                }
            }
        }
        return null;
    }

    private static boolean declares(ClassGraph graph, String owner, String name,
                                    String desc, boolean isMethod) {
        ClassNode cn = graph.getClasses().get(owner);
        if (cn == null) return false;
        if (isMethod) {
            if (cn.methods == null) return false;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.name.equals(name) && mn.desc.equals(desc)) return true;
            }
        } else {
            if (cn.fields == null) return false;
            for (org.objectweb.asm.tree.FieldNode fn : (List<org.objectweb.asm.tree.FieldNode>) cn.fields) {
                if (fn.name.equals(name) && fn.desc.equals(desc)) return true;
            }
        }
        return false;
    }

    /**
     * For a dangling reference whose member name is the ORIGINAL (pre-rename)
     * identifier, find the renamed declaring class + renamed member name by
     * walking the renamed hierarchy and consulting the mapping (via the reverse
     * class map: renamed class → original class).
     *
     * @return {@code [declaringRenamedClass, renamedMemberName]}, or null.
     */
    private static String[] resolveRenamedMember(ClassGraph graph,
                                                 Map<String, String> reverse,
                                                 Mapping mapping, String owner,
                                                 String name, String desc,
                                                 boolean isMethod) {
        java.util.Set<String> visited = new java.util.HashSet<>(8);
        java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
        queue.add(owner);
        visited.add(owner);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (cur.startsWith("java/")) continue;
            String orig = reverse.get(cur);
            if (orig != null) {
                // The reference's desc uses RENAMED class names; the mapping is
                // keyed by ORIGINAL descs, so translate the desc back first.
                String origDesc = unmapDesc(desc, reverse);
                boolean hit = isMethod ? mapping.hasMethod(orig, name, origDesc)
                        : mapping.hasField(orig, name, origDesc);
                if (hit) {
                    String renamedName = isMethod ? mapping.mapMethod(orig, name, origDesc)
                            : mapping.mapField(orig, name, origDesc);
                    return new String[]{cur, renamedName};
                }
            }
            ClassNode cn = graph.getClasses().get(cur);
            if (cn == null) continue;
            if (cn.superName != null && visited.add(cn.superName)) queue.add(cn.superName);
            if (cn.interfaces != null) {
                for (String itf : (List<String>) cn.interfaces) {
                    if (visited.add(itf)) queue.add(itf);
                }
            }
        }
        return null;
    }

    /**
     * Translates every class reference inside a method/field descriptor from a
     * RENAMED internal name back to its ORIGINAL name using the reverse class
     * map. Descriptors not containing a renamed class are returned unchanged.
     */
    private static String unmapDesc(String desc, Map<String, String> reverse) {
        if (desc == null || desc.indexOf('L') < 0 || reverse.isEmpty()) return desc;
        StringBuilder sb = null;
        int last = 0;
        int len = desc.length();
        for (int i = 0; i < len; i++) {
            if (desc.charAt(i) != 'L') continue;
            int end = desc.indexOf(';', i);
            if (end < 0) break;
            String cls = desc.substring(i + 1, end);
            String orig = reverse.get(cls);
            if (orig != null) {
                if (sb == null) sb = new StringBuilder(len + 16);
                sb.append(desc, last, i).append('L').append(orig).append(';');
                last = end + 1;
            }
            i = end;
        }
        if (sb == null) return desc;
        if (last < len) sb.append(desc, last, len);
        return sb.toString();
    }

    /**
     * Removes try-catch blocks whose start, end, or handler LabelNodes are
     * no longer present in the instruction list.  Orphaned labels produce
     * {@code ClassFormatError: Illegal exception table range} because the
     * JVM verifier cannot resolve {@code start_pc}/{@code end_pc}/
     * {@code handler_pc} to valid code offsets.
     *
     * <p>Also removes blocks where start comes after end (reversed range),
     * which can happen when pipeline transforms reorder instructions.
     */
    private static void cleanupTryCatchBlocks(ClassNode cn) {
        for (org.objectweb.asm.tree.MethodNode mn :
                ((java.util.List<org.objectweb.asm.tree.MethodNode>) cn.methods)) {
            if (mn.tryCatchBlocks == null || mn.tryCatchBlocks.isEmpty()) continue;
            if (mn.instructions == null || mn.instructions.size() == 0) {
                mn.tryCatchBlocks.clear();
                continue;
            }
            // Collect all LabelNode instances currently in the instruction list.
            java.util.Set<org.objectweb.asm.tree.LabelNode> live = new java.util.HashSet<>();
            for (org.objectweb.asm.tree.AbstractInsnNode insn = mn.instructions.getFirst();
                 insn != null; insn = insn.getNext()) {
                if (insn instanceof org.objectweb.asm.tree.LabelNode) {
                    live.add((org.objectweb.asm.tree.LabelNode) insn);
                }
            }
            // Build an index map of instruction positions for range validation.
            java.util.Map<org.objectweb.asm.tree.AbstractInsnNode, Integer> posMap =
                    new java.util.HashMap<>();
            int idx = 0;
            for (org.objectweb.asm.tree.AbstractInsnNode insn = mn.instructions.getFirst();
                 insn != null; insn = insn.getNext()) {
                posMap.put(insn, idx++);
            }
            java.util.Iterator<org.objectweb.asm.tree.TryCatchBlockNode> it =
                    mn.tryCatchBlocks.iterator();
            while (it.hasNext()) {
                org.objectweb.asm.tree.TryCatchBlockNode tcb = it.next();
                if (!live.contains(tcb.start) || !live.contains(tcb.end)
                        || !live.contains(tcb.handler)) {
                    it.remove();
                    continue;
                }
                Integer startPos = posMap.get(tcb.start);
                Integer endPos = posMap.get(tcb.end);
                if (startPos == null || endPos == null || startPos >= endPos) {
                    it.remove();
                }
            }
        }
    }

    /**
     * Removes all FrameNode entries from every method in the class.
     * Stale frames (from before CF obfuscation modified instructions)
     * cause COMPUTE_FRAMES to fail with NullPointerException.
     * Stripping them forces ASM to recompute clean frames.
     */
    private static void stripFrameNodes(ClassNode cn) {
        for (org.objectweb.asm.tree.MethodNode mn : ((java.util.List<org.objectweb.asm.tree.MethodNode>) cn.methods)) {
            if (mn.instructions == null) continue;
            java.util.Iterator<org.objectweb.asm.tree.AbstractInsnNode> it = mn.instructions.iterator();
            while (it.hasNext()) {
                org.objectweb.asm.tree.AbstractInsnNode n = it.next();
                if (n instanceof org.objectweb.asm.tree.FrameNode) {
                    it.remove();
                }
            }
        }
    }

    /**
     * Strips stale debug attributes from every method in the class. After
     * control-flow transforms, LocalVariableTable / LocalVariableTypeTable
     * entries reference local slots that no longer exist, causing
     * {@code VerifyError: Local variable table overflow} at JVM load time.
     * Debug info is not needed for execution, so we strip it unconditionally
     * before serialization.
     */
    @SuppressWarnings("unchecked")
    private static void stripDebugInfo(ClassNode cn) {
        for (org.objectweb.asm.tree.MethodNode mn :
                (List<org.objectweb.asm.tree.MethodNode>) cn.methods) {
            mn.localVariables = null;
            mn.visibleLocalVariableAnnotations = null;
            mn.invisibleLocalVariableAnnotations = null;
            mn.visibleParameterAnnotations = null;
            mn.invisibleParameterAnnotations = null;
        }
    }

    private byte[] serializeWithMode(ClassNode cn, ClassGraph graph, boolean computeFrames) {
        int flags = ClassWriter.COMPUTE_MAXS | (computeFrames ? ClassWriter.COMPUTE_FRAMES : 0);
        final boolean[] imprecise = new boolean[1];
        ClassWriter cw = graphAwareWriter(graph, flags, imprecise);
        cn.accept(cw);
        if (computeFrames && imprecise[0]) {
            // At least one branch join needed a common supertype we could neither
            // read from the graph nor load reflectively, so a frame had to be
            // widened to java/lang/Object. That widening is not always legal —
            // FlatLaf.getDisabledIcon merges `ImageFilter` with a RENAMED
            // GrayFilter subclass and the widened `Object` frame was rejected at
            // class load (VerifyError: ... not assignable to java/awt/image/ImageFilter).
            // The original bytes carry javac's own (correct) StackMapTable, so
            // rolling back is always safe; shipping wrong frames is not.
            KBoxLog.warn(TAG, "Frames not precisely computable for " + cn.name
                    + " (unresolvable common supertype) -> rolling back to original bytes");
            return null;
        }
        return cw.toByteArray();
    }

    /**
     * Builds a {@link ClassWriter} whose {@code getCommonSuperClass} resolves
     * types from the {@link ClassGraph} instead of the system classloader, so
     * frame computation never needs Minecraft/skija/viaversion on the classpath.
     *
     * @param imprecise optional out-flag: set to {@code true} when a common
     *                  supertype could not be determined and {@code java/lang/Object}
     *                  had to be assumed, so the caller can fall back to the
     *                  original bytes instead of shipping possibly-invalid frames.
     */
    private static ClassWriter graphAwareWriter(ClassGraph graph, int flags) {
        return graphAwareWriter(graph, flags, null);
    }

    private static ClassWriter graphAwareWriter(ClassGraph graph, int flags,
                                                final boolean[] imprecise) {
        return new ClassWriter(flags) {
            @Override
            protected String getCommonSuperClass(String type1, String type2) {
                // Avoid loading classes via the system loader; use the graph first.
                if (type1.equals(type2)) return type1;
                ClassNode n1 = graph.getClasses().get(type1);
                ClassNode n2 = graph.getClasses().get(type2);
                if (n1 != null && n2 != null) {
                    String a = type1, b = type2;
                    while (a != null) {
                        String t = b;
                        while (t != null) {
                            if (a.equals(t)) return a;
                            ClassNode tn = graph.getClasses().get(t);
                            t = tn == null ? null : tn.superName;
                        }
                        ClassNode an = graph.getClasses().get(a);
                        a = an == null ? null : an.superName;
                    }
                }
                // At least one type is not in the class graph (a JDK type such as
                // java/awt/image/ImageFilter, or a RENAMED in-jar type the tool's own
                // classpath cannot load). Resolving these straight to java/lang/Object
                // silently downgrades recomputed frames and the JVM then rejects the
                // class. Real case: FlatLaf.getDisabledIcon merges `ImageFilter`
                // (from a checkcast) with a renamed GrayFilter subclass at a branch
                // join; the frame was written as Object, and `Object` is not
                // assignable to the ImageFilter the invokedynamic declares ->
                //   VerifyError: Bad type on operand stack ... invokedynamic
                // So first compare the superclass-name chains, which stay exact even
                // once a chain leaves the graph.
                String byChain = commonSuperByChain(type1, type2, graph);
                if (byChain != null) return byChain;
                // Needs at least one reflective load. When a side cannot be loaded
                // at all, the answer is a guess: report it so the caller can keep
                // the original, valid bytes for this class.
                Class<?> c1 = loadClass(type1, graph);
                Class<?> c2 = loadClass(type2, graph);
                if (c1 == null || c2 == null) {
                    if (imprecise != null) imprecise[0] = true;
                    return "java/lang/Object";
                }
                return commonSuperClassReflective(type1, type2, graph);
            }
        };
    }

    /**
     * Superclass-name chain of {@code type}, following {@code superName} while the
     * graph knows the node. The chain keeps the name of the first node that leaves
     * the graph (that name is still exact) and then stops, because deeper links are
     * unknowable without loading the class.
     */
    private static java.util.List<String> superChain(String type, ClassGraph graph) {
        java.util.List<String> chain = new java.util.ArrayList<>();
        String cur = type;
        for (int guard = 0; cur != null && guard < 128; guard++) {
            chain.add(cur);
            ClassNode cn = graph.getClasses().get(cur);
            cur = (cn == null) ? null : cn.superName;
        }
        return chain;
    }

    /**
     * Common superclass decided purely from superclass-name chains: the first name
     * of {@code type1}'s chain that also occurs in {@code type2}'s chain. Returns
     * {@code null} when the chains share no known name.
     *
     * <p>Only {@code superName} is followed (never interfaces) because ASM's
     * {@code getCommonSuperClass} contract wants a class, and a StackMapTable entry
     * carrying an interface type is not accepted where a class is required.
     */
    private static String commonSuperByChain(String type1, String type2, ClassGraph graph) {
        java.util.List<String> c1 = superChain(type1, graph);
        java.util.List<String> c2 = superChain(type2, graph);
        for (String a : c1) {
            if (c2.contains(a)) return a;
        }
        return null;
    }

    /**
     * Reflectively computes the common super class of two internal class names,
     * consulting the class graph when a type is present and {@link Class#forName}
     * otherwise (JDK / ASM / third-party types the tool itself loads). Returns
     * {@code java/lang/Throwable} etc. precisely, so COMPUTE_FRAMES keeps
     * exception-handler local types (like {@code Throwable}) intact.
     */
    private static String commonSuperClassReflective(String type1, String type2, ClassGraph graph) {
        if (type1.equals(type2)) return type1;
        Class<?> c1 = loadClass(type1, graph);
        Class<?> c2 = loadClass(type2, graph);
        if (c1 == null || c2 == null) return "java/lang/Object";
        if (c1.isAssignableFrom(c2)) return c1.getName().replace('.', '/');
        if (c2.isAssignableFrom(c1)) return c2.getName().replace('.', '/');
        if (c1.isInterface() || c2.isInterface()) return "java/lang/Object";
        // Walk up the super chain of the deeper class until one is a super of the
        // other; guaranteed to terminate at java/lang/Object.
        do {
            c1 = c1.getSuperclass();
            if (c1 == null) return "java/lang/Object";
        } while (!c1.isAssignableFrom(c2));
        return c1.getName().replace('.', '/');
    }

    /** Resolve an internal class name to its {@link Class} via the graph or the classloader. */
    private static Class<?> loadClass(String internalName, ClassGraph graph) {
        try {
            return Class.forName(internalName.replace('/', '.'), false, Packager.class.getClassLoader());
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Re-serializes a class byte array with {@code COMPUTE_FRAMES} so its
     * StackMapTable is recomputed from scratch and guaranteed to match the
     * bytecode. Returns the original bytes unchanged if re-serialization fails.
     */
    private static byte[] recomputeFrames(byte[] bytes, ClassGraph graph) {
        if (bytes == null) return null;
        try {
            ClassReader cr = new ClassReader(bytes);
            ClassNode cn = new ClassNode();
            cr.accept(cn, 0);
            stripFrameNodes(cn);
            ClassWriter cw = graphAwareWriter(graph, ClassWriter.COMPUTE_FRAMES);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Exception e) {
            return bytes;
        }
    }

    private static String mapName(Map<String, String> classMap, String internal) {
        return classMap.getOrDefault(internal, internal);
    }

    /**
     * Resolves the ORIGINAL class bytes for a class given its (possibly
     * renamed) graph key. After identifier renaming the graph keys are the
     * renamed names, but {@code ClassGraph.originalBytes} is keyed by the
     * ORIGINAL names — so a direct lookup by the renamed key misses and the
     * rollback silently no-ops. Resolve via the reverse class map first.
     */
    private static byte[] lookupOriginalBytes(String graphKey,
                                              Map<String, String> reverseClassMap,
                                              ClassGraph graph) {
        byte[] b = graph.getOriginalBytes().get(graphKey);
        if (b != null) return b;
        String orig = reverseClassMap.get(graphKey);
        if (orig != null) return graph.getOriginalBytes().get(orig);
        return null;
    }

    /**
     * Re-applies the FULL rename mapping (classes + fields + methods) to a
     * class's ORIGINAL bytes when a rollback happens. This is critical: a
     * rolled-back class must be renamed consistently with every other class,
     * otherwise it references original field/method names that the defining
     * class has already renamed (e.g. an interface static field accessed via
     * an implementing class) -> NoSuchFieldError / NoSuchMethodError.
     */
    private static byte[] remapRollbackBytes(byte[] current, Mapping mapping, ClassGraph graph) {
        if (mapping == null || mapping.getClassMap().isEmpty()) return current;
        try {
            ClassReader cr = new ClassReader(current);
            ClassWriter cw = new ClassWriter(cr, 0);
            ClassRemapper remap = new ClassRemapper(cw, new FullRollbackRemapper(mapping, graph));
            cr.accept(remap, 0);
            // Deliberately NO frame recomputation here. `current` is the pristine
            // input class, so its StackMapTable was produced by javac against the
            // real library hierarchy and is already correct; ClassRemapper renamed
            // the types inside it consistently. Recomputing frames from our
            // classpath-limited graph is what downgraded e.g. a merged
            // `ImageFilter` frame to `Object` and produced
            //   VerifyError: Bad type on operand stack ... invokedynamic
            // on a rolled-back class — i.e. the rollback itself broke a class that
            // was valid. Keep the original frames.
            return cw.toByteArray();
        } catch (Exception e) {
            KBoxLog.warn(TAG, "Rollback byte remap failed: " + e.getMessage());
            return current;
        }
    }

    /**
     * Remaps class/field/method names from the {@link Mapping}, walking the
     * super class AND interface chain so references made through an
     * implementing class resolve to the member's renamed declaration.
     */
    private static final class FullRollbackRemapper extends Remapper {
        private final Mapping mapping;
        private final ClassGraph graph;

        FullRollbackRemapper(Mapping mapping, ClassGraph graph) {
            this.mapping = mapping;
            this.graph = graph;
        }

        @Override
        public String map(String internalName) {
            return mapping.mapClass(internalName);
        }

        @Override
        public String mapMethodName(String owner, String name, String desc) {
            if (name.charAt(0) == '<') return name;
            String mapped = resolve(owner, name, desc, true);
            return mapped != null ? mapped : name;
        }

        @Override
        public String mapFieldName(String owner, String name, String desc) {
            String mapped = resolve(owner, name, desc, false);
            return mapped != null ? mapped : name;
        }

        private String resolve(String owner, String name, String desc, boolean method) {
            java.util.Set<String> visited = new java.util.HashSet<>(8);
            java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
            queue.add(owner);
            visited.add(owner);
            while (!queue.isEmpty()) {
                String cur = queue.poll();
                if (cur.startsWith("java/")) continue;
                boolean hit = method ? mapping.hasMethod(cur, name, desc)
                        : mapping.hasField(cur, name, desc);
                if (hit) {
                    return method ? mapping.mapMethod(cur, name, desc)
                            : mapping.mapField(cur, name, desc);
                }
                ClassNode cn = graph.getClasses().get(cur);
                if (cn == null) continue;
                if (cn.superName != null && visited.add(cn.superName)) queue.add(cn.superName);
                if (cn.interfaces != null) {
                    for (String itf : (List<String>) cn.interfaces) {
                        if (visited.add(itf)) queue.add(itf);
                    }
                }
            }
            return null;
        }
    }

    private static String dotted(String internal) {
        return internal == null ? null : internal.replace('/', '.');
    }

    /**
     * BF-MC hybrid: prepends {@code BfSecureLoader.attach()} to the class'
     * {@code <clinit>} (creating one if absent) so the blob is decoded when the
     * mod loader first touches a plaintext entry class. attach() is idempotent,
     * so multiple entry classes calling it are harmless. INVOKESTATIC is stack
     * neutral, so inserting at the head of a clinit is always frame-safe.
     */
    private static void injectBfAttach(org.objectweb.asm.tree.ClassNode cn) {
        org.objectweb.asm.tree.MethodNode clinit = null;
        for (Object mo : cn.methods) {
            org.objectweb.asm.tree.MethodNode m = (org.objectweb.asm.tree.MethodNode) mo;
            if ("<clinit>".equals(m.name)) { clinit = m; break; }
        }
        org.objectweb.asm.tree.InsnList insns = new org.objectweb.asm.tree.InsnList();
        insns.add(new org.objectweb.asm.tree.MethodInsnNode(
                org.objectweb.asm.Opcodes.INVOKESTATIC,
                "com/kbox/runtime/BfSecureLoader", "attach", "()V", false));
        if (clinit == null) {
            clinit = new org.objectweb.asm.tree.MethodNode(
                    org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(insns);
            clinit.instructions.add(new org.objectweb.asm.tree.InsnNode(
                    org.objectweb.asm.Opcodes.RETURN));
            clinit.maxStack = 1;
            cn.methods.add(clinit);
        } else {
            clinit.instructions.insert(insns);
            if (clinit.maxStack < 1) clinit.maxStack = 1;
        }
    }

    private static void putEntry(ZipOutputStream out, String name, byte[] data) throws IOException {
        ZipEntry e = new ZipEntry(name);
        out.putNextEntry(e);
        out.write(data);
        out.closeEntry();
    }

    /**
     * Writes an entry STORED (uncompressed) with an explicit CRC-32.
     *
     * <p>Required for {@code BOOT-INF/lib/*.jar}: Spring Boot's boot loader maps
     * each nested jar as a contiguous byte window of the outer archive, so the
     * nested bytes must not be deflated. Deflating them makes every nested jar —
     * and with it every library class and every {@code META-INF} resource it
     * carries ({@code AutoConfiguration.imports}, SLF4J providers, …) —
     * unresolvable at runtime, while the application's own
     * {@code BOOT-INF/classes} entries keep working, which makes the failure look
     * like a Spring configuration problem instead of a packaging one.
     * {@code spring-boot-maven-plugin} stores these entries uncompressed for
     * exactly the same reason.
     */
    private static void putStoredEntry(ZipOutputStream out, String name, byte[] data)
            throws IOException {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        ZipEntry e = new ZipEntry(name);
        e.setMethod(ZipEntry.STORED);
        e.setSize(data.length);
        e.setCompressedSize(data.length);
        e.setCrc(crc.getValue());
        out.putNextEntry(e);
        out.write(data);
        out.closeEntry();
    }

    // ------------------------------------------------------------------
    // Anti-unpack decoys (task #6)
    // ------------------------------------------------------------------
    // Low-risk tricks that make extractor/repacker tools choke a little while
    // the JVM keeps running (none of these entries is ever requested at run time,
    // and all are valid ZIP entries so java.util.zip/ZipOutputStream can emit them):
    //   1. Foo.class/ directory masquerade — a ZIP "directory" whose name looks like
    //      a class file; naive unzippers try to create a FILE and a DIRECTORY with
    //      the same path and fail/abort.
    //   2. junk pseudo-class — a genuine .class-named entry whose body is NOT valid
    //      bytecode; tools that glob **/*.class and naively re-process the dump hit
    //      verification errors instead of clean vectors (safe: it lives under
    //      META-INF/kbox/, which the JVM never treats as a classpath root).
    //   3. decoy native lib — an inert native-looking file that lures disk extractors
    //      that dump *.dll/*.so (the real native blob is packed+encrypted, never these).
    // (A bit-reliable bad-CRC header or a same-name duplicate entry is intentionally
    // NOT used: ZipOutputStream.closeEntry() re-validates STORED CRC / rejects
    // duplicate names and aborts the build — not acceptable.)
    private static void writeAntiUnpackDecoys(ZipOutputStream out) throws IOException {
        String stamp = "Kbox-" + Integer.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextInt());
        String fakePkg = "META-INF/kbox/" + stamp + "/";
        // 1. Dir/file masquerade under a decoy package path (never a real class).
        putEntry(out, fakePkg + "com/kbox/protect/Foo.class/", new byte[0]);
        putEntry(out, fakePkg + "com/kbox/protect/Foo.class/.git", "x".getBytes(StandardCharsets.UTF_8));
        putEntry(out, fakePkg + "com/kbox/protect/Bar.java/", new byte[0]);
        putEntry(out, fakePkg + "com/kbox/protect/Bar.java/.keep", new byte[0]);
        // 2. Junk pseudo-class for naive **/*.class dump reprocessors.
        byte[] junkCls = new byte[]{ (byte)0xCA, (byte)0xFE, (byte)0xBA, (byte)0xBE,
                                     0x00, 0x00, 0x00, 0x3B, /* bogus minor/major */
                                     0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00 }; // junk header, invalid body
        putEntry(out, fakePkg + "META-INF/services/Factory.class", junkCls);
        putEntry(out, fakePkg + "META-INF/services/Factory$Loader.class", junkCls);
        // 3. Decoy native lib for disk-dumping extractors.
        byte[] dll = {0x4D, 0x5A, 0x00, 0x00}; // "MZ\x00\x00" inert fake PE header
        putEntry(out, fakePkg + "native/native-trap.dll", dll);
        putEntry(out, fakePkg + "native/native-trap.so", new byte[]{0x7F, 0x45, 0x4C, 0x46}); // ELF magic
        KBoxLog.info(TAG, "Wrote anti-unpack decoys (dir-masquerade + junk pseudo-class + native decoy) @ kbox/" + stamp);
    }

    /**
     * S5 — two-layer mock fill (kboxDedeobfShieldV1 packaging decoys).
     * Emits a second tier of <em>individually valid</em> pseudo-classes (real
     * CAFEBABE, correct structure) plus a fake second-level mock index / native
     * blob. None of these names ever appear in the real payload index (neither the
     * normal class map nor the BF KBII header), and loading is fail-closed, so at
     * runtime they are inert; a static tool that dumps/{@code **&#47;*.class}-recompiles
     * or enumerates the blob by name instead spends effort on a convincing mock
     * goldmine and cannot separate real entries from decoys from the container alone.
     */
    private static void writeMockFill(ZipOutputStream out, ProtectionConfig cfg) throws IOException {
        int lvl = cfg.getBlobMockFill();
        if (lvl <= 0) return;
        int ncls = lvl >= 3 ? 12 : (lvl == 2 ? 8 : 4);
        java.util.concurrent.ThreadLocalRandom r = java.util.concurrent.ThreadLocalRandom.current();
        StringBuilder tb = new StringBuilder();
        final String hex = "0123456789abcdef";
        for (int i = 0; i < 8; i++) tb.append(hex.charAt(r.nextInt(16)));
        String stamp = tb.toString();
        for (int i = 0; i < ncls; i++) {
            String name = "com/kbox/mock/_M" + stamp + "_" + i;
            putEntry(out, name + ".class", mockClassBytes(name + "_x"));
        }
        // fake second-level mock index (looks like a class/entry manifest)
        byte[] mockIdx = buildMockIndex(stamp, ncls);
        putEntry(out, "META-INF/kbox/mock-" + stamp + ".idx", mockIdx);
        // bogus MZ/ELF native blob decoy
        byte[] fakeBlob = new byte[512];
        r.nextBytes(fakeBlob);
        fakeBlob[0] = 0x4D; fakeBlob[1] = 0x5A;
        putEntry(out, "META-INF/kbox/mock-" + stamp + ".bin", fakeBlob);
        KBoxLog.info(TAG, "S5 two-layer mock fill: " + ncls + " pseudo-classes + mock index "
                + mockIdx.length + "b + fake native @ kbox/mock-" + stamp);
    }

    /** Build a minimal valid class file whose only member is a no-op ctor. */
    private static byte[] mockClassBytes(String simple) {
        org.objectweb.asm.ClassWriter cw =
                new org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
        cw.visit(org.objectweb.asm.Opcodes.V1_8, org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_FINAL,
                "com/kbox/mock/" + simple, null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0);
        mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(org.objectweb.asm.Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] buildMockIndex(String stamp, int ncls) {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream d = new java.io.DataOutputStream(bo);
        try {
            d.writeInt(0x4B4D4949 ^ 0x7A3D88C1); // masked, NOT ASCII "KMII"
            d.writeInt(ncls);
            for (int i = 0; i < ncls; i++) {
                String s = "com/kbox/mock/_M" + stamp + "_" + i;
                d.writeInt(s.length());
                d.write(s.getBytes(StandardCharsets.UTF_8));
                d.writeInt((int) ((i * 2654435761L) >>> 0));
                d.writeInt((i = i)); // harmless self-assign keeps byte-order noisy-ish
                d.writeInt(0xFFFF & (i * 31));
            }
        } catch (java.io.IOException ignored) {
            // unreachable for an in-memory stream
        }
        return bo.toByteArray();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        return bo.toByteArray();
    }
}
