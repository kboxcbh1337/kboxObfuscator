package com.kbox.core.jnic;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Orchestrates the JNIC pipeline for the whole graph:
 * <ol>
 *   <li>For each method in the user's {@code nativeMethod} config that has a
 *       matching declaration, translate the body to C via {@link JniCTranslator}.
 *       Each translated function gets an opaque symbol ({@code _kfnN}).</li>
 *   <li>If translation succeeds for at least one method, write the assembled
 *       C source (including a {@code JNI_OnLoad} registrar that calls
 *       {@code RegisterNatives}) and invoke {@link NativeCompiler} to produce
 *       a shared lib.</li>
 *   <li><b>Compress + encrypt</b> the shared lib with {@link NativePacker}
 *       (LZ77/DEFLATE + ChaCha20). The packed blob is returned so the
 *       {@link com.kbox.core.packaging.Packager} can embed it as
 *       {@code META-INF/kbox/native.bin}; the raw {@code .dll}/{@code .so} is
 *       never stored in the jar.</li>
 *   <li>For every successfully-translated method, mark it {@code ACC_NATIVE} and
 *       strip its bytecode.</li>
 *   <li>Inject a {@code <clinit>} call to {@code NativeLoader.load()} in the
 *       first class of the graph. {@code NativeLoader} reads the blob, decrypts
 *       and decompresses it, writes the lib to a temp file and calls
 *       {@code System.load}.</li>
 *   <li>Methods that failed translation are <em>not</em> touched: they continue
 *       through the obfuscation pipeline (graceful fall-back).</li>
 * </ol>
 */
public final class JnicOrchestrator {

    private static final String TAG = "jnic";
    private static final String LIB_NAME = "kbox_native";
    /** Runtime class that unpacks + loads the compressed/encrypted native lib. */
    private static final String NATIVE_LOADER = "com/kbox/runtime/NativeLoader";
    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final NativeCompiler compiler;

    public JnicOrchestrator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
        this.compiler = new NativeCompiler(cfg.getCc());
    }

    public static final class Result {
        public final Path libraryPath;
        /** Packed (compressed+encrypted) native-lib blob, or null when JNIC is off/failed. */
        public final byte[] packedBlob;
        public final boolean enabled;
        public final Map<String, String> failed; // method key -> reason
        public Result(Path lib, byte[] blob, boolean enabled, Map<String, String> failed) {
            this.libraryPath = lib; this.packedBlob = blob;
            this.enabled = enabled; this.failed = failed;
        }
    }

    public Result run(Path workDir) throws IOException {
        if (!cfg.isEnableJnic()) {
            return new Result(null, null, false, new HashMap<>());
        }
        Map<String, String> failures = new HashMap<>();
        List<JniBytecodeInterp.InterpFn> fns = new ArrayList<>();
        Map<String, MethodNode> toMark = new HashMap<>();
        // Every class that ends up with at least one JNIC-native method. Each such
        // class must load the native library from its <clinit>, otherwise calling
        // a native method on a class whose <clinit> never ran yields
        // UnsatisfiedLinkError (JNIC full-coverage sinks entry-point classes too).
        java.util.Set<ClassNode> nativeClasses = new java.util.LinkedHashSet<>();

        // Method-name multiplicity per class (ALL methods, not just the JNIC
        // ones) — the JVM decides between the short and long JNI export symbol
        // from the class's full method table, so translated methods must know
        // whether their name is overloaded in their owner class.
        java.util.Map<String, java.util.Map<String, Integer>> classMethodCounts = new HashMap<>();
        for (ClassNode cn : graph.getClasses().values()) {
            java.util.Map<String, Integer> nameCounts =
                    classMethodCounts.computeIfAbsent(cn.name, k -> new HashMap<>());
            for (MethodNode mn : cn.methods) {
                nameCounts.merge(mn.name, 1, Integer::sum);
            }
        }

        KBoxLog.info(TAG, "Native methods to find: " + cfg.getNativeMethods().size()
                + " keys: " + new ArrayList<>(cfg.getNativeMethods()));
        int index = 0;
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            ClassNode cn = e.getValue();
            // Body-sinking eligibility: use shouldProtectClass (NOT shouldTransformClass)
            // so a KEPT entry-point class can still have its method bodies sunk to
            // native — same gate as every other body-protection pass (control-flow,
            // string-encrypt, VMP) and exactly what the AutoJnicVmpSelector used when it
            // selected the native methods. shouldTransformClass excludes kept classes
            // and would silently drop every selected method for a single-class app whose
            // only class is the auto-kept Main, leaving JNIC to produce no native blob.
            if (!cfg.shouldProtectClass(cn.name)) {
                KBoxLog.debug(TAG, "  skip " + cn.name + " (shouldTransform=false)");
                continue;
            }
            if (!cfg.isNativeEligible(cn.name)) {
                KBoxLog.debug(TAG, "  skip " + cn.name + " (native-excluded prefix)");
                continue;
            }
            for (MethodNode mn : cn.methods) {
                String key = ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
                boolean isNative = cfg.getNativeMethods().contains(key);
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (isNative) {
                    KBoxLog.debug(TAG, "  MATCH: " + key + " -> " + cn.name + "." + mn.name + mn.desc);
                }
                if (!isNative) continue;
                // Check for unsupported bytecode instructions in the JNIC interpreter.
                String unsupported = checkUnsupportedInsns(mn);
                if (unsupported != null) {
                    failures.put(key, "contains unsupported instruction: " + unsupported);
                    KBoxLog.warn(TAG, "JNIC skip " + key + ": contains " + unsupported + " (not yet supported by interpreter)");
                    continue;
                }
                // Reject frames too large for the fixed-size native interpreter
                // arrays (kbox_ctx_t.stack[256] / locals[256]); exceeding them would
                // overrun the heap-allocated context (buffer overflow).
                if (mn.maxLocals > 256 || mn.maxStack > 256) {
                    failures.put(key, "frame too large: maxLocals=" + mn.maxLocals
                            + " maxStack=" + mn.maxStack);
                    KBoxLog.warn(TAG, "JNIC skip " + key + ": frame too large (maxLocals="
                            + mn.maxLocals + ", maxStack=" + mn.maxStack + ")");
                    continue;
                }
                try {
                    // Use the interpreter-based translator: packages raw bytecode
                    // + CP refs, calls kbox_jvm_interp() in the native library.
                    JniBytecodeInterp.InterpFn fn = JniBytecodeInterp.translate(cn.name, mn, index++);
                    fns.add(fn);
                    toMark.put(fn.symbol, mn);
                    nativeClasses.add(cn);
                    KBoxLog.info(TAG, "Interp-translated " + key + " -> " + fn.symbol
                            + " (javaClass=" + fn.javaClass + ")");
                } catch (Exception ex) {
                    failures.put(key, ex.getMessage());
                    KBoxLog.warn(TAG, "JNIC interp failed for " + key + ": " + ex.getMessage()
                            + " (falling back to obfuscation)");
                }
            }
        }
        if (fns.isEmpty()) {
            KBoxLog.warn(TAG, "No methods eligible for JNIC; skipping native lib");
            return new Result(null, null, true, failures);
        }

        // Compile: generate stub source + interpreter source, compile together.
        Path cDir = workDir.resolve("kbox-native-src");
        Files.createDirectories(cDir);

        // Write interpreter source.
        Path interpSrc = NativeCompiler.writeInterpreterSource(cDir);

        // Write stub source.
        String src = NativeCompiler.assembleInterpSource(fns, classMethodCounts);
        // Native shell hardening: encrypt function-body literals (class names,
        // method signatures) in the generated JNI stubs and mutate any matched
        // guard functions. Fail-safe — unknown contexts are left verbatim.
        src = com.kbox.core.nativeshell.NativeShellGuard.guardSource(src);
        Path stubSrc = NativeCompiler.writeSource(cDir, LIB_NAME, src);

        List<Path> srcFiles = new ArrayList<>();
        srcFiles.add(stubSrc);
        if (interpSrc != null) srcFiles.add(interpSrc);

        NativeCompiler.Result cres = compiler.compileMulti(srcFiles, cDir, LIB_NAME);
        if (!cres.success) {
            KBoxLog.error(TAG, "Native compilation failed: " + cres.log);
            try {
                java.nio.file.Files.write(
                        java.nio.file.Paths.get(System.getProperty("user.dir"), "jnic-gcc.log"),
                        cres.log.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } catch (Exception ignored) {}
            if (cfg.isFailOnNativeError()) {
                throw new RuntimeException("JNIC compile failed: " + cres.log);
            }
            KBoxLog.warn(TAG, "Native compile failed; all JNIC methods left as Java");
            return new Result(null, null, true, failures);
        }

        // Pack the native lib.
        byte[] blob = null;
        try {
            NativePacker.Packed packed = NativePacker.pack(cres.library);
            blob = packed.blob;
            KBoxLog.info(TAG, "Native lib packed: " + blob.length + " bytes (blob)");
        } catch (Exception ex) {
            KBoxLog.warn(TAG, "Native packing failed: " + ex.getMessage()
                    + " — falling back to raw lib copy");
        }

        // Mark methods native.
        for (JniBytecodeInterp.InterpFn fn : fns) {
            MethodNode mn = toMark.get(fn.symbol);
            mn.access |= Opcodes.ACC_NATIVE;
            mn.instructions.clear();
            if (mn.tryCatchBlocks != null) mn.tryCatchBlocks.clear();
            mn.localVariables = null;
        }

        // Inject NativeLoader.load() into EVERY class that carries a JNIC-native
        // method (not just the first one). Each such class's <clinit> loads the
        // native lib, so any native method is guaranteed to be resolvable even
        // when the entry-point class itself was sunk to native.
        for (ClassNode nc : nativeClasses) {
            injectNativeLoader(nc);
        }
        return new Result(cres.library, blob, true, failures);
    }

    /** Adds {@code NativeLoader.load()} at the start of <clinit>. */
    @SuppressWarnings("unchecked")
    private void injectNativeLoader(ClassNode cn) {
        MethodNode clinit = null;
        for (MethodNode m : (List<MethodNode>) cn.methods) {
            if (m.name.equals("<clinit>") && m.desc.equals("()V")) { clinit = m; break; }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
            clinit.maxStack = 1;
            cn.methods.add(clinit);
        }
        org.objectweb.asm.tree.InsnList head = new org.objectweb.asm.tree.InsnList();
        head.add(new MethodInsnNode(Opcodes.INVOKESTATIC, NATIVE_LOADER, "load",
                "()V", false));
        clinit.instructions.insert(head);
        clinit.maxStack = Math.max(clinit.maxStack, 1);
    }

    /**
     * Opcodes the JNIC v3 interpreter has no dispatch-table entry for (see
     * {@code kbox_init_table()} in kbox_jnic_interp_v3.c). Everything else the
     * C interpreter handles natively. {@code LDC_W}/{@code LDC2_W} are absent on
     * purpose: the serializer normalises both to {@code LDC} (0x12) with a tagged
     * 16-bit CP operand, so they never appear in the serialised stream. The four
     * opcodes below are legacy control-flow forms that have no native handler and
     * whose encoding ({@code insnSize}/{@code writeInsn}) is not implemented, so a
     * method containing any of them is rejected and left to the Java obfuscator.
     */
    private static final Set<Integer> UNSUPPORTED_JNIC_OPCODES = new HashSet<>();
    static {
        UNSUPPORTED_JNIC_OPCODES.add(Opcodes.JSR);    // 0xA8
        UNSUPPORTED_JNIC_OPCODES.add(Opcodes.RET);    // 0xA9
        UNSUPPORTED_JNIC_OPCODES.add(0xC8);           // GOTO_W (not in ASM Opcodes)
        UNSUPPORTED_JNIC_OPCODES.add(0xC9);           // JSR_W  (not in ASM Opcodes)
    }

    /**
     * Checks if a method contains bytecode instructions not supported by
     * the JNIC v3 interpreter. Returns the unsupported opcode name or null.
     *
     * <p>The C interpreter natively handles the full modern JVM instruction
     * set — including {@code TABLESWITCH}, {@code LOOKUPSWITCH},
     * {@code MULTIANEWARRAY}, {@code INVOKEDYNAMIC} (via the injected
     * {@code JnicIndy} bootstrap resolver), {@code WIDE} (emitted by the
     * serializer for large local indices) and the exception table — so this
     * guard only trips on the legacy JSR/RET/GOTO_W/JSR_W forms.
     */
    @SuppressWarnings("unchecked")
    static String checkUnsupportedInsns(MethodNode mn) {
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int op = insn.getOpcode();
            if (op < 0) continue; // labels / frames / line numbers
            if (UNSUPPORTED_JNIC_OPCODES.contains(op)) {
                return opcodeName(op);
            }
        }
        return null;
    }

    private static String opcodeName(int op) {
        switch (op) {
            case Opcodes.JSR:    return "JSR";
            case Opcodes.RET:    return "RET";
            case 0xC8:           return "GOTO_W";
            case 0xC9:           return "JSR_W";
            default: return String.format("0x%02X", op);
        }
    }
}
