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
import java.util.List;
import java.util.Map;

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
        ClassNode firstClass = null;

        KBoxLog.info(TAG, "Native methods to find: " + cfg.getNativeMethods().size()
                + " keys: " + new ArrayList<>(cfg.getNativeMethods()));
        int index = 0;
        for (Map.Entry<String, ClassNode> e : graph.getClasses().entrySet()) {
            ClassNode cn = e.getValue();
            if (!cfg.shouldTransformClass(cn.name)) {
                KBoxLog.debug(TAG, "  skip " + cn.name + " (shouldTransform=false)");
                continue;
            }
            if (firstClass == null) firstClass = cn;
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
        String src = NativeCompiler.assembleInterpSource(fns);
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

        // Inject NativeLoader.load().
        if (firstClass != null) {
            injectNativeLoader(firstClass);
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
     * Checks if a method contains bytecode instructions not supported by
     * the JNIC v3 interpreter. Returns the unsupported opcode name or null.
     *
     * <p>The C interpreter now natively handles {@code TABLESWITCH},
     * {@code LOOKUPSWITCH}, {@code MULTIANEWARRAY} and {@code INVOKEDYNAMIC}
     * (via the injected {@code JnicIndy} bootstrap resolver), so this check is
     * a no-op. It is retained as a guard so future additions must be reflected
     * here explicitly rather than silently breaking serialisation.
     */
    @SuppressWarnings("unchecked")
    static String checkUnsupportedInsns(MethodNode mn) {
        return null;
    }
}
