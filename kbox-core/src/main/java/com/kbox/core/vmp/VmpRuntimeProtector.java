package com.kbox.core.vmp;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.io.InputStream;

/**
 * Loads the KBox runtime <b>decryption</b> classes from the classpath into the
 * protection {@link ClassGraph} and registers their decryption methods for VMP,
 * so the decryption algorithm is never present as plain JVM bytecode in the
 * protected jar — it is translated to custom VMP opcodes that only
 * {@link com.kbox.runtime.VmpInterpreter} can execute.
 *
 * <p>This is invoked by the pipeline only when VMP is enabled
 * ({@link ProtectionConfig#isEnableVmp()}). It runs <em>after</em> string
 * encryption so the decryptor's own string literals (e.g. {@code "AES/CBC/PKCS5Padding"})
 * are NOT encrypted (the decryptor cannot call itself to decrypt its own
 * constants). The loaded classes are added to the graph's keep-set via the
 * existing {@code com.kbox.runtime.} keep prefix, so they are never renamed
 * (renaming would break the encrypted-string call sites that reference
 * {@code com.kbox.runtime.KBoxRuntime.d}).
 *
 * <p>Methods registered for VMP:
 * <ul>
 *   <li>{@code KBoxRuntime.d(byte[])String} — XOR string decryptor</li>
 *   <li>{@code KBoxRuntime.a(byte[])String} — AES string decryptor</li>
 *   <li>{@code KBoxRuntime.deriveKey(int)SecretKeySpec} — AES key derivation</li>
 *   <li>{@code ResourceGuardClassLoader.decryptClass(byte[])byte[]} — Anti-Dump class decryptor</li>
 *   <li>{@code ResourceGuardClassLoader.decryptResource(byte[])byte[]} — resource decryptor</li>
 * </ul>
 *
 * <p>{@code corrupt}/{@code corrypt} (the anti-debug decoy paths) are left as
 * plain bytecode — they are tiny and only run when tampering is detected, so
 * protecting them adds no security.
 */
public final class VmpRuntimeProtector {

    private static final String TAG = "vmp-rt";

    private static final String[] RUNTIME_CLASSES = {
            "com/kbox/runtime/KBoxRuntime",
            "com/kbox/runtime/ResourceGuardClassLoader",
            // ResourceGuardClassLoader is not self-contained: its own class file
            // references the nested Entry/closures and LicVerifier. When only the
            // outer class is added to the graph, the packager's reference-closure
            // check aborts with "would reference N missing KBox runtime class(es)".
            // Ship the whole set so VMP (which loads these runtime decryptors into
            // the graph) produces a loadable jar.
            "com/kbox/runtime/ResourceGuardClassLoader$Entry",
            "com/kbox/runtime/ResourceGuardClassLoader$1",
            "com/kbox/runtime/ResourceGuardClassLoader$2",
            "com/kbox/runtime/ResourceGuardClassLoader$2$1",
            "com/kbox/runtime/LicVerifier",
            "com/kbox/runtime/LicVerifier$State",
    };

    /** Decryption method specs (owner#name#desc) eligible for VMP. */
    private static final String[] DECRYPT_METHODS = {
            "com.kbox.runtime.KBoxRuntime#d#([B)Ljava/lang/String;",
            "com.kbox.runtime.KBoxRuntime#a#([B)Ljava/lang/String;",
            "com.kbox.runtime.KBoxRuntime#deriveKey#(I)Ljavax/crypto/spec/SecretKeySpec;",
            "com.kbox.runtime.ResourceGuardClassLoader#decryptClass#([B)[B",
            "com.kbox.runtime.ResourceGuardClassLoader#decryptResource#([B)[B",
    };

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public VmpRuntimeProtector(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /**
     * Loads the runtime decryption classes into the graph (when not already
     * present) and registers their decryption methods for VMP. Returns the
     * number of classes loaded.
     */
    public int load() {
        if (!cfg.isEnableVmp()) return 0;
        if (!cfg.isVmpProtectRuntime()) {
            KBoxLog.info(TAG, "VMP runtime protection disabled (vmpProtectRuntime=false), "
                    + "loading runtime classes without VMP translation");
            // Still load the runtime classes into the graph so they get packaged,
            // but don't register them for VMP translation.
            int loaded = 0;
            for (String internal : RUNTIME_CLASSES) {
                if (graph.getClasses().containsKey(internal)) continue;
                ClassNode cn = loadFromClasspath(internal);
                if (cn == null) {
                    KBoxLog.warn(TAG, "Could not load runtime class: " + internal);
                    continue;
                }
                graph.getClasses().put(internal, cn);
                loaded++;
            }
            return loaded;
        }
        // Only load when the decryption methods will actually be used at runtime.
        boolean needsStringDecryptor = cfg.isEncryptStrings();
        boolean needsClassDecryptor = cfg.isEncryptClasses();
        boolean needsResourceDecryptor = cfg.isObfuscateResources();
        if (!needsStringDecryptor && !needsClassDecryptor && !needsResourceDecryptor) {
            return 0;
        }
        int loaded = 0;
        for (String internal : RUNTIME_CLASSES) {
            if (graph.getClasses().containsKey(internal)) {
                // Already present (e.g. self-protection of the protector itself).
                continue;
            }
            ClassNode cn = loadFromClasspath(internal);
            if (cn == null) {
                KBoxLog.warn(TAG, "Could not load runtime class for VMP: " + internal);
                continue;
            }
            graph.getClasses().put(internal, cn);
            loaded++;
        }
        // KBX-audit "补" (VmpRuntimeProtector:125): registration used to be gated
        // on loaded > 0, which silently skipped it on self-protection builds where
        // the runtime classes were ALREADY in the graph (loaded == 0). Register per
        // spec whenever the owning class exists in the graph (freshly loaded or
        // not); log visibly when a needed decryptor's owner is missing.
        int registered = 0;
        for (String spec : DECRYPT_METHODS) {
            String ownerInternal = spec.substring(0, spec.indexOf('#')).replace('.', '/');
            if (!graph.getClasses().containsKey(ownerInternal)) {
                KBoxLog.warn(TAG, "VMP runtime decryptor owner missing from graph: "
                        + ownerInternal + " (" + spec + " NOT registered)");
                continue;
            }
            boolean add =
                    (needsStringDecryptor && spec.startsWith("com.kbox.runtime.KBoxRuntime#"))
                    || (needsClassDecryptor && spec.contains("decryptClass"))
                    || (needsResourceDecryptor && spec.contains("decryptResource"));
            if (add && cfg.getVmpMethods().add(spec)) registered++;
        }
        KBoxLog.info(TAG, "VMP runtime protection: loaded=" + loaded + " runtime class(es),"
                + " registered=" + registered + "/" + DECRYPT_METHODS.length
                + " decryptor spec(s); total vmpMethods=" + cfg.getVmpMethods().size());
        return loaded;
    }

    private ClassNode loadFromClasspath(String internal) {
        String res = internal + ".class";
        ClassLoader cl = VmpRuntimeProtector.class.getClassLoader();
        try (InputStream in = cl.getResourceAsStream(res)) {
            if (in == null) return null;
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) > 0) bo.write(buf, 0, r);
            ClassNode cn = new ClassNode();
            // IMPORTANT: do NOT use SKIP_FRAMES here. These runtime classes are
            // serialized later by Packager.serialize(). If frames are dropped now
            // and the class is Java 7+ (needs a StackMapTable), the COMPUTE_MAXS
            // path preserves "existing" frames - which there are none - producing
            // a frame-less class that fails JVM verification (VerifyError:
            // "Expecting a stackmap frame at branch target"). Preserve frames so
            // Packager can recompute or carry them correctly.
            com.kbox.core.compat.ClassFileCompat.accept(bo.toByteArray(), cn,
                    ClassReader.SKIP_DEBUG | ClassReader.EXPAND_FRAMES);
            return cn;
        } catch (IOException e) {
            return null;
        }
    }
}
