package com.kbox.core.jnic;

import com.kbox.core.KBoxException;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Build-time complement to {@link com.kbox.runtime.NativeCrypto}.
 *
 * <p>Compiles the self-contained native crypto source
 * ({@code kbox_vmp_crypto.c}: SHA-256, HMAC-SHA256, HKDF-SHA256 and a
 * single-byte decrypt-and-erase primitive) into a platform shared library and
 * packs it with {@link NativePacker} into the
 * {@code META-INF/kbox/native-crypto.bin} blob that the packager embeds in the
 * protected jar.
 *
 * <p>The native layer is <b>strictly additive</b>. If the compiler is missing,
 * the compile fails, or packing fails, this returns {@code null} and the whole
 * pipeline continues on the byte-identical Java HKDF path. Production-code
 * correctness therefore never depends on a native toolchain being present.
 */
public final class NativeCryptoBuilder {

    private static final String TAG = "ncrypto";

    /** C source resource on the build classpath (also shipped to the runtime
     *  via {@code NativeCrypto} as an optional layer). */
    private static final String C_RESOURCE = "kbox_vmp_crypto.c";

    private static final String LIB_NAME = "kbox_native_crypto";

    private NativeCryptoBuilder() {}

    /**
     * Attempts to build + pack the native crypto library.
     *
     * @param workDir scratch directory; the generated C source and compiled lib
     *                are placed under {@code kbox-ncrypto-src/}.
     * @param cfg     config (used only for the configured {@code cc} path).
     * @return the packed blob to embed as {@code META-INF/kbox/native-crypto.bin},
     *         or {@code null} if the toolchain is unavailable / the build fails.
     *         {@code null} is always safe: the runtime falls back to Java HKDF.
     */
    public static byte[] build(Path workDir, ProtectionConfig cfg) {
        try {
            Path cDir = workDir.resolve("kbox-ncrypto-src");
            Files.createDirectories(cDir);
            Path cSrc = NativeCompiler.writeSource(cDir, "kbox_vmp_crypto",
                    com.kbox.core.nativeshell.NativeShellGuard.guardSource(readResource(C_RESOURCE)));
            NativeCompiler.Result cres = new NativeCompiler(cfg.getCc()).compile(cSrc, cDir, LIB_NAME);
            if (!cres.success) {
                KBoxLog.warn(TAG, "native crypto build skipped (compiler unavailable/failed), "
                        + "using Java HKDF path: " + oneLine(cres.log));
                return null;
            }
            NativePacker.Packed packed = NativePacker.pack(cres.library);
            KBoxLog.info(TAG, "Native crypto lib packed: " + packed.blob.length + " bytes");
            return packed.blob;
        } catch (Throwable t) {
            KBoxLog.warn(TAG, "native crypto build skipped (" + t + "), using Java HKDF path");
            return null;
        }
    }

    private static String readResource(String name) throws IOException {
        try (InputStream in = NativeCryptoBuilder.class.getClassLoader().getResourceAsStream(name)) {
            if (in == null) throw new KBoxException("Resource not found: " + name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String oneLine(String s) {
        if (s == null) return "";
        String t = s.replace('\n', ' ').trim();
        return t.length() > 220 ? t.substring(0, 220) + "..." : t;
    }
}