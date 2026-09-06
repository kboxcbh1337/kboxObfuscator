package com.kbox.runtime;

/**
 * Native binding for VMP crypto primitives.
 *
 * <p>Exposes two atomic operations implemented in C ({@code kbox_vmp_crypto.c}):
 * <ul>
 *   <li>{@link #hkdfSha256(byte[], byte[], byte[], int)} — byte-for-byte identical
 *       to {@code HardwareKeyRing.hkdfSha256(...)} (RFC 5869), run in native code
 *       so the master/per-run key derivation never has to materialise the PRK on
 *       the Java heap.</li>
 *   <li>{@link #decryptByteAt(byte[], int, byte[])} — decrypts a single byte of a
 *       resident stream in native, returning only a transient value.</li>
 * </ul>
 *
 * <p>The native library is an <b>additive, optional</b> layer. Every operation has
 * a Java fallback that produces byte-identical output, so the protect pipeline is
 * fully usable whether or not the native lib is present/loadable. Callers use
 * {@link #available()} to decide which path to take; they never observe a hard
 * failure from the native side.
 *
 * <p>Loading uses {@link System#load} + JNI auto-binding on the
 * {@code Java_com_kbox_runtime_NativeCrypto_*} exports. The packed blob is loaded
 * via {@link #ensureLoaded()} which is self-contained (owns its own blob resource,
 * independent of the JNIC {@code native.bin} loader).
 */
public final class NativeCrypto {

    /** Blob resource written by the packager (NativePacker format). */
    private static final String BLOB_PATH = "META-INF/kbox/native-crypto.bin";

    private NativeCrypto() {}

    private static volatile boolean available = false;
    private static volatile boolean tried = false;

    /** True once the native crypto lib is loaded and its natives are bound. */
    public static boolean available() {
        if (!tried) ensureLoaded();
        return available;
    }

    private static synchronized void ensureLoaded() {
        if (tried) return;
        tried = true;
        try {
            byte[] blob = loadResource(BLOB_PATH);
            if (blob == null) return;
            byte[] lib = unpack(blob);
            if (lib == null || lib.length == 0) return;
            java.nio.file.Path tmp = writeToTemp(lib);
            if (tmp == null) return;
            try {
                System.load(tmp.toAbsolutePath().toString());
                // Probe availability with a trivial call.
                if (probe()) available = true;
            } finally {
                purgeTemp(tmp);
            }
        } catch (Throwable t) {
            available = false;
        }
    }

    /** Removes the mapped PE from disk. Windows refuses to delete a file while
     *  its image section is mapped (delete returns ACCESS_DENIED), so on that
     *  path the module is renamed to a random hidden name — the one operation
     *  the OS permits on a mapped image — via the resident decoder's
     *  {@link BfSecureLoader#purgeSelf}, and the renamed path is scheduled for
     *  deletion at exit. Falls back to a Java-side rename when the resident
     *  decoder is unavailable (non-BF pipeline). */
    private static void purgeTemp(java.nio.file.Path tmp) {
        nukeTemp(tmp);   // zero-fill the plaintext PE before removal (disk-capture closure)
        try {
            if (java.nio.file.Files.deleteIfExists(tmp)) return;
        } catch (Throwable ignored) {
            // mapped image: plain delete is refused on Windows
        }
        try {
            String renamed = BfSecureLoader.purgeSelf(tmp.toAbsolutePath().toString());
            if (renamed == null) return; // fully removed
            final java.nio.file.Path rp = java.nio.file.Paths.get(renamed);
            rp.toFile().deleteOnExit();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try { java.nio.file.Files.deleteIfExists(rp); } catch (Throwable ignored2) {}
            }));
        } catch (Throwable t) {
            // Resident decoder unavailable (non-BF): rename via Java.
            try {
                java.nio.file.Path rp = java.nio.file.Files.move(tmp,
                        tmp.resolveSibling(".kboxnc~"
                                + Integer.toHexString(System.identityHashCode(tmp)) + ".tmp"),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                rp.toFile().deleteOnExit();
            } catch (Throwable ignored2) {}
        }
    }

    /** Trivial self-check: HKDF of a known vector must be non-trivial. */
    private static boolean probe() {
        try {
            byte[] r = hkdfSha2560(new byte[]{1, 2, 3}, new byte[1], new byte[0], 16);
            return r != null && r.length == 16;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Native HKDF-SHA256 (RFC 5869) — byte-identical to
     * {@link HardwareKeyRing#hkdfSha256(byte[], byte[], String, int)} where the
     * {@code info} string is its UTF-8 bytes. Returns {@code null} if the native
     * lib is unavailable (caller falls back to the Java implementation).
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int len) {
        if (!available()) return null;
        try {
            return hkdfSha2560(ikm == null ? new byte[0] : ikm,
                    salt == null ? new byte[0] : salt,
                    info == null ? new byte[0] : info, len);
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Native single-byte stream decrypt: {@code res[pos] ^ ks[pos]}, returning only
     * the transient plain byte. Returns {@code Byte.MIN_VALUE} on unavailable;
     * callers should gate on {@link #available()} instead of inspecting the value.
     */
    public static int decryptByteAt(byte[] res, int pos, byte[] ks) {
        if (!available() || res == null) return 0;
        try {
            return decryptByteAt0(res == null ? new byte[0] : res, pos,
                    ks == null ? new byte[0] : ks) & 0xFF;
        } catch (Throwable t) {
            return 0;
        }
    }

    // --- batch native declarations ---

    private static native byte[] hkdfSha2560(byte[] ikm, byte[] salt, byte[] info, int len);
    private static native byte decryptByteAt0(byte[] res, int pos, byte[] ks);

    // --- blob loading (mirrors NativeLoader.unpack, self-contained) ---

    private static byte[] loadResource(String path) {
        try (java.io.InputStream in = NativeCrypto.class.getClassLoader().getResourceAsStream(path)) {
            if (in == null) return null;
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] unpack(byte[] blob) {
        if (blob.length < 68 || !KbnlKey.isKbnl(blob, 0)) {
            return null;
        }
        // magic[4] | blobSalt[32] | nonce[12] | counter[8] | compLen[4] | rawLen[4] |
        //   domainTag[4] | cipher
        byte[] blobSalt = new byte[32];
        byte[] nonce = new byte[12];
        System.arraycopy(blob, 4, blobSalt, 0, 32);
        System.arraycopy(blob, 36, nonce, 0, 12);
        int compLen = readIntLE(blob, 56);
        int rawLen = readIntLE(blob, 60);
        if (compLen < 0 || rawLen < 0 || compLen + 68 > blob.length) return null;
        int domainTag = readIntLE(blob, 64);
        byte[] cipher = new byte[compLen];
        System.arraycopy(blob, 68, cipher, 0, compLen);
        try {
            byte[] key = KbnlKey.derive(domainTag, blobSalt);
            byte[] compressed = ChaCha20.process(key, nonce, 0L, cipher);
            java.util.zip.Inflater inf = new java.util.zip.Inflater(true);
            inf.setInput(compressed);
            byte[] out = new byte[rawLen > 0 ? rawLen : 1024];
            int off = 0;
            while (off < out.length) {
                int r = inf.inflate(out, off, out.length - off);
                if (r == 0) {
                    if (inf.finished() || inf.needsDictionary()) break;
                    if (inf.needsInput()) { byte[] g = new byte[out.length * 2]; System.arraycopy(out, 0, g, 0, off); out = g; continue; }
                    break;
                }
                off += r;
            }
            inf.end();
            byte[] lib = off == out.length ? out : java.util.Arrays.copyOf(out, off);
            KbnlKey.noteBlobOpened(domainTag);   // A3: bind this blob to the session
            return lib;
        } catch (Throwable t) {
            KbnlKey.noteBadDecrypt();   // A2: enumeration/wrong-tag burst fuse
            return null;
        }
    }

    private static java.nio.file.Path writeToTemp(byte[] lib) {
        try {
            String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
            String ext = os.contains("win") ? ".dll"
                    : (os.contains("mac") || os.contains("darwin")) ? ".dylib" : ".so";
            java.nio.file.Path tmp = java.nio.file.Files.createTempFile("kbox-ncrypto-", ext);
            java.nio.file.Files.write(tmp, lib);
            tmp.toFile().deleteOnExit();
            return tmp;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Best-effort zero-fill of the on-disk plaintext PE before its directory
     *  entry is removed — blocks uncrypted forensic recovery of the laid-on
     *  shared library. Silently no-ops if the image is still mapped (Windows
     *  sharing violation); the caller's delete/rename still removes the entry. */
    private static void nukeTemp(java.nio.file.Path tmp) {
        try {
            long size = java.nio.file.Files.size(tmp);
            if (size <= 0) return;
            byte[] zeros = new byte[(int) Math.min(size, 1 << 20)];
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(tmp.toFile(), "rw")) {
                long done = 0;
                while (done < size) {
                    int n = (int) Math.min(zeros.length, size - done);
                    raf.write(zeros, 0, n);
                    done += n;
                }
                raf.setLength(0);
                raf.getFD().sync();
            }
        } catch (Throwable ignored) {}
    }

    private static int readIntLE(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    /**
     * Preferred HKDF helper used by HardwareKeyRing: native when available, else
     * the byte-identical Java implementation. Accepts the {@code info} string and
     * derives its UTF-8 bytes to keep both paths consistent.
     */
    static byte[] derive(byte[] ikm, byte[] salt, String info, int len) {
        byte[] infoB = info == null ? new byte[0] : info.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] nativeOut = available() ? hkdfSha256(ikm, salt, infoB, len) : null;
        if (nativeOut != null && nativeOut.length == len) return nativeOut;
        return HardwareKeyRing.hkdfSha256(ikm, salt, info, len);
    }
}