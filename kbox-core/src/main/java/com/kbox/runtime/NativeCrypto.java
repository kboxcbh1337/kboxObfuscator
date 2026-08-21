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

    private static final byte[] MAGIC = {'K', 'B', 'N', 'L'};

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
            if (blob == null) { if (dbg()) System.err.println("[NATIVECRYPTO] blob not found"); return; }
            byte[] lib = unpack(blob);
            if (lib == null || lib.length == 0) { if (dbg()) System.err.println("[NATIVECRYPTO] unpack failed blob=" + (blob==null?-1:blob.length)); return; }
            java.nio.file.Path tmp = writeToTemp(lib);
            if (tmp == null) { if (dbg()) System.err.println("[NATIVECRYPTO] temp write failed"); return; }
            if (dbg()) System.err.println("[NATIVECRYPTO] loading " + tmp + " (" + lib.length + "B)");
            System.load(tmp.toAbsolutePath().toString());
            // If binding failed (wrong arch / partial load), the JVM would have
            // thrown UnsatisfiedLinkError. Probe availability with a trivial call.
            if (probe()) available = true;
        } catch (Throwable t) {
            if (System.getProperty("kbox.native.dbg") != null)
                System.err.println("[NATIVECRYPTO] load failed: " + t);
            available = false;
        }
    }

    private static boolean dbg() {
        return System.getProperty("kbox.native.dbg") != null;
    }

    /** Trivial self-check: HKDF of a known vector must be non-trivial. */
    private static boolean probe() {
        try {
            byte[] r = hkdfSha2560(new byte[]{1, 2, 3}, new byte[1], new byte[0], 16);
            if (System.getProperty("kbox.native.dbg") != null)
                System.err.println("[NATIVECRYPTO] probe returned len=" + (r == null ? -1 : r.length));
            return r != null && r.length == 16;
        } catch (Throwable t) {
            if (System.getProperty("kbox.native.dbg") != null) {
                System.err.println("[NATIVECRYPTO] probe native threw: " + t);
                t.printStackTrace();
            }
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
        if (blob.length < 64 || blob[0] != MAGIC[0] || blob[1] != MAGIC[1]
                || blob[2] != MAGIC[2] || blob[3] != MAGIC[3]) {
            return null;
        }
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        System.arraycopy(blob, 4, key, 0, 32);
        System.arraycopy(blob, 36, nonce, 0, 12);
        int compLen = readIntLE(blob, 56);
        int rawLen = readIntLE(blob, 60);
        if (compLen < 0 || rawLen < 0 || compLen + 64 > blob.length) return null;
        byte[] cipher = new byte[compLen];
        System.arraycopy(blob, 64, cipher, 0, compLen);
        try {
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
            return off == out.length ? out : java.util.Arrays.copyOf(out, off);
        } catch (Throwable t) {
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