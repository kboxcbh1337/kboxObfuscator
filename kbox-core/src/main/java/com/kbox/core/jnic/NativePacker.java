package com.kbox.core.jnic;

import com.kbox.core.log.KBoxLog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Compresses and encrypts a compiled native library (.{code dll}/.{code so}/
 * .{code dylib}) so the protected jar contains no plaintext native code.
 *
 * <p>Build-time pipeline:
 * <ol>
 *   <li><b>LZ77/DEFLATE compression</b> ({@link Deflater} with
 *       {@link Deflater#BEST_COMPRESSION}). This achieves ~50-65% size reduction
 *       on typical JNI libraries (comparable to LZMA2 on small inputs; LZMA2 wins
 *       more on larger inputs but requires a third-party decoder in the runtime).
 *       The compression layer is isolated behind {@link #compress}/{@link #decompress}
 *       so a future LZMA2 implementation can be dropped in without touching
 *       callers.</li>
 *   <li><b>ChaCha20 keystream encryption</b> with a fresh random 256-bit key and
 *       96-bit nonce. The native code is never stored in plaintext.</li>
 *   <li>A 60-byte header is prepended:
 *       <pre>
 *         magic     4B  "KBNL" (KBox Native Library)
 *         key      32B  ChaCha20 key
 *         nonce    12B  ChaCha20 nonce
 *         counter   8B  initial counter (always 0)
 *         compLen   4B  compressed length (post-encryption = ciphertext length)
 *         rawLen    4B  uncompressed length (for Inflater allocation)
 *       </pre>
 *       The key/nonce are embedded in the blob itself — the security here is not
 *       key secrecy (the blob is self-contained) but the fact that the native
 *       code is not directly extractable by static analysis tools that don't run
 *       the KBox {@link com.kbox.runtime.NativeLoader}. An attacker must
 *       reverse-engineer the format and re-implement ChaCha20 + Inflater.</li>
 * </ol>
 *
 * <p>The resulting blob is written to {@code META-INF/kbox/native.bin} inside
 * the protected jar and unpacked to a temp file at runtime by
 * {@link com.kbox.runtime.NativeLoader}.
 */
public final class NativePacker {

    private static final String TAG = "jnic-pack";
    private static final byte[] MAGIC = {'K', 'B', 'N', 'L'};

    private NativePacker() {}

    /** Result of packing: the encrypted blob and its metadata. */
    public static final class Packed {
        public final byte[] blob;
        public final int rawLen;
        public final int compLen;
        public Packed(byte[] blob, int rawLen, int compLen) {
            this.blob = blob; this.rawLen = rawLen; this.compLen = compLen;
        }
    }

    /** Compresses + encrypts the native library at {@code libPath}. */
    public static Packed pack(Path libPath) throws IOException {
        byte[] raw = Files.readAllBytes(libPath);
        return pack(raw);
    }

    public static Packed pack(byte[] raw) {
        byte[] compressed = compress(raw);
        SecureRandom rng = new SecureRandom();
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        rng.nextBytes(key);
        rng.nextBytes(nonce);
        byte[] cipher = com.kbox.runtime.ChaCha20.process(key, nonce, 0L, compressed);
        // Header layout (64 bytes):
        //   magic[4] | key[32] | nonce[12] | counter[8] | compLen[4] | rawLen[4] | ciphertext
        byte[] blob = new byte[64 + cipher.length];
        int p = 0;
        blob[p++] = MAGIC[0]; blob[p++] = MAGIC[1]; blob[p++] = MAGIC[2]; blob[p++] = MAGIC[3];
        System.arraycopy(key, 0, blob, p, 32); p += 32;
        System.arraycopy(nonce, 0, blob, p, 12); p += 12;
        // counter (8 bytes, little-endian) = 0
        for (int i = 0; i < 8; i++) blob[p++] = 0;
        writeIntLE(blob, p, compressed.length); p += 4;
        writeIntLE(blob, p, raw.length); p += 4;
        System.arraycopy(cipher, 0, blob, p, cipher.length);
        KBoxLog.info(TAG, "Packed native lib: raw=" + raw.length
                + " compressed=" + compressed.length + " (ratio "
                + String.format("%.0f%%", 100.0 * compressed.length / Math.max(1, raw.length))
                + ") encrypted=" + blob.length);
        return new Packed(blob, raw.length, compressed.length);
    }

    /** Compresses with DEFLATE best compression (build-time). */
    public static byte[] compress(byte[] data) {
        Deflater d = new Deflater(Deflater.BEST_COMPRESSION, true);
        d.setInput(data);
        d.finish();
        byte[] buf = new byte[8192];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(data.length / 2);
        int n;
        while ((n = d.deflate(buf)) > 0) out.write(buf, 0, n);
        d.end();
        return out.toByteArray();
    }

    /** Decompresses (runtime-side helper; the runtime uses {@link Inflater} directly). */
    public static byte[] decompress(byte[] data, int rawLen) throws Exception {
        Inflater inf = new Inflater(true);
        inf.setInput(data);
        byte[] out = new byte[rawLen];
        int off = 0;
        while (off < rawLen) {
            int n = inf.inflate(out, off, rawLen - off);
            if (n == 0) {
                if (inf.finished() || inf.needsDictionary()) break;
                throw new IOException("NativePacker: inflate stalled");
            }
            off += n;
        }
        inf.end();
        if (off != rawLen) {
            byte[] trimmed = new byte[off];
            System.arraycopy(out, 0, trimmed, 0, off);
            return trimmed;
        }
        return out;
    }

    private static void writeIntLE(byte[] b, int off, int v) {
        b[off]     = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }
}
