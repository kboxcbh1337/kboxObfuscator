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
 *   <li>A 68-byte header is prepended:
 *       <pre>
 *         magic      4B  "KBNL" (KBox Native Library)
 *         blobSalt  32B  per-blob random salt (mixed into the derived key)
 *         nonce     12B  ChaCha20 nonce
 *         counter    8B  initial counter (always 0)
 *         compLen    4B  compressed length (post-encryption = ciphertext length)
 *         rawLen     4B  uncompressed length (for Inflater allocation)
 *         domainTag  4B  per-build random domain tag (A1 de-staticization)
 *       </pre>
 *       The ChaCha20 key is never embedded in the blob — it is derived at run
 *       time from the blobSalt + the per-build random domainTag + hardware factor
 *       ({@link com.kbox.runtime.KbnlKey}). An attacker must reverse-engineer
 *       the derivation and re-implement ChaCha20 + Inflater, and the domain is
 *       not a static enumerable constant shared across builds.</li>
 * </ol>
 *
 * <p>The resulting blob is written to {@code META-INF/kbox/native.bin} inside
 * the protected jar and unpacked to a temp file at runtime by
 * {@link com.kbox.runtime.NativeLoader}.
 */
public final class NativePacker {

    private static final String TAG = "jnic-pack";

    private NativePacker() {}

    /** Result of packing: the encrypted blob and its metadata. */
    public static final class Packed {
        public final byte[] blob;
        public final int rawLen;
        public final int compLen;
        /** {@code true} 表示 KBNL 打包前已对底层原生库做过 kboXShield PE 加壳
         *  （含函数级虚拟化/指令变异/控制流平坦化）——即「KBNL 外层容器 + 内层壳/VM」两层。 */
        public final boolean shielded;
        public Packed(byte[] blob, int rawLen, int compLen) {
            this(blob, rawLen, compLen, false);
        }
        public Packed(byte[] blob, int rawLen, int compLen, boolean shielded) {
            this.blob = blob; this.rawLen = rawLen; this.compLen = compLen;
            this.shielded = shielded;
        }
    }

    /** 加壳临时文件名后缀（ShieldPacker 按内容解析 PE，与后缀无关）。 */
    private static final String SHIELD_EXT = ".dll";

    /**
     * 对已编译的原生库做 kboXShield <b>完整加壳</b>：全节 ChaCha20 加密 + 合成导入表 +
     * 函数级虚拟化（x64 按 .pdata 逐函数，入口 E9 改写）+ 指令变异 + 控制流平坦化（双族 VM）。
     *
     * <p>运行期防御位（{@code defFlags}）置 0：这些库由 JVM 进程内加载，开启 PEB/时序/VM
     * 自检在宿主进程内易误判，也与杀软实时防护冲突；虚拟化/变异/平坦化照常全开。</p>
     *
     * @return 加壳后的 PE 字节；输入非 x64 PE（如 ELF/Mach-O，或壳自身拒绝）时返回
     *         {@code null}，由调用方降级为直接 KBNL。
     */
    public static byte[] shield(byte[] lib, Path workDir, String tag) {
        Path in = null;
        Path out = null;
        try {
            Files.createDirectories(workDir);
            in = workDir.resolve("kbox-shield-" + tag + "-in" + SHIELD_EXT);
            out = workDir.resolve("kbox-shield-" + tag + "-out" + SHIELD_EXT);
            Files.write(in, lib);
            com.kbox.core.shield.ShieldOptions opts = new com.kbox.core.shield.ShieldOptions();
            opts.defFlags = 0;
            opts.defPolicy = 0;
            opts.virtualizeFunctions = true;
            opts.irMutation = 2;
            opts.cfgFlatten = true;
            StringBuilder log = new StringBuilder();
            if (!com.kbox.core.shield.ShieldPacker.pack(in.toString(), out.toString(), opts, log)) {
                KBoxLog.info(TAG, "shield(" + tag + ") skipped (not a shieldable PE): " + oneLine(log));
                return null;
            }
            byte[] shielded = Files.readAllBytes(out);
            KBoxLog.info(TAG, "shield(" + tag + "): " + lib.length + " -> " + shielded.length
                    + " bytes (PE 壳 + 函数级虚拟化/变异/平坦化)");
            return shielded;
        } catch (Throwable t) {
            KBoxLog.info(TAG, "shield(" + tag + ") skipped: " + t);
            return null;
        } finally {
            if (in != null) { try { Files.deleteIfExists(in); } catch (Exception ignored) {} }
            if (out != null) { try { Files.deleteIfExists(out); } catch (Exception ignored) {} }
        }
    }

    /** 单行化日志（壳的结构自检是多行文本）。 */
    private static String oneLine(StringBuilder sb) {
        if (sb == null) return "";
        String s = sb.toString().replace('\n', ' ').trim();
        return s.length() > 300 ? s.substring(0, 300) + "..." : s;
    }

    /**
     * 先在生成的 KBNL 容器<b>之前</b>做一层 kboXShield PE 壳，再 KBNL 打包。
     *
     * <p>顺序不可颠倒：KBNL 是自定义容器（遮蔽魔数 + salt + nonce + ChaCha20 密文），
     * 不是 PE，PE 壳必须作用在底层原生库上。加壳失败自动降级为直接 KBNL，绝不使构建失败。</p>
     */
    public static Packed packShielded(Path libPath, Path workDir, String tag) throws IOException {
        byte[] lib = Files.readAllBytes(libPath);
        byte[] shielded = shield(lib, workDir, tag);
        if (shielded == null) {
            return pack(lib);
        }
        Packed p = pack(shielded);
        return new Packed(p.blob, p.rawLen, p.compLen, true);
    }

    /** Compresses + encrypts the native library at {@code libPath}, deriving the
     *  container key from a fresh per-build random domain tag (A1 de-staticization). */
    public static Packed pack(Path libPath) throws IOException {
        return pack(Files.readAllBytes(libPath));
    }

    public static Packed pack(byte[] raw) {
        byte[] compressed = compress(raw);
        SecureRandom rng = new SecureRandom();
        byte[] blobSalt = new byte[32];
        byte[] nonce = new byte[12];
        rng.nextBytes(blobSalt);
        rng.nextBytes(nonce);
        // A1: the domain is no longer a static enumerable constant (0..3). Each
        // blob gets its own CSPRNG-drawn random tag, embedded below and read back
        // at run time, so build↔run agree and domain enumeration cannot transfer
        // across builds. Different blobs get different random tags, preserving
        // cross-blob dispersion.
        int domainTag = com.kbox.runtime.KbnlKey.newDomainTag();
        // Key is NOT stored in the blob; it is derived at run time from the
        // random blobSalt + tag + hardware factor (KbnlKey.derive). A static scan
        // of the jar cannot extract a clean key alongside the PE.
        byte[] key = com.kbox.runtime.KbnlKey.derive(domainTag, blobSalt);
        byte[] cipher = com.kbox.runtime.ChaCha20.process(key, nonce, 0L, compressed);
        // Header layout (68 bytes):
        //   magic[4] | blobSalt[32] | nonce[12] | counter[8] | compLen[4] |
        //   rawLen[4] | domainTag[4] | ciphertext
        byte[] blob = new byte[68 + cipher.length];
        int p = 0;
        // Masked magic (NOT the ASCII "KBNL") — see KbnlKey.isKbnl, so the header
        // bytes can't be fingerprint-grepped; readers use the same masked bytes.
        blob[p++] = com.kbox.runtime.KbnlKey.kbnlMagicByte(0);
        blob[p++] = com.kbox.runtime.KbnlKey.kbnlMagicByte(1);
        blob[p++] = com.kbox.runtime.KbnlKey.kbnlMagicByte(2);
        blob[p++] = com.kbox.runtime.KbnlKey.kbnlMagicByte(3);
        System.arraycopy(blobSalt, 0, blob, p, 32); p += 32;
        System.arraycopy(nonce, 0, blob, p, 12); p += 12;
        // counter (8 bytes, little-endian) = 0
        for (int i = 0; i < 8; i++) blob[p++] = 0;
        writeIntLE(blob, p, compressed.length); p += 4;
        writeIntLE(blob, p, raw.length); p += 4;
        writeIntLE(blob, p, domainTag); p += 4;
        System.arraycopy(cipher, 0, blob, p, cipher.length);
        KBoxLog.info(TAG, "Packed native lib: raw=" + raw.length
                + " compressed=" + compressed.length + " (ratio "
                + String.format("%.0f%%", 100.0 * compressed.length / Math.max(1, raw.length))
                + ") encrypted=" + blob.length + " domainTag=" + domainTag);
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
