package com.kbox.runtime;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * L0 / Zero-Vortex: {@code HardwareKeyRing}.
 *
 * <p>Derives 256-bit subkeys by HKDF-SHA256 from a single <b>portable</b>
 * seed (see {@link #PORTABLE_SEED}):
 *
 * <pre>
 *   classKey  -> encrypts on-disk / in-memory class bodies
 *   streamKey -> encrypts the VM instruction stream (VortexVM / VMP code)
 *   wmKey     -> encrypts the digital watermark slots
 * </pre>
 *
 * <p><b>Hardware binding removed (2026-09-05):</b> this class no longer
 * enumerates MAC / wmic / DMI / ioreg / boot-disk identity. The factor feed
 * is a fixed constant, so every key is identical on every host — a protected
 * jar runs on any machine, and the build (obfuscator) JVM and run (product)
 * JVM always agree on the same keys. Per-build randomized-seed injection is a
 * follow-up (the Packager would thread the seed through the blob contract);
 * the constant form guarantees build↔run agreement.
 *
 * <p>An additional {@link #ephemeralKey()} is derived from the portable seed
 * combined with a per-launch salt (startup time + random). It is intentionally
 * <em>not stable across runs</em>, so two launches of the same protected
 * application yield different in-memory cipher streams (defeats replay /
 * re-dump of a decrypted instruction window).
 *
 * <p>Design principles (matching the project's hard constraints):
 * <ul>
 *   <li><b>Silent degradation.</b> Every derivation is best-effort and never
 *       throws; the JVM always gets a deterministic 32-byte key.</li>
 *   <li><b>Deterministic across processes and hosts.</b> The portable feed is
 *       constant, so all {@code *Key()} calls agree in the protect JVM and the
 *       run JVM on any machine.</li>
 *   <li><b>No privileged API / subprocess dependency.</b> No wmic, ioreg or
 *       DMI sysfs reads — fast, flake-free and sandbox-friendly.</li>
 * </ul>
 */
public final class HardwareKeyRing {

    private HardwareKeyRing() {}

    private static final String HKDF_ALGO = "HmacSHA256";
    private static final String DIGEST    = "SHA-256";
    private static final int    KEY_LEN   = 32;

    // ------------------------------------------------------------------
    //  Public API
    // ------------------------------------------------------------------

    /** 256-bit key for class-body encryption (stable per machine). */
    public static byte[] classKey()   { return hkdf(stableMachineFeed(), "kbox:class",   KEY_LEN); }

    /** 256-bit key for VM instruction-stream encryption (stable per machine). */
    public static byte[] streamKey()  { return hkdf(feed(), "kbox:stream",  KEY_LEN); }

    /** 256-bit key for watermark slots (stable per machine). */
    public static byte[] wmKey()      { return hkdf(feed(), "kbox:wm",      KEY_LEN); }

    /**
     * 256-bit per-launch key. Derived from the stable machine feed plus a
     * per-JVM salt (startup nanos + OS-level entropy), so it differs between
     * runs while staying re-derivable inside a single process. Used to re-seed
     * the rolling decode window and to re-encrypt tables at interpreter
     * teardown, defeating cross-launch replay of a dumped window.
     */
    public static byte[] ephemeralKey() {
        // Mix the per-run native-sourced session epoch (KbnlKey.sessionEpoch) into
        // the feed: improves cross-process unpredictability of the session layer
        // beyond pure System.nanoTime(). SAFE because per-run by design; it must
        // never be folded into classKey/streamKey/vmpMaster/domainSeed (see the
        // blob-contract note in KbnlKey.sessionEpoch).
        byte[] eph = com.kbox.runtime.KbnlKey.sessionEpoch();
        return hkdf(feed(), "kbox:eph:" + Long.toHexString(nanosSalt()) + ":" + hex(eph), KEY_LEN);
    }

    /** 32-byte machine fingerprint = SHA-256 of the stable factor feed.
     *  Used by the license verifier for device-binding comparison.
     *  <p>Hardware binding removed (2026-09-05): the seed is portable, so the
     *  same key is produced on every host. A protected jar therefore runs on
     *  any machine, not just the build host. */
    public static byte[] fingerprint() {
        return sha256(stableMachineFeed());
    }

    // ------------------------------------------------------------------
    //  Portable seed (hardware binding removed)
    // ------------------------------------------------------------------
    // Originally the factor feed was built from machine hardware (MAC, wmic/DMI
    // serials, boot-disk identity). That bound every protected product to the
    // build host: blobs opened only on a machine whose hardware recomputed the
    // same feed. Since obfuscators run in the build JVM and products run in the
    // run JVM, the two MUST agree even though no portable seed is injected yet,
    // so the feed is now a FIXED portable constant — identical across processes,
    // threads and machines. Build-time randomized-seed injection (per-build
    // portability) is a follow-up (Packager must thread the seed through the
    // blob contract); the constant form keeps build↔run agreement guaranteed.
    private static final byte[] PORTABLE_SEED =
            uncoverSeed();

    // The portable seed is NOT stored as a readable string constant in the class
    // constant pool: an attacker reversing <clinit> would otherwise read the seed
    // bytes verbatim and trivially re-derive every blob key (route ① cost=low,
    // guaranteed same-host hit). Instead the bytes are split across two constant
    // pools XOR-masked against fixed key material and reassembled at first use, so
    // no contiguous seed string survives a decompile/constant-pool scan. Build↔run
    // are unaffected (the reassembly is deterministic in both JVMs).
    private static byte[] uncoverSeed() {
        // Masked split halves; XOR of the two halves reconstructs the seed bytes.
        byte[] a = {
                (byte)0x2B,(byte)0x7E,(byte)0x51,(byte)0x0A,(byte)0xC3,(byte)0x94,(byte)0x60,(byte)0x1D,
                (byte)0xE8,(byte)0x73,(byte)0x09,(byte)0xAC,(byte)0x45,(byte)0xEF,(byte)0x3A,(byte)0x18,
                (byte)0xB6,(byte)0xD2,(byte)0x9F,(byte)0x47,(byte)0x71,(byte)0xC5,(byte)0x36,(byte)0xE0,
                (byte)0x8D,(byte)0x5A,(byte)0xF4,(byte)0x20,(byte)0xB9,(byte)0x0C,(byte)0x67,(byte)0xDE,
                (byte)0x3B,(byte)0xF1,(byte)0x88,(byte)0x54,(byte)0x2C,(byte)0xD0,(byte)0xE4,(byte)0x9B,
                (byte)0x13,(byte)0xA7,(byte)0x70,(byte)0xCC,(byte)0x5F,(byte)0x06,(byte)0x92,(byte)0x39 };
        byte[] b = {
                (byte)0x42,(byte)0x5D,(byte)0x20,(byte)0x39,(byte)0xB2,(byte)0xF7,(byte)0x49,(byte)0x2C,
                (byte)0x9A,(byte)0x51,(byte)0x7C,(byte)0xCF,(byte)0x16,(byte)0x8E,(byte)0x0B,(byte)0x79,
                (byte)0xC7,(byte)0xF0,(byte)0xA6,(byte)0x36,(byte)0x4A,(byte)0xA4,(byte)0x07,(byte)0x9B,
                (byte)0xF8,(byte)0x6D,(byte)0x8B,(byte)0x51,(byte)0xC0,(byte)0x7F,(byte)0x16,(byte)0xA9,
                (byte)0x58,(byte)0xCA,(byte)0xE9,(byte)0x65,(byte)0x4D,(byte)0xB3,(byte)0x9D,(byte)0xE0,
                (byte)0x6A,(byte)0xC6,(byte)0x03,(byte)0xB5,(byte)0x3C,(byte)0x7B,(byte)0xA1,(byte)0x4A };
        byte[] s = new byte[a.length];
        for (int i = 0; i < a.length; i++) s[i] = (byte) (a[i] ^ b[i]);
        return s;
    }

    private static volatile byte[] _buildSeed = null;

    /** Inject a build-time random seed (called once by the pipeline before any
     *  packing). The SAME bytes are written into the product as
     *  {@code META-INF/kbox/seed.bin}, which the run JVM reads back, so build↔run
     *  agree on this seed and every build's seed is unique (route ①: a captured
     *  seed from one jar does not unlock a different jar). Null (unset) → fall
     *  back to {@link #uncoverSeed()} then the product resource. */
    public static void attachBuildSeed(byte[] seed) {
        if (seed == null || seed.length == 0) return;
        _buildSeed = seed.clone();
    }

    /** The build-injected seed (32 bytes), or null before attachBuildSeed / when
     *  this is not a build that ran the pipeline. The packager embeds these bytes
     *  into the product so the run JVM re-derives the same keys. */
    public static byte[] currentBuildSeed() {
        byte[] bs = _buildSeed;
        return bs == null ? null : bs.clone();
    }

    /** Current factor feed. Priority: build-injected seed > product resource →
     *  masked static fallback. Deterministic in both the build and the run JVM
     *  (both see the same effective seed), so blob build↔run agreement holds. */
    private static byte[] effectiveSeed() {
        byte[] bs = _buildSeed;
        if (bs != null) return bs;
        byte[] res = productSeed();
        if (res != null) return res;
        return uncoverSeed();
    }

    /** Reads {@code META-INF/kbox/seed.bin} (32 bytes) from the classpath — the
     *  per-build seed the packager embedded. Returns null when absent (e.g. the
     *  bare obfuscator itself, which is not a protected product). */
    private static byte[] productSeed() {
        try {
            java.io.InputStream in = HardwareKeyRing.class.getClassLoader()
                    .getResourceAsStream("META-INF/kbox/seed.bin");
            if (in == null) return null;
            try {
                byte[] b = in.readAllBytes();
                if (b != null && b.length == 32) return b;
                return null;
            } finally {
                try { in.close(); } catch (Exception ignored) {}
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Deterministic, subprocess-free, machine-INDEPENDENT factor feed. */
    private static byte[] stableMachineFeed() {
        return effectiveSeed();
    }

    // ------------------------------------------------------------------
    //  VMP method-key wrapping (hardware-bound master)
    // ------------------------------------------------------------------
    // A per-method random 32-byte key K encrypts the VM instruction stream. K is
    // NEVER stored bare; it is wrapped (AES-256-GCM) under a master key derived
    // from THIS machine's hardware feed. Only a host whose hardware computes the
    // same master can unwrap K; anywhere else the authenicated decrypt fails and
    // the interpreter silently falls back to a noise method. This replaces the old
    // bare long $vmpkey constant with a hardware-bound envelope.

    /** Fixed domain-separation salt; must be byte-identical on build & run JVMs.
     *  XOR-masked so no readable "KBox-VMP-KeyWrap-v1" string rests in the constant pool. */
    private static final byte[] VMP_SALT = xorLit(
            new byte[]{0x4B,0x42,0x6F,0x78,0x2D,0x56,0x4D,0x50,0x2D,0x4B,0x65,0x79,0x57,0x72,0x61,0x70,0x2D,0x76,0x31},
            new byte[]{0x1D,0x7C,0x19,0x08,0x57,0x06,0x39,0x5B});

    /** Portable master for VMP key wrapping (identical on every host).
     *  <p>Derived from the constant {@link #stableMachineFeed()} so the
     *  protect-time wrap and run-time unwrap — possibly seconds/minutes apart —
     *  always agree, on any machine. */
    public static byte[] vmpMaster() {
        return hkdfPreferred(sha256(stableMachineFeed()), VMP_SALT, "kbox.master", KEY_LEN);
    }

    /** AES-256-GCM wrap of {@code data} under {@code key32}. Output = IV||ciphertext||tag.
     *  A random 12-byte IV is used; a fresh ciphertext is produced each call. */
    public static byte[] aesGcmEncrypt(byte[] key32, byte[] data) {
        try {
            byte[] iv = new byte[12];
            new java.security.SecureRandom().nextBytes(iv);
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            c.init(javax.crypto.Cipher.ENCRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(key32, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(128, iv));
            byte[] ct = c.doFinal(data);
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return out;
        } catch (Throwable t) {
            return null;
        }
    }

    /** AES-256-GCM unwrap of a blob produced by {@link #aesGcmEncrypt}. Returns the
     *  plaintext, or {@code null} on any failure (wrong machine / tampered key). */
    public static byte[] aesGcmDecrypt(byte[] key32, byte[] blob) {
        try {
            if (blob == null || blob.length < 28) return null;
            byte[] iv = new byte[12];
            System.arraycopy(blob, 0, iv, 0, 12);
            byte[] ct = new byte[blob.length - 12];
            System.arraycopy(blob, 12, ct, 0, ct.length);
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            c.init(javax.crypto.Cipher.DECRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(key32, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(128, iv));
            return c.doFinal(ct);
        } catch (Throwable t) {
            return null;
        }
    }

    /** Public HKDF-SHA256 (RFC 5869 extract+expand) with explicit salt + info.
     *  Used to derive license-bound sub-keys (e.g. the session key). */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, String info, int len) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(HKDF_ALGO);
            byte[] prk;
            if (salt != null && salt.length > 0) {
                mac.init(new javax.crypto.spec.SecretKeySpec(ikm, HKDF_ALGO));
                mac.update(salt);
                prk = mac.doFinal(ikm);
            } else {
                prk = ikm;
            }
            mac.init(new javax.crypto.spec.SecretKeySpec(prk, HKDF_ALGO));
            byte[] infoB = toBytes(info);
            byte[] t = new byte[0];
            byte[] okm = new byte[len];
            int pos = 0, ctr = 1;
            while (pos < len) {
                mac.reset();
                mac.update(t);
                mac.update(infoB);
                mac.update((byte) ctr);
                t = mac.doFinal();
                int n = Math.min(t.length, len - pos);
                System.arraycopy(t, 0, okm, pos, n);
                pos += n;
                ctr++;
            }
            return okm;
        } catch (Throwable ignored) {
            byte[] k = new byte[len];
            java.util.Arrays.fill(k, (byte) 0x2A);
            return k;
        }
    }

    /** License-bound envelope key: HKDF(machineFeed, session, "lic:app.v1", 32).
     *  A bogus {@code session} (random key when the license is invalid) yields a
     *  different key from what the publisher signed against, so decryption of
     *  class/stream material produces noise instead of a clean boot. */
    public static byte[] appKey(byte[] session) {
        byte[] sess = session == null ? ephemeralKey() : session;
        return hkdfPreferred(feed(), sess, "lic:app.v1", KEY_LEN);
    }

    /**
     * Preferred HKDF path: native {@code NativeCrypto.hkdfSha256} when the native
     * lib is loaded, else the byte-identical Java {@link #hkdfSha256}. The native
     * and Java implementations are contractually byte-identical, so the protect
     * (build) JVM and the run JVM always agree regardless of which path each used.
     */
    private static byte[] hkdfPreferred(byte[] ikm, byte[] salt, String info, int len) {
        try {
            if (com.kbox.runtime.NativeCrypto.available()) {
                try {
                    byte[] infoB = info.getBytes(StandardCharsets.UTF_8);
                    byte[] out = com.kbox.runtime.NativeCrypto.hkdfSha256(ikm, salt, infoB, len);
                    if (out != null && out.length == len) return out;
                } catch (Throwable ignored) {
                    // native call failed -> fall through to Java
                }
            }
        } catch (Throwable ignored) {
            // NativeCrypto class absent (e.g. Brainfuck/guard loader that does not
            // ship the native crypto runtime): the JVM throws NoClassDefFoundError when
            // resolving NativeCrypto.available(). The Java HKDF is byte-identical, so
            // fall back silently — the master key must agree build->run regardless of
            // whether the native lib is present.
        }
        return hkdfSha256(ikm, salt, info, len);
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(DIGEST);
            return md.digest(data);
        } catch (Throwable ignored) {
            return new byte[KEY_LEN];
        }
    }

    // ------------------------------------------------------------------
    //  Stable machine feed
    // ------------------------------------------------------------------

    /**
     * Deterministic per-host byte feed (best effort, silent on failure).
     * Order is fixed; missing sources are simply skipped so the digest stays
     * stable on machines lacking a given source.
     * <p>Hardware binding removed: this returns the same portable seed as
     * {@link #stableMachineFeed()}. {@code streamKey}/{@code wmKey}/{@code
     * appKey} must agree between the build JVM and the run JVM, and now do so
     * on every host. */
    private static byte[] feed() {
        return effectiveSeed();
    }

    /** XOR {@code key} repeatedly over {@code data} (circular) and return the
     *  result. Used to unmask byte-literal secrets that would otherwise rest as
     *  readable strings in the constant pool. Deterministic and identical in
     *  both the build and the run JVM, so blob build↔run agreement is kept. */
    private static byte[] xorLit(byte[] data, byte[] key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return out;
    }

    // ------------------------------------------------------------------
    //  HKDF-SHA256 (RFC 5869 extract+expand)
    private static byte[] hkdf(byte[] ikm, String info, int length) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(HKDF_ALGO);
            mac.init(new javax.crypto.spec.SecretKeySpec(ikm, HKDF_ALGO));
            byte[] prk = mac.doFinal(); // extract
            mac.init(new javax.crypto.spec.SecretKeySpec(prk, HKDF_ALGO));
            byte[] infoBytes = toBytes(info);
            byte[] t = new byte[0];
            byte[] okm = new byte[length];
            int pos = 0, c = 1;
            while (pos < length) {
                mac.reset();
                mac.update(t);
                mac.update(infoBytes);
                mac.update((byte) c);
                t = mac.doFinal();
                int n = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, okm, pos, n);
                pos += n;
                c++;
            }
            return okm;
        } catch (Throwable ignored) {
            byte[] k = new byte[length];
            java.util.Arrays.fill(k, (byte) 0x2A);
            return k;
        }
    }

    /** Per-launch salt (startup nanos + a bit of OS entropy), stable within one JVM. */
    private static long nanosSalt() {
        // Cache so all ephemeralKey() calls in a process agree.
        if (salt == 0L) {
            long base = System.nanoTime();
            long ent = 0L;
            try { ent = java.lang.management.ManagementFactory.getRuntimeMXBean().getStartTime(); } catch (Throwable ignored) {}
            salt = base ^ (ent << 8) ^ (System.identityHashCode(new Object()) & 0xFFFFFFFFL);
        }
        return salt;
    }
    private static volatile long salt = 0L;

    private static byte[] toBytes(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }

    private static String hex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(Character.forDigit((x >>> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }
}