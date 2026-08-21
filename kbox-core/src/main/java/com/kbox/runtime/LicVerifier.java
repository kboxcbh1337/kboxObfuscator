package com.kbox.runtime;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime license verifier for the KBox offline (or online) licensing system.
 *
 * <p>Flow (mirrors {@code LicGen} on the publisher side):
 * <pre>
 *   publish(offline): Ed25519 keypair; .lic = MAGIC||payload||signature(64B)
 *   run(machine)    : LicVerifier.verify()
 *                      ① Ed25519 verify          (anti-forge)
 *                      ② hardware fingerprint    (anti-transfer)
 *                      ③ monotonic clock window  (anti-expire / anti-rewind)
 *                      ④ sessionKey derivation   (anti-patch skip)
 * </pre>
 *
 * <p>The publisher's public key is <em>not</em> shipped as raw X.509 bytes:
 * the packager writes it as a masked table {@code META-INF/kbox/lic.pub}
 * where {@code byte[i] = pub[i] XOR mask(i)}. {@link #publicKeyUnwrap()}
 * re-applies {@code mask(i) = (i*31+7)} at runtime, so a naive "find the
 * X.509 sequence then patch it" attack cannot locate the key bytes.
 *
 * <p><b>Anti-patch skip.</b> Do not gate licensing on a single boolean.
 * Call {@link #appKey()} and feed its output into the class / VM decryption;
 * a bogus (replaced) license yields a <em>different</em> {@code appKey} and
 * therefore garbage plaintext instead of a clean boot — there is no single
 * {@code valid} bit left to patch.
 *
 * <p>Requires Ed25519 (JDK 15+). On runtimes without Ed25519 the verifier
 * fails closed (invalid) rather than crashing. Everything else degrades
 * silently to {@code invalid}.
 */
public final class LicVerifier {

    private LicVerifier() {}

    private static final byte[] MAGIC = {0x5A};
    private static final String PUB_RES = "/META-INF/kbox/lic.pub";
    private static final int SIG_LEN = 64; // Ed25519 signature length
    private static final int IV_LEN = 12;  // AES-GCM IV
    private static final int GCM_TAG = 16; // AES-GCM tag

    private static final SecureRandom RNG = new SecureRandom();

    /** License state. */
    public static final class State {
        public boolean valid;
        public String subject = "";
        public long expiresAt;
        public int features;
    }

    private static final State STATE = new State();

    /** Per-license random app-secret (32B) extracted from a VALID license; null when invalid. */
    private static volatile byte[] appSecretValid;

    public static State state() { return STATE; }
    /** Convenience used by the pipeline / boot loader. */
    public static boolean isValid() { return STATE.valid; }

    /**
     * Returns the license-bound app secret that a VALID license carries (or a
     * random 32-byte value when invalid). Downstream class/VM decryption keys
     * must be a function of this value so there is no single {@code valid}
     * flag an attacker can patch: with a forged license the secret differs and
     * decryption yields noise.
     */
    public static byte[] appKey() {
        byte[] s = appSecretValid;
        if (s == null) { byte[] r = new byte[32]; RNG.nextBytes(r); return r; }
        return java.util.Arrays.copyOf(s, s.length);
    }

    /** Compatibility alias (no FP-derived session needed; the signed secret IS the session). */
    public static byte[] sessionKey() { return appKey(); }

    /** Verify the license once. Call at app boot; re-callable. */
    public static State verify() {
        reset();
        String path = System.getProperty("lic.path", "license.lic");
        try {
            Path lic = locate(path);
            if (lic == null) return fail("no lic file");
            byte[] blob = Files.readAllBytes(lic);
            if (blob.length < 2 + SIG_LEN || (blob[0] & 0xFF) != (MAGIC[0] & 0xFF)) return fail("bad header");
            int ver = blob[1] & 0xFF; // 1=plaintext legacy, 2=encrypted
            if (ver != 1 && ver != 2) return fail("bad version");

            byte[] sig    = java.util.Arrays.copyOfRange(blob, blob.length - SIG_LEN, blob.length);
            byte[] signed = java.util.Arrays.copyOfRange(blob, 0, blob.length - SIG_LEN);

            // ① signature verify (anti-forge) — over the on-disk bytes, so the
            //    encrypted payload cannot be swapped or its ciphertext edited.
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(publicKeyUnwrap());
            s.update(signed);
            if (!s.verify(sig)) return fail("signature invalid");

            // Decrypt / decode the payload region.
            byte[] payload;
            if (ver == 1) {
                payload = java.util.Arrays.copyOfRange(signed, 2, signed.length);
            } else {
                payload = decryptV2(signed);
                if (payload == null) return fail("payload decrypt");
            }

            // parse payload: subject(UTF), iss, notAfter, feat, bound, [devHex], nonce
            DataInputStream di = new DataInputStream(new ByteArrayInputStream(payload));
            String subject = di.readUTF();
            long iss = di.readLong();
            long notAfter = di.readLong();
            int feat = di.readInt();
            int bound = di.readByte();
            String devFp = null;
            if (bound == 1) {
                int n = di.readUnsignedShort();
                byte[] h = new byte[n];
                di.readFully(h);
                devFp = new String(h, StandardCharsets.ISO_8859_1);
            }
            di.readLong(); // nonce (replay marker; window check below is primary)
            // payload tail: 32-byte per-license app secret (signed inside the payload)
            byte[] secret = new byte[32];
            di.readFully(secret);

            // ② hardware bind (anti-transfer)
            if (bound == 1 && devFp != null) {
                byte[] cur = HardwareKeyRing.fingerprint();
                if (!constantTimeEq(hex(cur), devFp)) return fail("hardware mismatch");
            }

            // ③ time window + anti-rewind
            long now = monotonicNow();
            if (now < iss) return fail("clock before issue");
            if (now > notAfter) return fail("expired");

            STATE.valid = true;
            STATE.subject = subject;
            STATE.expiresAt = notAfter;
            STATE.features = feat;
            appSecretValid = secret;
            return STATE;
        } catch (Throwable t) {
            return fail("verify exception");
        }
    }

    /**
     * Decrypt the v0x02 region: {@code MAGIC||iv||plen(BE16)||ciphertext(plen)||tag},
     * keyed by {@code SHA-256(spki)}. GCM authenticates the ciphertext.
     */
    private static byte[] decryptV2(byte[] signed) throws Exception {
        int hdr = 2 + IV_LEN + 2; // magic(1)+ver(1)+iv(12)+plen(2)
        if (signed.length < hdr + GCM_TAG) return null;
        byte[] iv = java.util.Arrays.copyOfRange(signed, 2, 2 + IV_LEN);
        int plen = ((signed[2 + IV_LEN] & 0xFF) << 8) | (signed[2 + IV_LEN + 1] & 0xFF);
        if (plen < 0 || signed.length != hdr + plen + GCM_TAG) return null;
        byte[] ct = java.util.Arrays.copyOfRange(signed, hdr, hdr + plen);
        byte[] tag = java.util.Arrays.copyOfRange(signed, hdr + plen, signed.length);
        byte[] full = new byte[ct.length + tag.length];
        System.arraycopy(ct, 0, full, 0, ct.length);
        System.arraycopy(tag, 0, full, ct.length, tag.length);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sha256PublicKey(), "AES"),
                new GCMParameterSpec(GCM_TAG * 8, iv));
        return c.doFinal(full); // throws AEADBadTagException on tamper
    }

    private static byte[] sha256PublicKey() throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(spkiRaw());
    }

    // ------------------------------------------------------------------
    //  White-box public key
    // ------------------------------------------------------------------

    /** Reads {@code META-INF/kbox/lic.pub} (masked) and un-masks it to the raw SPKI bytes. */
    private static byte[] spkiRaw() throws Exception {
        byte[] masked;
        try (java.io.InputStream in = LicVerifier.class.getResourceAsStream(PUB_RES)) {
            if (in == null) throw new IllegalStateException("lic.pub missing");
            masked = readAll(in);
        }
        byte[] pub = new byte[masked.length];
        for (int i = 0; i < masked.length; i++) {
            pub[i] = (byte) (masked[i] ^ mask(i));
        }
        return pub;
    }

    private static PublicKey publicKeyUnwrap() throws Exception {
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spkiRaw()));
    }

    /** Build-side/run-side shared mask: {@code (i*31+7) & 0xFF}. */
    private static int mask(int i) { return (byte) ((i * 31 + 7) & 0xFF) & 0xFF; }

    /** Mask a raw public key to {@code META-INF/kbox/lic.pub} (used by the packager). */
    public static void writeMaskedPublicKey(java.io.OutputStream out, byte[] spki) throws Exception {
        for (int i = 0; i < spki.length; i++) {
            out.write(((spki[i] & 0xFF) ^ mask(i)) & 0xFF);
        }
        out.flush();
    }

    // ------------------------------------------------------------------
    //  Anti-rewind monotonic clock (encrypted last-seen on disk)
    // ------------------------------------------------------------------

    private static synchronized long monotonicNow() {
        long cur = System.currentTimeMillis();
        Path f = Paths.get(System.getProperty("user.home", "."), ".kbox-lic", "last");
        long last = -1;
        try {
            if (Files.exists(f)) {
                byte[] b = Files.readAllBytes(f);
                byte[] k = HardwareKeyRing.streamKey();
                byte[] d = new byte[b.length];
                for (int i = 0; i < b.length; i++) d[i] = (byte) (b[i] ^ k[i % k.length]);
                last = ByteBuffer.wrap(d).getLong();
            }
        } catch (Throwable ignored) {
        }
        if (last > cur + 120_000L) return Long.MIN_VALUE; // clock rolled back > 2 min -> "expired"
        long cap = Math.max(cur, last);
        try {
            byte[] k = HardwareKeyRing.streamKey();
            Files.createDirectories(f.getParent());
            byte[] st = new byte[8];
            ByteBuffer.wrap(st).putLong(cap);
            byte[] out = new byte[8];
            for (int i = 0; i < 8; i++) out[i] = (byte) (st[i] ^ k[i % k.length]);
            Files.write(f, out);
        } catch (Throwable ignored) {
        }
        return cap;
    }

    /**
     * Locate a license file: {@code -Dlic.path} wins; otherwise {@code license.lic}
     * in the working dir, else next to the running jar, else not found.
     */
    private static Path locate(String path) {
        String override = System.getProperty("lic.path");
        if (override != null && !override.isEmpty()) {
            Path p = Paths.get(override);
            if (Files.isRegularFile(p)) return p;
        }
        Path cwd = Paths.get(path);
        if (Files.isRegularFile(cwd)) return cwd;
        try {
            java.net.URI u = LicVerifier.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI();
            Path dir = Paths.get(u).getParent();
            if (dir != null) {
                Path near = dir.resolve(path);
                if (Files.isRegularFile(near)) return near;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    // ------------------------------------------------------------------
    //  helpers
    // ------------------------------------------------------------------

    private static void reset() {
        STATE.valid = false;
        STATE.subject = "";
        STATE.expiresAt = 0;
        STATE.features = 0;
        appSecretValid = null;
    }

    private static State fail(String why) { reset(); return STATE; }

    private static boolean constantTimeEq(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.ISO_8859_1);
        byte[] y = b.getBytes(StandardCharsets.ISO_8859_1);
        int diff = x.length ^ y.length;
        int n = Math.max(x.length, y.length);
        for (int i = 0; i < n; i++) {
            int xv = i < x.length ? (x[i] & 0xFF) : 0;
            int yv = i < y.length ? (y[i] & 0xFF) : 0;
            diff |= xv ^ yv;
        }
        return diff == 0;
    }

    private static byte[] readAll(java.io.InputStream in) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int r;
        while ((r = in.read(buf)) > 0) bo.write(buf, 0, r);
        return bo.toByteArray();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }
}