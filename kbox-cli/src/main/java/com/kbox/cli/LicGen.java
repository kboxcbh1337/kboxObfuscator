package com.kbox.cli;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Offline license publisher tool — runs on the PUBLISHER machine only and is
 * <em>never</em> distributed in the protected jar (its private key must never
 * leave the publisher).
 *
 * <pre>
 *   java -cp kbox-protector.jar com.kbox.cli.LicGen gen  &lt;baseName&gt;
 *        -> writes &lt;baseName&gt;.pub.der and &lt;baseName&gt;.priv.der   (+ prints pub hex)
 *
 *   java -cp kbox-protector.jar com.kbox.cli.LicGen sign &lt;priv.der&gt; &lt;subject&gt; &lt;days&gt; &lt;features&gt; [&lt;deviceFpHex&gt;] &lt;out.lic&gt; [&lt;appSecretHex&gt;]
 *        - days        : validity window from now
 *        - features    : int feature bitmask
 *        - deviceFpHex : bind to a machine fingerprint (hex of HardwareKeyRing.fingerprint());
 *                        omit for a generic (device-unbound) short-term license
 *        - appSecretHex: 64-hex app secret to embed. When distributing MANY licenses for
 *                        one jar you <b>must</b> reuse the same secret that was baked into
 *                        the build config as `licAppSecret` (omitting it generates a fresh
 *                        random secret only correct for a single ad-hoc license).
 * </pre>
 *
 * <p><b>Encrypted .lic format (v0x02).</b> The signed payload is not stored as
 * readable bytes: it is AES-256-GCM encrypted with a key derived from the
 * published public key, so the file is an opaque binary blob — no ASCII
 * subject/expiry/features survive, and it is not a trivial "license" suffix.
 * The Ed25519 signature covers the encrypted bytes, so tampering fails both the
 * signature and the GCM authenticator.
 *
 * <pre>
 *   [0..1]   MAGIC {0x5A, 0x02}
 *   [2..13]  12-byte GCM IV
 *   [14..15] uint16 BE plaintext length
 *   [16..]   ciphertext (== plaintext length bytes)
 *   [..+16]  16-byte GCM tag
 *   [sig...] 64-byte Ed25519 signature over the bytes above
 * </pre>
 *
 * <p>The publisher also supplies {@code licPublicKey = &lt;pub.der hex&gt;} in the
 * protection config so the packager embeds (masked) the same public key into
 * the jar and onboards the license verification &amp; app-key gating.
 */
public final class LicGen {

    private static final byte[] MAGIC = {0x5A, 0x02}; // encrypted .lic version
    private static final int SIG_LEN = 64; // Ed25519
    private static final int IV_LEN = 12;
    private static final int GCM_TAG = 16;

    private LicGen() {}

    public static void main(String[] a) throws Exception {
        if (a.length < 1) { usage(); return; }
        switch (a[0]) {
            case "gen":
                if (a.length < 2) { usage(); return; }
                gen(a[1]);
                break;
            case "sign":
                sign(a);
                break;
            case "pubhex":
                System.out.println(hex(Files.readAllBytes(Paths.get(a[1]))));
                break;
            default:
                usage();
        }
    }

    private static void gen(String base) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();
        Files.write(Paths.get(base + ".pub.der"), kp.getPublic().getEncoded());
        Files.write(Paths.get(base + ".priv.der"), kp.getPrivate().getEncoded());
        System.out.println("wrote " + base + ".pub.der  (" + kp.getPublic().getEncoded().length + "B)");
        System.out.println("wrote " + base + ".priv.der");
        System.out.println("PUBLIC KEY HEX = " + hex(kp.getPublic().getEncoded()));
    }

    private static void sign(String[] a) throws Exception {
        // priv.der  subject  days  features  [devFpHex]  out.lic  [appSecretHex]
        if (a.length < 6) { usage(); return; }
        String privPath = a[1];
        String subject  = a[2];
        long days       = Long.parseLong(a[3]);
        int  features   = Integer.parseInt(a[4]);
        String devFp = null;
        String out;
        String appSecHex = null;
        if (a.length >= 7) { devFp = a[5]; out = a[6]; if (a.length >= 8) appSecHex = a[7]; }
        else { out = a[5]; if (a.length >= 7) appSecHex = a[6]; }

        byte[] priv = Files.readAllBytes(Paths.get(privPath));
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(priv));

        long now = System.currentTimeMillis();
        long notAfter = now + days * 86_400_000L;
        long nonce = System.nanoTime() ^ ((long) features << 32);

        // app secret: explicit override wins (needed for many licenses / one jar);
        // otherwise a fresh random one (printed for the build config).
        byte[] appSecret;
        if (appSecHex != null && !appSecHex.isEmpty()) {
            appSecret = hexToBytes(appSecHex);
        } else {
            appSecret = new byte[32];
            new SecureRandom().nextBytes(appSecret);
        }

        byte[] payload = buildPayload(subject, now, notAfter, features, devFp, nonce, appSecret);

        byte[] spki = tryReadPub(privPath);
        byte[] blob = buildBlob(pk, payload, spki);

        Files.write(Paths.get(out), blob);
        System.out.println("wrote " + out + " bytes=" + blob.length
                + " subject=" + subject + " expiry(ms)=" + notAfter
                + (devFp != null ? " bound=1" : " bound=0(generic)")
                + (appSecHex != null ? " secret=explicit" : " secret=random"));
        System.out.println("APP SECRET HEX (put in config 'licAppSecret=...') = " + hex(appSecret));
    }

    /** Signs {@code payload}. Encrypts it with AES-256-GCM when the public key is available. */
    static byte[] buildBlob(PrivateKey pk, byte[] payload, byte[] spki) throws Exception {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        head.write(MAGIC);
        byte[] iv = new byte[IV_LEN];
        new SecureRandom().nextBytes(iv);
        head.write(iv);

        if (spki != null && spki.length > 0) {
            byte[] key = sha256(spki);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG * 8, iv));
            byte[] ct = c.doFinal(payload); // ct includes the 16-byte tag

            head.write(new byte[]{(byte) ((payload.length >> 8) & 0xFF), (byte) (payload.length & 0xFF)});
            head.write(Arrays.copyOfRange(ct, 0, payload.length));           // ciphertext (== plen)
            head.write(Arrays.copyOfRange(ct, payload.length, ct.length));   // GCM tag
            byte[] signed = head.toByteArray();
            byte[] sig = ed25519Sign(pk, signed);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(signed);
            out.write(sig);
            return out.toByteArray();
        } else {
            // Fallback legacy plaintext form (no pubkey available).
            head.write(new byte[]{(byte) ((payload.length >> 8) & 0xFF), (byte) (payload.length & 0xFF)});
            head.write(payload);
            byte[] signed = head.toByteArray();
            byte[] sig = ed25519Sign(pk, signed);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(signed);
            out.write(sig);
            return out.toByteArray();
        }
    }

    /** Fixed layout via DataOutputStream (matches LicVerifier). */
    static byte[] buildPayload(String subject, long iss, long notAfter, int feat,
                               String devFp, long nonce, byte[] appSecret) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(b);
        d.writeUTF(subject);
        d.writeLong(iss);
        d.writeLong(notAfter);
        d.writeInt(feat);
        if (devFp == null || devFp.isEmpty()) {
            d.writeByte(0);
        } else {
            d.writeByte(1);
            byte[] h = devFp.getBytes(StandardCharsets.ISO_8859_1);
            d.writeShort(h.length);
            d.write(h);
        }
        d.writeLong(nonce);
        d.write(appSecret, 0, 32);
        d.flush();
        return b.toByteArray();
    }

    private static byte[] ed25519Sign(PrivateKey pk, byte[] data) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(pk);
        s.update(data);
        return s.sign();
    }

    /** Reads the matching {@code <base>.pub.der} for {@code privPath}; null if absent. */
    static byte[] tryReadPub(String privPath) {
        String base = privPath;
        if (base.endsWith(".priv.der")) base = base.substring(0, base.length() - ".priv.der".length());
        else if (base.endsWith(".priv")) base = base.substring(0, base.length() - ".priv".length());
        try {
            return Files.readAllBytes(Paths.get(base + ".pub.der"));
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] sha256(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(in);
    }

    static byte[] hexToBytes(String h) {
        int n = h.length() / 2;
        byte[] r = new byte[n];
        for (int i = 0; i < n; i++) r[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        return r;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private static void usage() {
        System.out.println("LicGen (publisher-only)");
        System.out.println("  gen  <base>                       # Ed25519 -> base.pub.der + base.priv.der, print pub hex");
        System.out.println("  sign <priv.der> <subject> <days> <features> [<devFpHex>] <out.lic> [<appSecretHex>]");
    }
}