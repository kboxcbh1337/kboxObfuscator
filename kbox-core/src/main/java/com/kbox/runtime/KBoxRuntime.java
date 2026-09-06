package com.kbox.runtime;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime decryption stub injected by KBox into every protected jar. The
 * encrypted-string bytecode emitted by {@code StringEncryptor} calls
 * {@link #d} (strength 1, XOR) or {@link #a} (strength 2, AES).
 *
 * <p>This class is intentionally tiny and dependency-free so it survives any
 * later obfuscation pass and loads under a minimal classpath. It is injected
 * verbatim (never renamed) by the {@link com.kbox.core.packaging.Packager}.
 */
public final class KBoxRuntime {

    private KBoxRuntime() {}

    /** Strength-1 (rolling-XOR) decryptor. Layout: 4-byte key + payload. */
    public static String d(byte[] b) {
        if (TamperShield.isTampered()) return corrupt(b);
        int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        byte[] data = new byte[b.length - 4];
        for (int i = 0; i < data.length; i++) {
            int shift = (i * 7) % 32;
            int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
            data[i] = (byte) (b[i + 4] ^ (k & 0xFF));
        }
        // intern() preserves == semantics and string-switch hash tables.
        return new String(data, StandardCharsets.UTF_8).intern();
    }

    /**
     * Random-decryption variant E: position-dependent XOR with a different
     * shift schedule ({@code i * 3} instead of {@code i * 7}). The key bytes
     * are read from the first 4 bytes of the payload, identical to {@link #d}.
     * <p>An attacker must reverse-engineer every variant to recover all
     * strings — there is no single static decryption pattern.
     */
    public static String e(byte[] b) {
        if (TamperShield.isTampered()) return corrupt(b);
        int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        byte[] data = new byte[b.length - 4];
        for (int i = 0; i < data.length; i++) {
            int shift = (i * 3) % 32;
            int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
            data[i] = (byte) (b[i + 4] ^ (k & 0xFF));
        }
        return new String(data, StandardCharsets.UTF_8).intern();
    }

    /**
     * Random-decryption variant F: rotating XOR with a 5-position schedule
     * ({@code i % 5}). Different from {@link #d} and {@link #e}.
     */
    public static String f(byte[] b) {
        if (TamperShield.isTampered()) return corrupt(b);
        int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        byte[] data = new byte[b.length - 4];
        for (int i = 0; i < data.length; i++) {
            int shift = (i % 5) * 6;
            int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
            data[i] = (byte) (b[i + 4] ^ (k & 0xFF));
        }
        return new String(data, StandardCharsets.UTF_8).intern();
    }

    /**
     * Random-decryption variant G: XOR with a running counter mixed into the
     * key. Defeats pattern-based XOR key recovery.
     */
    public static String g(byte[] b) {
        if (TamperShield.isTampered()) return corrupt(b);
        int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        byte[] data = new byte[b.length - 4];
        int state = key;
        for (int i = 0; i < data.length; i++) {
            state = (state ^ (state << 13)) ^ (i * 0x9E3779B9);
            data[i] = (byte) (b[i + 4] ^ (state & 0xFF));
        }
        return new String(data, StandardCharsets.UTF_8).intern();
    }

    /**
     * Random-decryption variant H: XOR with a fibonacci-like key schedule.
     * Uses two running key states mixed via XOR and rotate.
     */
    public static String h(byte[] b) {
        if (TamperShield.isTampered()) return corrupt(b);
        int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        byte[] data = new byte[b.length - 4];
        int a = key, c = key ^ 0x61C88647;
        for (int i = 0; i < data.length; i++) {
            int next = a ^ c;
            a = c;
            c = next;
            data[i] = (byte) (b[i + 4] ^ (a & 0xFF));
        }
        return new String(data, StandardCharsets.UTF_8).intern();
    }

    /** Strength-2 (AES/CBC) decryptor. Layout: 4-byte key + 16-byte IV + ciphertext. */
    public static String a(byte[] b) {
        if (TamperShield.isTampered()) return corrypt(b);
        try {
            int key = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                    | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
            SecretKeySpec sk = deriveKey(key);
            byte[] iv = new byte[16];
            System.arraycopy(b, 4, iv, 0, 16);
            byte[] enc = new byte[b.length - 20];
            System.arraycopy(b, 20, enc, 0, enc.length);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
            return new String(c.doFinal(enc), StandardCharsets.UTF_8).intern();
        } catch (Exception e) {
            throw new RuntimeException("KBox AES decrypt failed", e);
        }
    }

    /**
     * When the anti-debug canary fires, the XOR decryptor returns a constant
     * garbage string instead of the plaintext, so an attacker watching the
     * decrypted output sees junk. Note: returns a non-interned string so
     * == comparisons also break, maximizing confusion.
     */
    private static String corrupt(byte[] b) {
        return new String(b, 4, Math.max(0, b.length - 4), StandardCharsets.UTF_8);
    }

    /** Variant for the AES path: corrupts the key bytes so decryption yields noise. */
    private static String corrypt(byte[] b) {
        byte[] noise = new byte[Math.max(0, b.length - 20)];
        for (int i = 0; i < noise.length; i++) noise[i] = (byte) (i & 0xFF);
        return new String(noise, StandardCharsets.UTF_8);
    }

    private static SecretKeySpec deriveKey(int key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(new byte[]{
                    (byte) (key >>> 24), (byte) (key >>> 16),
                    (byte) (key >>> 8), (byte) key
            });
            byte[] d = md.digest();
            return new SecretKeySpec(d, 0, 16, "AES");
        } catch (Exception e) {
            throw new RuntimeException("KBox key derivation failed", e);
        }
    }
}
