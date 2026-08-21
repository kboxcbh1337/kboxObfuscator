package com.kbox.runtime;

import java.net.NetworkInterface;
import java.security.MessageDigest;
import java.util.Enumeration;

/**
 * Hardware fingerprint generator. Derives a machine-specific key from
 * CPU core count, MAC address, and OS-level identifiers using HKDF-SHA256.
 *
 * <p>Used by class encryption to bind the decryption key to the build
 * machine, so the encrypted classes cannot be decrypted on a different
 * machine without the hardware fingerprint.
 *
 * <p>The fingerprint is intentionally lenient: if any individual source
 * fails (e.g. no network interface), the remaining sources still produce
 * a stable fingerprint. The fingerprint is deterministic per-machine.
 */
public final class HardwareFingerprint {

    private HardwareFingerprint() {}

    /**
     * Generate a 32-byte hardware fingerprint.
     * Sources (all best-effort, any failure is silently skipped):
     * <ul>
     *   <li>OS name + architecture + version</li>
     *   <li>Available processors (CPU core count)</li>
     *   <li>First MAC address</li>
     *   <li>User name (OS account)</li>
     * </ul>
     */
    public static byte[] derive() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // OS identifiers
            md.update(getBytes(System.getProperty("os.name", "?")));
            md.update(getBytes(System.getProperty("os.arch", "?")));
            md.update(getBytes(System.getProperty("os.version", "?")));
            // CPU core count
            md.update(getBytes(String.valueOf(Runtime.getRuntime().availableProcessors())));
            // MAC address (first interface)
            byte[] mac = getFirstMac();
            if (mac != null) {
                md.update(mac);
            }
            // User name
            md.update(getBytes(System.getProperty("user.name", "?")));
            // Java version (minor contributor)
            md.update(getBytes(System.getProperty("java.version", "?")));
            return md.digest();
        } catch (Throwable t) {
            // Fallback: use a fixed seed derived from os.name only
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(getBytes(System.getProperty("os.name", "fallback")));
                return md.digest();
            } catch (Throwable t2) {
                return new byte[32]; // all zeros — last resort
            }
        }
    }

    /**
     * HKDF-Expand: derive a key of specified length from the fingerprint.
     * Uses a simple HMAC-SHA256 based expansion (RFC 5869).
     *
     * @param salt  optional salt (null = no salt)
     * @param info  context info string
     * @param length desired key length (e.g. 16 for AES-128, 32 for AES-256)
     */
    public static byte[] deriveKey(byte[] salt, String info, int length) {
        try {
            byte[] prk = derive();
            if (salt != null && salt.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(salt);
                md.update(prk);
                prk = md.digest();
            }
            // HKDF-Expand
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"));
            byte[] infoBytes = getBytes(info != null ? info : "");
            byte[] t = new byte[0];
            byte[] okm = new byte[length];
            int pos = 0;
            int counter = 1;
            while (pos < length) {
                mac.reset();
                mac.update(t);
                mac.update(infoBytes);
                mac.update((byte) counter);
                t = mac.doFinal();
                int copyLen = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, okm, pos, copyLen);
                pos += copyLen;
                counter++;
            }
            return okm;
        } catch (Throwable t) {
            return new byte[length]; // fallback: zeros
        }
    }

    private static byte[] getFirstMac() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces != null && ifaces.hasMoreElements()) {
                NetworkInterface ni = ifaces.nextElement();
                try {
                    if (ni.isLoopback() || !ni.isUp()) continue;
                    byte[] mac = ni.getHardwareAddress();
                    if (mac != null && mac.length > 0) return mac;
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static byte[] getBytes(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}
