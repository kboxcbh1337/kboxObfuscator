package com.kbox.runtime;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;

/**
 * L0 / Zero-Vortex: {@code HardwareKeyRing}.
 *
 * <p>Collects a <em>machine</em> fingerprint from real hardware identity
 * sources (not just {@code -D} spoofable string properties) and derives three
 * 256-bit subkeys by HKDF-SHA256:
 *
 * <pre>
 *   classKey  -> encrypts on-disk / in-memory class bodies
 *   streamKey -> encrypts the VM instruction stream (VortexVM / VMP code)
 *   wmKey     -> encrypts the digital watermark slots
 * </pre>
 *
 * <p>An additional {@link #ephemeralKey()} is derived from the machine
 * fingerprint combined with a per-launch salt (startup time + random). It is
 * intentionally <em>not stable across runs</em>, so two launches of the same
 * protected application yield different in-memory cipher streams (defeats
 * replay / re-dump of a decrypted instruction window).
 *
 * <p>Design principles (matching the project's hard constraints):
 * <ul>
 *   <li><b>Silent degradation.</b> Every hardware source is best-effort and
 *       wrapped in a short-timeout guard. If a source is unavailable or the
 *       fingerprint moves to another machine, we never throw and never crash;
 *       {@link #classKey()} etc. still return a deterministic 32-byte key so
 *       the JVM runs. The corruption is only visible as "wrong" plaintext, not
 *       as an exception.</li>
 *   <li><b>Deterministic per machine.</b> The hardware factor feed is stable
 *       across processes on the same host, so all {@code *Key()} calls agree
 *       in the protect (build) JVM and the run JVM on the same machine.</li>
 *   <li><b>No privileged API dependency.</b> DMI/IOPlatform are read via the
 *       kernel sysfs / IOKit CLI; Windows hardware identity is best-effort via
 *       {@code wmic} with a timeout; if it is blocked we fall back to MAC +
 *       boot-dir identity, which itself is not settable via {@code -D}.</li>
 * </ul>
 *
 * <p>Because the feed must agree between the build-time encryptor and the
 * run-time decryptor on the same box, {@link #machineFactors()} uses only
 * sources that are identical in both JVMs on a given host.
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
    public static byte[] classKey()   { return hkdf(feed(), "kbox:class",   KEY_LEN); }

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
        return hkdf(feed(), "kbox:eph:" + Long.toHexString(nanosSalt()), KEY_LEN);
    }

    /** 32-byte machine fingerprint = SHA-256 of the stable hardware factor feed.
     *  Used by the license verifier for device-binding comparison. */
    public static byte[] fingerprint() {
        return sha256(feed());
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

    /** Fixed domain-separation salt; must be byte-identical on build & run JVMs. */
    private static final byte[] VMP_SALT = toBytes("KBox-VMP-KeyWrap-v1");

    /** Hardware-bound master for VMP key wrapping (stable per machine).
     *  <p>Derived from {@link #stableMachineFeed()}, which uses ONLY deterministic,
     *  subprocess-free sources (OS/arch/CPU-count, MAC, boot-disk path). This is
     *  intentional: VmpMethod is key-wrapped at protect time and unwrapped at run
     *  time — possibly seconds/minutes apart — so the master MUST be reproducible
     *  across those two JVMs. The full {@link #feed()} includes {@code wmic}/
     *  {@code ioreg} subprocess results which are timing-flaky on Windows (1500ms
     *  timeout can return partial data), so it is NOT a safe build->run binding.
     *  Class-body encryption still uses the stronger {@link #feed()}; VMP key
     *  wrapping priorities deterministic binding over maximum entropy. */
    public static byte[] vmpMaster() {
        return hkdfPreferred(sha256(stableMachineFeed()), VMP_SALT, "kbox.master", KEY_LEN);
    }

    /** Deterministic, subprocess-free machine feed (os/arch/cpus + MAC + boot disk). */
    private static byte[] stableMachineFeed() {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(128);
            out.write(toBytes(System.getProperty("os.name", "?")));
            out.write(toBytes(System.getProperty("os.arch", "?")));
            out.write(toBytes(String.valueOf(Runtime.getRuntime().availableProcessors())));
            byte[] mac = firstMac();
            if (mac != null) { out.write(mac); }
            out.write(toBytes(bootDiskIdentity()));
            return out.toByteArray();
        } catch (Throwable ignored) {
            byte[] f = new byte[32];
            new java.security.SecureRandom().nextBytes(f);
            return f;
        }
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
        if (com.kbox.runtime.NativeCrypto.available()) {
            try {
                byte[] infoB = info.getBytes(StandardCharsets.UTF_8);
                byte[] out = com.kbox.runtime.NativeCrypto.hkdfSha256(ikm, salt, infoB, len);
                if (out != null && out.length == len) return out;
            } catch (Throwable ignored) {
                // fall through to Java
            }
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
     */
    private static byte[] feed() {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(256);
            out.write(toBytes(System.getProperty("os.name", "?")));
            out.write(toBytes(System.getProperty("os.arch", "?")));
            out.write(toBytes(String.valueOf(Runtime.getRuntime().availableProcessors())));
            byte[] mac = firstMac();
            if (mac != null) { out.write(mac); }
            byte[] dmi = dmiFingerprint();
            if (dmi.length > 0) { out.write(dmi); }
            byte[] win = windowsFingerprint();
            if (win.length > 0) { out.write(win); }
            byte[] cli = macCliFingerprint();
            if (cli.length > 0) { out.write(cli); }
            out.write(toBytes(bootDiskIdentity()));
            return out.toByteArray();
        } catch (Throwable ignored) {
            // Unreachable in practice; keep a stable fallback key alive.
            try {
                MessageDigest md = MessageDigest.getInstance(DIGEST);
                md.update(toBytes(System.getProperty("os.name", "?")));
                return md.digest();
            } catch (Throwable ignored2) {
                return new byte[KEY_LEN];
            }
        }
    }

    /** First non-loopback, up-network-interface MAC (hardware-derived, not -D spoofable). */
    private static byte[] firstMac() {
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            while (ifs != null && ifs.hasMoreElements()) {
                NetworkInterface ni = ifs.nextElement();
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

    /** true on Windows. */
    private static boolean isWin() {
        String s = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        return s.contains("win");
    }

    /** true on Linux. */
    private static boolean isLinux() {
        return "Linux".equalsIgnoreCase(System.getProperty("os.name", ""));
    }

    /** true on macOS. */
    private static boolean isMac() {
        return "Mac OS X".equalsIgnoreCase(System.getProperty("os.name", ""))
                || System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("mac");
    }

    /**
     * Linux DMI identity: product_uuid / board_serial / product_serial from
     * the kernel's sysfs (no privileges needed, root-readable for all users).
     * Empty when the files are absent (non-Linux).
     */
    private static byte[] dmiFingerprint() {
        try {
            if (!isLinux()) return new byte[0];
            ByteArrayOutputStream out = new ByteArrayOutputStream(96);
            String[] rel = {
                "/sys/class/dmi/id/product_uuid",
                "/sys/class/dmi/id/product_serial",
                "/sys/class/dmi/id/board_serial",
                "/sys/class/dmi/id/chassis_serial",
            };
            for (String p : rel) {
                Path path = Paths.get(p);
                if (Files.isReadable(path)) {
                    byte[] b = Files.readAllBytes(path);
                    if (b.length > 0) out.write(trim(b));
                }
            }
            return out.toByteArray();
        } catch (Throwable ignored) {
            return new byte[0];
        }
    }

    /**
     * Windows hardware identity via {@code wmic} (ProcessorId, BIOS serial,
     * BaseBoard serial, system UUID). Runs with a hard timeout and silently
     * yields {} when wmic is absent/blocked. This is not settable via -D.
     *
     * <p>wmic is deprecated and being removed on Windows 11 24H2+, so when
     * wmic returns nothing we fall back to {@code Get-CimInstance} through
     * PowerShell, which reads the same WMI/CIM hardware identity. The source
     * is chosen deterministically (wmic first, then CIM) so the build-time
     * packager and the run-time JVM on the same host always agree.
     */
    private static byte[] windowsFingerprint() {
        byte[] cpu = exec(new String[]{"wmic", "cpu", "get", "ProcessorId"});
        byte[] bios = exec(new String[]{"wmic", "bios", "get", "SerialNumber"});
        byte[] bb = exec(new String[]{"wmic", "baseboard", "get", "SerialNumber"});
        byte[] uuid = exec(new String[]{"wmic", "csproduct", "get", "UUID"});
        boolean wmicOk = cpu.length > 0 || bios.length > 0 || bb.length > 0 || uuid.length > 0;
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(128);
            if (wmicOk) {
                if (cpu.length > 0) out.write(stripHeader(cpu));
                if (bios.length > 0) out.write(stripHeader(bios));
                if (bb.length > 0) out.write(stripHeader(bb));
                if (uuid.length > 0) out.write(stripHeader(uuid));
            } else {
                byte[] cim = powershellHardwareFingerprint();
                if (cim.length > 0) out.write(cim);
            }
            return out.toByteArray();
        } catch (Throwable ignored) {
            return new byte[0];
        }
    }

    /**
     * Windows CIM hardware identity via PowerShell {@code Get-CimInstance}
     * (ProcessorId, BIOS serial, BaseBoard serial, system UUID). Used only when
     * wmic is unavailable (deprecated on Windows 11 24H2+). Longer timeout to
     * cover a cold PowerShell start; silently yields {} on any failure.
     */
    private static byte[] powershellHardwareFingerprint() {
        String script =
                "Get-CimInstance Win32_Processor | %{ $_.ProcessorId }; " +
                "Get-CimInstance Win32_BIOS | %{ $_.SerialNumber }; " +
                "Get-CimInstance Win32_BaseBoard | %{ $_.SerialNumber }; " +
                "Get-CimInstance Win32_ComputerSystemProduct | %{ $_.UUID }";
        byte[] raw = exec(new String[]{"powershell", "-NoProfile", "-NonInteractive",
                "-Command", script}, 4000L);
        if (raw.length == 0) return new byte[0];
        String s = new String(raw, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        for (String line : s.split("\\r?\\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            sb.append(t);
        }
        return toBytes(sb.toString());
    }

    /** macOS IOPlatformUUID via IOKit CLI. Best-effort, silenced. */
    private static byte[] macCliFingerprint() {
        if (!isMac()) return new byte[0];
        byte[] out = exec(new String[]{"ioreg", "-rd1", "-c", "IOPlatformExpertDevice"});
        if (out.length == 0) return new byte[0];
        String s = new String(out, StandardCharsets.UTF_8);
        int i = s.indexOf("IOPlatformUUID");
        if (i < 0) return new byte[0];
        int p = s.indexOf('"', s.indexOf('=', i));
        int e = p > 0 ? s.indexOf('"', p + 1) : -1;
        if (p > 0 && e > p) return toBytes(s.substring(p + 1, e).trim());
        return new byte[0];
    }

    /** Stable boot-disk identity: canonical user.home path (machine-ish anchor). */
    private static String bootDiskIdentity() {
        try {
            String home = System.getProperty("user.home", "?");
            if (isLinux()) {
                File f = new File(home);
                return f.getCanonicalPath().replaceAll("[0-9]+$", "X");
            }
            return home;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    // ------------------------------------------------------------------
    //  subprocess helper (short timeout, silent)
    // ------------------------------------------------------------------

    private static byte[] exec(String[] cmd) {
        return exec(cmd, 1500L);
    }

    private static byte[] exec(String[] cmd, long timeoutMillis) {
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            if (!p.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) {
                p.destroyForcibly();
                return new byte[0];
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream(128);
            byte[] buf = new byte[2048];
            int n;
            java.io.InputStream in = p.getInputStream();
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toByteArray();
        } catch (Throwable ignored) {
            return new byte[0];
        }
    }

    /** Drop the header line that wmic prints (the column title). */
    private static byte[] stripHeader(byte[] raw) {
        String s = new String(raw, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        for (String line : s.split("\\r?\\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            boolean header = t.equalsIgnoreCase("ProcessorId") || t.equalsIgnoreCase("SerialNumber")
                    || t.equalsIgnoreCase("FGPUID") || t.equalsIgnoreCase("UUID")
                    || t.toLowerCase(java.util.Locale.ROOT).startsWith("processorid");
            if (header) continue;
            sb.append(t);
        }
        return toBytes(sb.toString());
    }

    private static byte[] trim(byte[] b) {
        return toBytes(new String(b, StandardCharsets.UTF_8).trim());
    }

    // ------------------------------------------------------------------
    //  HKDF-SHA256 (RFC 5869 extract+expand)
    // ------------------------------------------------------------------

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
}