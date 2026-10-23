package com.kbox.runtime;

import java.io.File;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Boot-time jar integrity check. Computes a SHA-256 over the sorted .class
 * entries of the running jar (excluding KBox runtime classes) and compares it
 * against the value stored in {@code META-INF/kbox/integrity.hash}.
 *
 * <p>If the hash mismatches, {@link #tampered} is set. Downstream code
 * (string decryptor, VMP dispatcher) consults this flag to silently corrupt
 * results, so a repackaged/modified jar appears to run but produces garbage.
 *
 * <p>The stored hash file is itself written by the {@code Packager} and is
 * not encrypted (it is a hash, not a secret); the security comes from the
 * fact that any class modification changes the digest.
 */
public final class IntegrityChecker {

    private static volatile boolean tampered = false;
    private static volatile boolean checked = false;

    private IntegrityChecker() {}

    public static boolean isTampered() { return tampered; }

    /** Run the check once. Safe to call multiple times.
     *
     *  <p>条目 85/91: besides the whole-jar digest, a Merkle root over the
     *  per-class leaf hashes is verified (when {@code integrity.merkle} is
     *  present), and a low-priority daemon re-runs the verification every
     *  {@code -Dkbox.integrity.interval=<ms>} (default 60s, {@code <=0}
     *  disables) so a jar swapped on disk after boot is also detected. */
    public static void check() {
        if (checked) return;
        checked = true;
        verifyNow();
        startPeriodicCheck();
    }

    /** 条目 91: periodic re-verification. */
    private static void startPeriodicCheck() {
        long interval;
        try {
            interval = Long.getLong("kbox.integrity.interval", 60000L);
        } catch (Throwable t) {
            interval = 60000L;
        }
        if (interval <= 0) return;
        final long period = interval;
        try {
            Thread t = new Thread(() -> {
                while (true) {
                    try {
                        Thread.sleep(period);
                    } catch (InterruptedException ie) {
                        return;
                    }
                    verifyNow();
                }
            }, "kbox-integrity");
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            t.start();
        } catch (Throwable ignored) {
            // Thread creation failure must never break the app.
        }
    }

    /** Recomputes all digests; flips {@link #tampered} on any mismatch. */
    private static void verifyNow() {
        try {
            File jar = locateJar();
            if (jar == null) return; // can't locate; skip silently
            byte[] expected = readResource("META-INF/kbox/integrity.hash");
            byte[] expectedMerkle = readResource("META-INF/kbox/integrity.merkle");
            if (expected == null && expectedMerkle == null) return; // not enforced
            String[] actual = computeHashes(jar);
            if (expected != null) {
                String expectedHex = new String(expected,
                        java.nio.charset.StandardCharsets.UTF_8).trim();
                if (!expectedHex.equals(actual[0])) tampered = true;
            }
            if (expectedMerkle != null) {
                String expectedHex = new String(expectedMerkle,
                        java.nio.charset.StandardCharsets.UTF_8).trim();
                if (!expectedHex.equals(actual[1])) tampered = true;
            }
            // 条目 90: signature linkage. When the build embedded a certificate
            // fingerprint, the running jar MUST be signed by that certificate.
            // An unsigned or re-signed jar is treated as tampered.
            byte[] sigBind = readResource("META-INF/kbox/sig.bind");
            if (sigBind != null) {
                String want = new String(sigBind,
                        java.nio.charset.StandardCharsets.UTF_8).trim();
                if (!want.isEmpty() && !signedBy(jar, want)) tampered = true;
            }
        } catch (java.io.IOException io) {
            // KBX-NAT-06: a verification PROCESS failure (transient IO error,
            // nested-jar CodeSource quirk, read-only fs) is NOT proof of
            // tampering. Treating it as such permanently corrupted every
            // protected string on such environments. Skip this round; the
            // periodic re-check will retry. A genuinely modified jar produces
            // a hash MISMATCH above, which still flips the flag.
        } catch (Throwable t) {
            // Unexpected internal error: also skip (not evidence of tampering).
        }
    }

    /** Locate the jar this class was loaded from. */
    private static File locateJar() {
        try {
            java.security.CodeSource cs = IntegrityChecker.class.getProtectionDomain().getCodeSource();
            if (cs == null || cs.getLocation() == null) return null;
            return new File(cs.getLocation().toURI());
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * SHA-256 over all non-KBox-runtime {@code .class} entries, sorted by name
     * (name bytes then content bytes per entry).
     *
     * <p><b>Signature parity.</b> This must hash EXACTLY the same entry set in the
     * exact same order/format as the build side
     * {@code com.kbox.core.packaging.Packager#writeIntegrityHash}, otherwise an
     * honest (untampered) jar will always look tampered. The build side hashes
     * <em>only</em> the protected classes (all KBox runtime classes are excluded
     * on both sides because they are injected verbatim). META-INF resources
     * (manifest, {@code resources.map}, {@code native-crypto.bin}, {@code lic.pub},
     * the {@code integrity.hash} file itself, signature files) are deliberately
     * NOT hashed: they are either injected per-build or would make the digest
     * brittle to repackaging that the class set itself would catch anyway.
     */
    /**
     * Computes both digests in ONE pass over the sorted class set:
     * <ul>
     *   <li>[0] — whole-jar SHA-256 (name bytes then content bytes per entry),</li>
     *   <li>[1] — Merkle root over per-entry leaf hashes (条目 85).</li>
     * </ul>
     * Entry selection and ordering must mirror {@code Packager#writeIntegrityHash}
     * exactly; see that method's contract for the excluded entry classes.
     */
    private static String[] computeHashes(File jar) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        java.util.List<byte[]> leaves = new java.util.ArrayList<>();
        try (ZipFile zf = new ZipFile(jar)) {
            java.util.TreeSet<String> names = new java.util.TreeSet<>();
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                String n = ze.getName();
                if (!n.endsWith(".class")) continue;          // classes only
                if (n.startsWith("com/kbox/runtime/")) continue; // runtime excluded
                // Skip anti-unpack decoy "classes": Packager injects fake .class
                // entries under META-INF/ (junk decoys) that exist on disk but are
                // never part of the protected class set — including them would make
                // the digest permanently mismatch the build side.
                if (n.contains("/META-INF/")) continue;
                names.add(n);
            }
            for (String n : names) {
                byte[] nameBytes = n.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] content;
                try (InputStream in = zf.getInputStream(zf.getEntry(n))) {
                    java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                    byte[] buf = new byte[8192];
                    int r;
                    while ((r = in.read(buf)) > 0) bo.write(buf, 0, r);
                    content = bo.toByteArray();
                }
                md.update(nameBytes);
                md.update(content);
                MessageDigest leaf = MessageDigest.getInstance("SHA-256");
                leaf.update(nameBytes);
                leaf.update(content);
                leaves.add(leaf.digest());
            }
        }
        return new String[]{toHex(md.digest()), toHex(merkleRoot(leaves))};
    }

    /** Binary Merkle root; an odd trailing node is hashed with itself. */
    private static byte[] merkleRoot(java.util.List<byte[]> leaves) throws Exception {
        if (leaves.isEmpty()) return new byte[32];
        java.util.List<byte[]> cur = leaves;
        while (cur.size() > 1) {
            java.util.List<byte[]> next = new java.util.ArrayList<>();
            for (int i = 0; i < cur.size(); i += 2) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(cur.get(i));
                md.update(i + 1 < cur.size() ? cur.get(i + 1) : cur.get(i));
                next.add(md.digest());
            }
            cur = next;
        }
        return cur.get(0);
    }

    /** 条目 90: true when the jar carries a signer certificate whose DER
     *  SHA-256 equals {@code fingerprintHex}. Unsigned jars return false. */
    private static boolean signedBy(File jar, String fingerprintHex) {
        try (java.util.jar.JarFile jf = new java.util.jar.JarFile(jar, true)) {
            java.util.TreeSet<String> hashes = new java.util.TreeSet<>();
            Enumeration<? extends java.util.jar.JarEntry> en = jf.entries();
            while (en.hasMoreElements()) {
                java.util.jar.JarEntry je = en.nextElement();
                if (je.isDirectory()) continue;
                // Certificates are populated only after the entry is actually
                // verified, and JarFile verifies lazily on stream access — so
                // the entry must be read before getCertificates().
                try (InputStream in = jf.getInputStream(je)) {
                    byte[] buf = new byte[8192];
                    while (in.read(buf) > 0) { /* drain to trigger verification */ }
                }
                java.security.cert.Certificate[] certs = je.getCertificates();
                if (certs == null) continue;
                for (java.security.cert.Certificate c : certs) {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    hashes.add(toHex(md.digest(c.getEncoded())));
                }
            }
            return hashes.contains(fingerprintHex.trim());
        } catch (Throwable t) {
            return false;
        }
    }

    private static byte[] readResource(String path) {
        try (InputStream in = IntegrityChecker.class.getClassLoader().getResourceAsStream(path)) {
            if (in == null) return null;
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) > 0) bo.write(buf, 0, r);
            return bo.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
