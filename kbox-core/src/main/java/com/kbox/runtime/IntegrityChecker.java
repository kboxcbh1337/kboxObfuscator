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

    /** Run the check once. Safe to call multiple times. */
    public static void check() {
        if (checked) return;
        checked = true;
        try {
            File jar = locateJar();
            if (jar == null) return; // can't locate; skip silently
            byte[] expected = readResource("META-INF/kbox/integrity.hash");
            if (expected == null) return; // no hash stored; skip
            String expectedHex = new String(expected, java.nio.charset.StandardCharsets.UTF_8).trim();
            String actualHex = hashJar(jar);
            if (!expectedHex.equals(actualHex)) {
                tampered = true;
            }
        } catch (Throwable t) {
            // Don't fail loudly; just mark tampered so downstream corrupts.
            tampered = true;
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
    private static String hashJar(File jar) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
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
                md.update(n.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                ZipEntry ze = zf.getEntry(n);
                try (InputStream in = zf.getInputStream(ze)) {
                    byte[] buf = new byte[8192];
                    int r;
                    while ((r = in.read(buf)) > 0) md.update(buf, 0, r);
                }
            }
        }
        return toHex(md.digest());
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
