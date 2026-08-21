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

    /** SHA-256 over all non-runtime .class entries AND META-INF entries,
     *  sorted by name. The integrity.hash file itself is excluded to avoid
     *  a circular dependency. META-INF entries (manifest, signatures, etc.)
     *  are included so any tampering with the jar metadata is detected. */
    private static String hashJar(File jar) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (ZipFile zf = new ZipFile(jar)) {
            // Collect entry names, sort, then hash contents in order.
            java.util.TreeSet<String> names = new java.util.TreeSet<>();
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                String n = ze.getName();
                // Skip the hash file itself (circular dependency)
                if (n.equals("META-INF/kbox/integrity.hash")) continue;
                // Skip signature files (they change when re-signing)
                if (n.startsWith("META-INF/") && (n.endsWith(".SF")
                        || n.endsWith(".RSA") || n.endsWith(".DSA"))) continue;
                // Include .class files (excluding KBox runtime)
                if (n.endsWith(".class")) {
                    if (n.startsWith("com/kbox/runtime/")) continue;
                    names.add(n);
                    continue;
                }
                // Include META-INF entries (manifest, config, etc.)
                if (n.startsWith("META-INF/")) {
                    names.add(n);
                    continue;
                }
                // Include other non-class resources (config files, etc.)
                if (!n.endsWith("/")) {
                    names.add(n);
                }
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
