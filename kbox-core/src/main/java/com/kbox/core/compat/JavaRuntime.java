package com.kbox.core.compat;

import com.kbox.core.log.KBoxLog;

/**
 * Runtime JDK compatibility layer for the obfuscator itself.
 *
 * <p>KBox is built with {@code --release 8} (core/CLI) so the CLI must start on
 * every JVM from Java 8 through the newest feature release. This class reports
 * the detected feature version, validates the supported window
 * ({@value #MIN_FEATURE}..{@value #MAX_FEATURE}) and emits one actionable
 * startup line instead of letting an obscure linkage error surface later.
 *
 * <p>It also drives the GUI gate: {@code kbox-gui} is compiled with
 * {@code --release 17} (it uses Java 9+ APIs), so {@code --gui} on Java 8-16
 * must fail with a clear message rather than {@code UnsupportedClassVersionError}.
 */
public final class JavaRuntime {

    public static final int MIN_FEATURE = 8;
    /** Newest JDK feature release this build is validated against. */
    public static final int MAX_FEATURE = 27;
    /** The GUI module is compiled for this feature release. */
    public static final int GUI_FEATURE = 17;

    private JavaRuntime() {}

    /** Feature release of the running JVM ({@code 1.8.0_x} → 8, {@code 25} → 25). */
    public static int feature() {
        String v = System.getProperty("java.specification.version", "8");
        try {
            if (v.startsWith("1.")) return Integer.parseInt(v.substring(2));
            int dot = v.indexOf('.');
            return Integer.parseInt(dot < 0 ? v : v.substring(0, dot));
        } catch (Exception e) {
            return 8;
        }
    }

    public static boolean atLeast(int feature) { return feature() >= feature; }

    public static boolean guiSupported() { return atLeast(GUI_FEATURE); }

    /** e.g. {@code 25.0.1+8-LTS (Eclipse Adoptium)}. */
    public static String describe() {
        return System.getProperty("java.version", "?") + " ("
                + System.getProperty("java.vendor", "?") + ")";
    }

    /** Emits the startup compatibility line and any advisory for this JDK. */
    public static void logStartup(String app) {
        int f = feature();
        KBoxLog.info("compat", app + " starting on Java " + f + " [" + describe() + "]");
        if (f < MIN_FEATURE) {
            KBoxLog.warn("compat", "Java " + MIN_FEATURE + "+ is required; Java " + f
                    + " may fail with missing APIs or class-file support.");
        } else if (f > MAX_FEATURE) {
            KBoxLog.warn("compat", "Running on Java " + f + " (newer than the validated Java "
                    + MAX_FEATURE + "). Class files newer than major "
                    + ClassFileCompat.MAX_MAJOR + " are parsed with a forward-compatible header mask.");
        }
        KBoxLog.debug("compat", "Class-file range: major " + ClassFileCompat.MIN_MAJOR + ".."
                + ClassFileCompat.MAX_MAJOR + " (Java " + (ClassFileCompat.MIN_MAJOR - 44)
                + ".." + (ClassFileCompat.MAX_MAJOR - 44) + "), forward-masked beyond.");
        if (f >= 17) {
            KBoxLog.debug("compat", "GUI available (compiled for Java " + GUI_FEATURE + "+).");
        }
    }
}
