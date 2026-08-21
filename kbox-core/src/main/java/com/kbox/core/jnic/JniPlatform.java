package com.kbox.core.jnic;

/**
 * JVM platform variant for JNI code generation. Different JVM implementations
 * have different JNI conventions and available APIs:
 *
 * <ul>
 *   <li><b>HOTSPOT</b> — OpenJDK/Oracle HotSpot VM. Uses {@code DefineClass}
 *       for on-the-fly class loading and supports full JNI 1.8+ API.
 *       Default for desktop/server Java applications.</li>
 *   <li><b>STD_JAVA</b> — Standard JNI with minimal assumptions. Uses
 *       {@code FindClass} instead of {@code DefineClass} (safer for
 *       compatibility with non-HotSpot VMs like GraalVM native-image,
 *       OpenJ9). Avoids HotSpot-specific JVM TI extensions.</li>
 *   <li><b>ANDROID</b> — Android Runtime (ART/Dalvik). Uses
 *       {@code JNI_OnLoad} with Android-specific class-loader handling,
 *       avoids {@code FindClass} in threads where the classloader may
 *       differ. Uses {@code __android_log_print} for logging instead
 *       of fprintf.</li>
 * </ul>
 *
 * <p>The platform selection affects:
 * <ol>
 *   <li>C header style ({@code __stdcall} on Windows HotSpot? No — JNI uses
 *       the platform ABI, no special calling convention markers needed.)</li>
 *   <li>Class-lookup strategy (FindClass via env vs. cached jclass refs
 *       vs. ClassLoader-based lookup).</li>
 *   <li>Thread attachment (Android requires {@code AttachCurrentThread}
 *       with specific semantics for daemon threads).</li>
 *   <li>Exception handling (Android's CheckException may differ from HotSpot).</li>
 *   <li>Logging sink (Android: __android_log_print; HotSpot: fprintf(stderr)).</li>
 * </ol>
 */
public enum JniPlatform {

    /** OpenJDK / Oracle HotSpot VM (default). */
    HOTSPOT("hotspot"),

    /** Standard JNI, minimal assumptions (GraalVM, OpenJ9 compatible). */
    STD_JAVA("std_java"),

    /** Android Runtime (ART / Dalvik). */
    ANDROID("android");

    private final String configName;

    JniPlatform(String configName) {
        this.configName = configName;
    }

    /** Returns the platform identifier string used in config files. */
    public String getConfigName() { return configName; }

    /** Parse a platform name from the config string. */
    public static JniPlatform fromConfig(String s) {
        if (s == null) return HOTSPOT;
        switch (s.toLowerCase(java.util.Locale.ROOT).trim()) {
            case "android": return ANDROID;
            case "std_java":
            case "stdjava":
            case "standard": return STD_JAVA;
            case "hotspot":
            case "openjdk":
            default: return HOTSPOT;
        }
    }

    /** Returns true if DefineClass is available (HotSpot only). */
    public boolean supportsDefineClass() {
        return this == HOTSPOT;
    }

    /** Returns true if Android logging should be used. */
    public boolean useAndroidLogging() {
        return this == ANDROID;
    }
}
