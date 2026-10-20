package com.kbox.core.packaging;

import com.kbox.core.log.KBoxLog;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Updates {@code META-INF/MANIFEST.MF}: rewrites the {@code Main-Class} if it
 * was renamed, and injects a {@code Class-Path} entry pointing at any native
 * lib placed next to the jar (so {@code System.loadLibrary} resolves when the
 * current dir is on {@code java.library.path}).
 *
 * We deliberately avoid {@code java.util.jar.Manifest} because it canonicalizes
 * the format (wraps long lines, normalizes version attributes) and that has
 * historically broken tools that consume the raw bytes. We do minimal text
 * edits on the original byte stream.
 */
public final class ManifestUpdater {

    private static final String TAG = "manifest";
    private final Map<String, String> classMap;

    /** True when the input is a Spring Boot executable (fat) jar. */
    private boolean springBootFatJar;
    /** Java 24+ (JEP 472) restricted-native-access opt-in for the unnamed
     *  module. Harmless on Java 8-23 (unknown manifest attributes are ignored);
     *  required from the release where restricted methods are blocked. */
    private boolean enableNativeAccess;

    public ManifestUpdater(Map<String, String> classMap) {
        this.classMap = classMap;
    }

    /**
     * Marks the input as a Spring Boot executable jar. Such jars declare
     * {@code Main-Class: org.springframework.boot.loader.launch.JarLauncher}
     * (a class at the jar ROOT) plus {@code Start-Class: <app main>} (a class
     * under {@code BOOT-INF/classes/}). The JVM's system classloader only sees
     * the jar root, so the entry-point substitution must target
     * {@code Start-Class} — see {@link #update(byte[], String, String, String)}.
     */
    public void setSpringBootFatJar(boolean v) {
        this.springBootFatJar = v;
    }

    /** 条目 Java 24-27: emit {@code Enable-Native-Access: ALL-UNNAMED} so the
     *  injected runtime may call {@code System.load} from Java 24 onward
     *  without warnings (and keeps working when JEP 472 blocks by default). */
    public void setEnableNativeAccess(boolean v) {
        this.enableNativeAccess = v;
    }

    public byte[] update(byte[] manifest, String oldMainClass) {
        return update(manifest, oldMainClass, null);
    }

    /**
     * Updates the manifest. When {@code launcherClass} is non-null (resource
     * obfuscation enabled), the renamed original main class is moved into the
     * {@code Original-Main-Class} attribute and {@code Main-Class} is replaced
     * by the launcher so the JVM boots the {@code ResourceGuardLauncher}
     * which transparently installs the resource resolver before invoking the
     * real application entry point.
     *
     * <p>When {@code tweakerClass} is non-null (class encryption + Forge/Mixin),
     * the tweaker is prepended to the existing {@code TweakClass} attribute
     * so it runs before {@code MixinTweaker} and decrypts encrypted classes.
     */
    public byte[] update(byte[] manifest, String oldMainClass, String launcherClass) {
        return update(manifest, oldMainClass, launcherClass, null);
    }

    /**
     * Full update with optional TweakClass prepending for class encryption
     * in Forge/Mixin projects.
     */
    public byte[] update(byte[] manifest, String oldMainClass, String launcherClass,
                         String tweakerClass) {
        if (manifest == null) return null;
        String s = new String(manifest, StandardCharsets.UTF_8);
        String newMain = oldMainClass == null ? null : mapClass(oldMainClass);

        // ---- Entry-point substitution ----
        // Standalone jar  : replace Main-Class with the guard launcher.
        // Spring Boot jar : KEEP Main-Class (it names the boot loader, which lives
        //   at the jar ROOT and is the only thing the JVM can load directly) and
        //   replace Start-Class instead. The boot loader resolves Start-Class
        //   through its LaunchedClassLoader, whose root is BOOT-INF/classes/ —
        //   exactly where the guard launcher is injected. Replacing Main-Class on
        //   such a jar dies at startup with
        //   ClassNotFoundException: com.kbox.runtime.ResourceGuardLauncher.
        final String entryAttr = springBootFatJar ? "Start-Class" : "Main-Class";
        if (launcherClass != null && newMain != null) {
            String replaced = replaceAttribute(s, entryAttr, launcherClass);
            if (replaced != null) {
                s = putAttributeAfter(replaced, entryAttr, "Original-Main-Class", newMain);
                KBoxLog.info(TAG, "Substituted " + entryAttr + " -> " + launcherClass
                        + " (Original-Main-Class=" + newMain + ")"
                        + (springBootFatJar ? " [Spring Boot: Main-Class kept as the boot loader]" : ""));
            } else {
                // No entry attribute at all (library-style input, or an entry
                // declared through --main-class). Add both so the launcher can
                // still be reached and the real entry is recorded.
                //
                // The attributes MUST go inside the main section: appending them
                // after the trailing blank line would start a second section
                // without a "Name:" attribute and the JVM rejects the manifest
                // with "invalid manifest format".
                int cut = s.length();
                while (cut > 0) {
                    char c = s.charAt(cut - 1);
                    if (c == '\n' || c == '\r') cut--;
                    else break;
                }
                s = s.substring(0, cut) + "\r\n"
                        + entryAttr + ": " + launcherClass + "\r\n"
                        + "Original-Main-Class: " + newMain + "\r\n\r\n";
                KBoxLog.info(TAG, "Added " + entryAttr + " -> " + launcherClass
                        + " (input had no entry attribute; Original-Main-Class=" + newMain + ")");
            }
        } else if (newMain != null && !newMain.equals(oldMainClass)) {
            String replaced = replaceAttribute(s, entryAttr, newMain);
            if (replaced != null) {
                s = replaced;
                KBoxLog.info(TAG, "Updated " + entryAttr + ": " + oldMainClass + " -> " + newMain);
            }
        }

        // ---- TweakClass prepend (Forge/Mixin mods with class encryption) ----
        if (tweakerClass != null) {
            int ti = s.indexOf("TweakClass:");
            if (ti >= 0) {
                int tend = s.indexOf('\n', ti);
                if (tend < 0) tend = s.length();
                // Consume the full line ending (\n or \r\n) so we don't leave
                // a dangling \n that creates a blank line between attributes.
                int afterEnd = tend;
                while (afterEnd < s.length() && (s.charAt(afterEnd) == '\r' || s.charAt(afterEnd) == '\n'))
                    afterEnd++;
                String line = s.substring(ti, tend).trim();
                String oldTweak = line.substring("TweakClass:".length()).trim();
                if (!oldTweak.startsWith(tweakerClass)) {
                    // Prepend our decrypt tweaker before existing tweaker(s).
                    String replacement = "TweakClass: " + tweakerClass + " " + oldTweak + "\r\n";
                    s = s.substring(0, ti) + replacement + s.substring(afterEnd);
                    KBoxLog.info(TAG, "Prepended TweakClass: " + tweakerClass
                            + " (was: " + oldTweak + ")");
                }
            }
        }

        // ---- FMLCorePlugin remap (Forge 1.8.9..1.12.2 coremod) ----
        // FML instantiates this class directly from the manifest before any mod
        // class is defined. It is normally kept (MinecraftModDetector adds it to
        // the keep set); if a mapping does rename it, the manifest must follow,
        // otherwise startup dies with ClassNotFoundException.
        if (classMap != null && !classMap.isEmpty()) {
            s = remapClassList(s, "FMLCorePlugin");
        }

        // ---- Java 24+ restricted native access (JEP 472) ----
        // The injected runtime may load a native crypto/VMP library through
        // System.load. Java 24 warns, later releases block by default; the
        // manifest attribute is the supported opt-in and is ignored by 8-23.
        if (enableNativeAccess && findAttributeLine(s, "Enable-Native-Access") < 0) {
            int cut = s.length();
            while (cut > 0) {
                char c = s.charAt(cut - 1);
                if (c == '\n' || c == '\r') cut--;
                else break;
            }
            s = s.substring(0, cut) + "\r\n"
                    + "Enable-Native-Access: ALL-UNNAMED\r\n\r\n";
        }

        // Ensure the manifest ends with a blank line (per spec) and use CRLF.
        if (!s.endsWith("\r\n")) s = s + "\r\n";
        if (!s.endsWith("\r\n\r\n")) s = s + "\r\n";
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private String mapClass(String dotted) {
        // classMap keys are internal (slash) names; manifest values are dotted.
        String internal = dotted.replace('.', '/');
        String mapped = classMap.get(internal);
        if (mapped == null) mapped = classMap.get(dotted);
        if (mapped == null) return dotted;
        return mapped.replace('/', '.');
    }

    /** Remaps a comma-separated class list attribute (e.g. FMLCorePlugin). */
    private String remapClassList(String s, String attr) {
        int i = findAttributeLine(s, attr);
        if (i < 0) return s;
        int end = s.indexOf('\n', i);
        int lineEnd = end < 0 ? s.length() : end;
        int colon = s.indexOf(':', i);
        if (colon < 0 || colon > lineEnd) return s;
        String val = s.substring(colon + 1, lineEnd).trim();
        if (val.isEmpty()) return s;
        String[] parts = val.split(",");
        StringBuilder nb = new StringBuilder();
        boolean changed = false;
        for (String p : parts) {
            String t = p.trim();
            String mapped = mapClass(t);
            if (!mapped.equals(t)) changed = true;
            if (nb.length() > 0) nb.append(", ");
            nb.append(mapped);
        }
        if (!changed) return s;
        String eol = (end > i && s.charAt(end - 1) == '\r') ? "\r\n" : "\n";
        int next = (end < s.length()) ? end + 1 : end;
        return s.substring(0, i) + attr + ": " + nb + eol + s.substring(next);
    }

    /**
     * Finds the start index of an attribute line. Matching is anchored at a line
     * start so {@code Main-Class} can never match inside
     * {@code Original-Main-Class} (which we may have injected on an earlier run).
     */
    private static int findAttributeLine(String s, String attr) {
        String needle = attr + ":";
        int from = 0;
        while (true) {
            int i = s.indexOf(needle, from);
            if (i < 0) return -1;
            if (i == 0 || s.charAt(i - 1) == '\n') return i;
            from = i + 1;
        }
    }

    /** Replaces an attribute's value, preserving the original line ending.
     *  Returns {@code null} when the attribute is absent. */
    private static String replaceAttribute(String s, String attr, String value) {
        int i = findAttributeLine(s, attr);
        if (i < 0) return null;
        int end = s.indexOf('\n', i);
        if (end < 0) end = s.length();
        String eol = (end > i && s.charAt(end - 1) == '\r') ? "\r\n" : "\n";
        int next = (end < s.length()) ? end + 1 : end;
        return s.substring(0, i) + attr + ": " + value + eol + s.substring(next);
    }

    /** Inserts {@code newAttr: newValue} directly after the {@code afterAttr} line. */
    private static String putAttributeAfter(String s, String afterAttr,
                                            String newAttr, String newValue) {
        int i = findAttributeLine(s, afterAttr);
        if (i < 0) return s;
        int end = s.indexOf('\n', i);
        int insertAt = (end < 0) ? s.length() : end + 1;
        return s.substring(0, insertAt) + newAttr + ": " + newValue + "\r\n" + s.substring(insertAt);
    }
}
