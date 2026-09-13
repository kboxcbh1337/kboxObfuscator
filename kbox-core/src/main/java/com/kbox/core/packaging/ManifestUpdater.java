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
                KBoxLog.warn(TAG, "Manifest has no " + entryAttr + " attribute; "
                        + "guard launcher not installed (principal class left untouched)");
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

        // Ensure the manifest ends with a blank line (per spec) and use CRLF.
        if (!s.endsWith("\r\n")) s = s + "\r\n";
        if (!s.endsWith("\r\n\r\n")) s = s + "\r\n";
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private String mapClass(String dotted) {
        String mapped = classMap.get(dotted);
        return mapped != null ? mapped : dotted;
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
