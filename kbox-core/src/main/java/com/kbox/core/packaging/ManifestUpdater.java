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

    public ManifestUpdater(Map<String, String> classMap) {
        this.classMap = classMap;
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

        // ---- Main-Class substitution (standalone jars) ----
        if (launcherClass != null && newMain != null) {
            int i = s.indexOf("Main-Class:");
            if (i >= 0) {
                int end = s.indexOf('\n', i);
                if (end < 0) end = s.length();
                int afterEnd = end;
                while (afterEnd < s.length() && (s.charAt(afterEnd) == '\r' || s.charAt(afterEnd) == '\n'))
                    afterEnd++;
                String replacement = "Main-Class: " + launcherClass + "\r\n"
                        + "Original-Main-Class: " + newMain + "\r\n";
                s = s.substring(0, i) + replacement + s.substring(afterEnd);
                KBoxLog.info(TAG, "Substituted Main-Class -> " + launcherClass
                        + " (Original-Main-Class=" + newMain + ")");
            }
        } else if (newMain != null && !newMain.equals(oldMainClass)) {
            int i = s.indexOf("Main-Class:");
            if (i >= 0) {
                int end = s.indexOf('\n', i);
                if (end < 0) end = s.length();
                int afterEnd = end;
                while (afterEnd < s.length() && (s.charAt(afterEnd) == '\r' || s.charAt(afterEnd) == '\n'))
                    afterEnd++;
                s = s.substring(0, i) + "Main-Class: " + newMain + "\r\n" + s.substring(afterEnd);
                KBoxLog.info(TAG, "Updated Main-Class: " + oldMainClass + " -> " + newMain);
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
}
