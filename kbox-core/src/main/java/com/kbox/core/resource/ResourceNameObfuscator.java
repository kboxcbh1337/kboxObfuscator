package com.kbox.core.resource;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

/**
 * Generates random names for non-class resources and decides which resources
 * should also have their content encrypted.
 *
 * <p><b>Safety rules</b>:
 * <ul>
 *   <li>Never rename {@code META-INF/MANIFEST.MF} — the JVM reads it directly.</li>
 *   <li>Never rename files under {@code META-INF/services/} when the resource
 *       reference updater is responsible for them (their <em>file name</em>
 *       tracks a renamed interface, so renaming twice would break).</li>
 *   <li>Never rename Spring Boot launcher classes ({@code org/springframework/boot/loader/*}).</li>
 *   <li>Files matching {@code excludeResourcePatterns} keep their original name and are not encrypted.</li>
 *   <li>Files matching {@code encryptResourcePatterns} are flagged for AES-GCM encryption; the
 *       remaining renameable files get their name randomized only.</li>
 * </ul>
 *
 * <p>Random names are 16-hex-char strings under a flat {@code res/} directory to
 * hide the original directory structure. The extension is preserved when the
 * pattern is recognized (some loaders dispatch by extension), otherwise a
 * {@code .dat} suffix is used.
 */
public final class ResourceNameObfuscator {

    private static final String TAG = "resource-name";
    private static final String RES_PREFIX = "res/";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final SecureRandom rng = new SecureRandom();
    private final ResourceMapping mapping = new ResourceMapping();

    public ResourceNameObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public ResourceMapping compute() {
        if (!cfg.isObfuscateResources()) {
            KBoxLog.info(TAG, "Resource obfuscation disabled");
            return mapping;
        }
        Set<String> encryptPatterns = cfg.getEncryptResourcePatterns();
        Set<String> excludePatterns = cfg.getExcludeResourcePatterns();
        int renamed = 0;
        int encrypted = 0;

        for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            String path = e.getKey();
            if (shouldSkip(path)) continue;
            if (matchesAny(path, excludePatterns)) {
                // Keep original path + content verbatim.
                mapping.map(path, path, false);
                continue;
            }
            boolean encrypt = !encryptPatterns.isEmpty() && matchesAny(path, encryptPatterns);
            String newName = randomName(path);
            mapping.map(path, newName, encrypt);
            if (encrypt) encrypted++;
            renamed++;
        }
        KBoxLog.info(TAG, "Renamed " + renamed + " resources (" + encrypted + " encrypted)");
        return mapping;
    }

    /**
     * Returns true if the resource must be left untouched by both the renamer
     * and the encryptor. These are framework files whose names/contents the JVM
     * or container reads directly, plus the KBox-managed services entries that
     * {@code ResourceReferenceUpdater} already handles.
     */
    private boolean shouldSkip(String path) {
        if (path.equals("META-INF/MANIFEST.MF")) return true;
        if (path.startsWith("META-INF/services/")) return true;       // handled by ResourceReferenceUpdater
        if (path.startsWith("META-INF/kbox/")) return true;          // KBox internal
        if (path.startsWith("org/springframework/boot/loader/")) return true;
        // spring.factories & AutoConfiguration.imports are handled by ResourceReferenceUpdater
        // (content rewritten), but their *file name* stays unchanged.
        if (path.endsWith("spring.factories")) return true;
        if (path.endsWith("AutoConfiguration.imports")) return true;
        if (path.endsWith(".class")) return true;                     // class files handled elsewhere
        // Mixin ecosystem files: referenced by exact name in MANIFEST.MF
        // (MixinConfigs:) and @Mixin(refmap=...). Renaming these breaks
        // MixinTweaker classpath scanning.
        if (path.endsWith(".json") && (path.contains("mixins") || path.contains("refmap"))) return true;
        // Forge/Minecraft SPI service files — names are hardcoded in framework.
        if (path.endsWith(".info") && path.toLowerCase().contains("mcmod")) return true;
        return false;
    }

    /** Ant-style glob match (supports {@code *} and {@code **}). */
    private boolean matchesAny(String path, Set<String> patterns) {
        for (String p : patterns) {
            if (globMatch(p, path)) return true;
        }
        return false;
    }

    static boolean globMatch(String pattern, String path) {
        // Convert ant-style pattern to regex.
        StringBuilder regex = new StringBuilder(pattern.length() + 16);
        int i = 0;
        while (i < pattern.length()) {
            char c = pattern.charAt(i);
            if (c == '*') {
                if (i + 1 < pattern.length() && pattern.charAt(i + 1) == '*') {
                    regex.append(".*");
                    i += 2;
                    if (i < pattern.length() && pattern.charAt(i) == '/') i++;
                } else {
                    regex.append("[^/]*");
                    i++;
                }
            } else if (c == '?') {
                regex.append('.');
                i++;
            } else {
                regex.append(java.util.regex.Pattern.quote(String.valueOf(c)));
                i++;
            }
        }
        return java.util.regex.Pattern.compile(regex.toString()).matcher(path).matches();
    }

    private String randomName(String original) {
        byte[] buf = new byte[8];
        rng.nextBytes(buf);
        StringBuilder sb = new StringBuilder(RES_PREFIX.length() + 24);
        sb.append(RES_PREFIX);
        for (byte b : buf) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        String ext = extension(original);
        if (ext != null) sb.append(ext);
        else sb.append(".dat");
        return sb.toString();
    }

    private static String extension(String path) {
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        if (dot > slash && dot < path.length() - 1) {
            return path.substring(dot);
        }
        return null;
    }
}
