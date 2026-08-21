package com.kbox.core.config;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Determines whether a class or resource should be obfuscated based on the
 * configured scope and patterns. Supports glob-style patterns:
 * <ul>
 *   <li>{@code **} matches any number of path segments (crosses {@code /})</li>
 *   <li>{@code *}  matches any characters except {@code /}</li>
 *   <li>{@code ?}  matches a single character except {@code /}</li>
 * </ul>
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code "com/example/**"} matches all classes under {@code com.example}
 *       and its subpackages</li>
 *   <li>{@code "com/example/*"} matches classes directly in {@code com.example}</li>
 *   <li>{@code "com/example/MyClass"} matches exactly that class</li>
 *   <li>{@code "**&#47;api&#47;**"} matches any class in any package containing an
 *       {@code api} subpackage</li>
 * </ul>
 *
 * <p>The selector is stateless; compiled glob patterns are cached internally
 * so repeated lookups for the same pattern are cheap. Safe to call from
 * multiple threads.
 */
public final class FileSelector {

    private FileSelector() { /* no instances */ }

    /** Cache of compiled glob -> regex Pattern to avoid recompiling on every lookup. */
    private static final ConcurrentHashMap<String, Pattern> PATTERN_CACHE = new ConcurrentHashMap<>();

    /**
     * Returns {@code true} if the given class (internal name, e.g.
     * {@code "com/example/Foo"}) should be obfuscated according to the
     * config's scope and patterns.
     *
     * <p>Decision matrix:
     * <ul>
     *   <li>{@link ProtectionConfig.ObfuscationScope#ALL ALL}: always {@code true}
     *       (patterns ignored).</li>
     *   <li>{@link ProtectionConfig.ObfuscationScope#SELECTIVE SELECTIVE}:
     *       {@code true} only if the name matches an include pattern and does
     *       not match any exclude pattern.</li>
     *   <li>{@link ProtectionConfig.ObfuscationScope#EXCLUDE EXCLUDE}:
     *       {@code true} unless the name matches an exclude pattern.</li>
     * </ul>
     */
    public static boolean shouldObfuscateClass(String internalName, ProtectionConfig cfg) {
        if (internalName == null || cfg == null) return true;
        ProtectionConfig.ObfuscationScope scope = cfg.getObfuscationScope();
        if (scope == null) scope = ProtectionConfig.ObfuscationScope.ALL;

        switch (scope) {
            case ALL:
                return true;
            case SELECTIVE:
                return matchesAny(internalName, cfg.getIncludePatterns())
                        && !matchesAny(internalName, cfg.getExcludePatterns());
            case EXCLUDE:
                return !matchesAny(internalName, cfg.getExcludePatterns());
            default:
                return true;
        }
    }

    /**
     * Returns {@code true} if the given resource path should be obfuscated.
     *
     * <p>The existing {@link ProtectionConfig#getExcludeResourcePatterns()
     * excludeResourcePatterns} and the secondary
     * {@link ProtectionConfig#getExcludeResourcePatterns2() excludeResourcePatterns2}
     * sets are honoured in <em>all</em> scopes (they describe resources that
     * must never be touched). The {@link ProtectionConfig.ObfuscationScope
     * scope} then controls the include/selective behaviour on top of that
     * baseline:
     * <ul>
     *   <li>{@link ProtectionConfig.ObfuscationScope#ALL ALL}: obfuscate unless
     *       excluded.</li>
     *   <li>{@link ProtectionConfig.ObfuscationScope#SELECTIVE SELECTIVE}:
     *       obfuscate only if it matches an include resource pattern and is not
     *       excluded.</li>
     *   <li>{@link ProtectionConfig.ObfuscationScope#EXCLUDE EXCLUDE}:
     *       obfuscate unless excluded.</li>
     * </ul>
     */
    public static boolean shouldObfuscateResource(String resourcePath, ProtectionConfig cfg) {
        if (resourcePath == null || cfg == null) return true;
        ProtectionConfig.ObfuscationScope scope = cfg.getObfuscationScope();
        if (scope == null) scope = ProtectionConfig.ObfuscationScope.ALL;

        // The two exclude-resource sets always apply, regardless of scope.
        boolean excluded = matchesAny(resourcePath, cfg.getExcludeResourcePatterns())
                || matchesAny(resourcePath, cfg.getExcludeResourcePatterns2());
        if (excluded) return false;

        switch (scope) {
            case ALL:
            case EXCLUDE:
                return true;
            case SELECTIVE:
                return matchesAny(resourcePath, cfg.getIncludeResourcePatterns());
            default:
                return true;
        }
    }

    /**
     * Returns {@code true} if {@code path} matches at least one of the supplied
     * glob {@code patterns}. An empty or {@code null} pattern set never matches.
     */
    private static boolean matchesAny(String path, Set<String> patterns) {
        if (patterns == null || patterns.isEmpty()) return false;
        for (String p : patterns) {
            if (p == null || p.isEmpty()) continue;
            Pattern regex = compilePattern(p);
            if (regex.matcher(path).matches()) return true;
        }
        return false;
    }

    /** Compile (and cache) the regex equivalent of a glob pattern. */
    private static Pattern compilePattern(String glob) {
        Pattern cached = PATTERN_CACHE.get(glob);
        if (cached != null) return cached;
        Pattern compiled = Pattern.compile(globToRegex(glob));
        Pattern prev = PATTERN_CACHE.putIfAbsent(glob, compiled);
        // Another thread may have won the race; use the canonical instance.
        return prev != null ? prev : compiled;
    }

    /**
     * Converts a glob pattern to a Java regex string.
     * <ul>
     *   <li>{@code **} &rarr; {@code .*} (matches across path separators)</li>
     *   <li>{@code *}  &rarr; {@code [^/]*} (matches within a single package)</li>
     *   <li>{@code ?}  &rarr; {@code [^/]} (single char, not a separator)</li>
     *   <li>every other character is escaped if it is a regex metacharacter</li>
     * </ul>
     *
     * <p>The resulting regex is intended to be used with full-match semantics
     * (i.e. {@link java.util.regex.Matcher#matches()} or anchored with
     * {@code ^...$}).
     */
    static String globToRegex(String pattern) {
        StringBuilder sb = new StringBuilder(pattern.length() + 16);
        int i = 0;
        int len = pattern.length();
        while (i < len) {
            char c = pattern.charAt(i);
            if (c == '*') {
                if (i + 1 < len && pattern.charAt(i + 1) == '*') {
                    // ** matches any sequence including path separators.
                    sb.append(".*");
                    i += 2;
                } else {
                    // * matches within a single path segment (no '/').
                    sb.append("[^/]*");
                    i++;
                }
            } else if (c == '?') {
                sb.append("[^/]");
                i++;
            } else if (isRegexMeta(c)) {
                sb.append('\\').append(c);
                i++;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    /** True for characters that have special meaning in a Java regex. */
    private static boolean isRegexMeta(char c) {
        return ".\\+()|^${}[]".indexOf(c) >= 0;
    }
}
