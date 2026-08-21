package com.kbox.core.minecraft;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Auto-detects the Minecraft mod loader from a jar's metadata and strips the
 * framework entry points out of the obfuscation scope.
 *
 * <p>Unlike {@link MinecraftModPresets} (which requires the user to pass
 * {@code --mc-preset}), this class inspects the input jar itself:
 * <ul>
 *   <li>{@code fabric.mod.json} → Fabric loader; keeps every {@code entrypoints}
 *       class (main / client / server / preLaunch / postInit / ...).</li>
 *   <li>{@code META-INF/neoforge.mods.toml} → NeoForge; keeps the {@code @Mod}
 *       entry class and the {@code [[mods]]} entry points.</li>
 *   <li>{@code META-INF/mods.toml} → Forge; keeps {@code @Mod} entry class.</li>
 *   <li>{@code plugin.yml} / {@code paper-plugin.yml} → Bukkit/Paper; keeps the
 *       {@code main:} class.</li>
 *   <li>{@code TweakClass:} manifest attribute → Forge LaunchWrapper; keeps the
 *       tweaker, mixin combiner and launch target.</li>
 *   <li>{@code mixins.*.json} → Mixin infrastructure; keeps the mixin package.</li>
 * </ul>
 *
 * <p>The detector only runs when {@code autoAdaptMinecraft} is enabled in the
 * config (explicit opt-in). It is additive: it merges detected entry points into
 * the existing keep-set without disabling any user-supplied rules.
 */
public final class MinecraftModDetector {

    private static final String TAG = "mc-detect";

    /** Result of detection. */
    public static final class Result {
        /** Detected loader, or {@code null} if the jar is not a Minecraft mod. */
        public final MinecraftModPresets.ModLoader loader;
        /** Internal class names discovered as loader entry points (kept). */
        public final Set<String> entryClasses = new HashSet<>();
        /** Extra keep prefixes discovered (e.g. mixin package). */
        public final Set<String> keepPrefixes = new HashSet<>();
        /** Resource paths that must never be renamed (loader metadata). */
        public final Set<String> protectedResources = new HashSet<>();

        Result(MinecraftModPresets.ModLoader loader) { this.loader = loader; }

        public boolean isMod() { return loader != null; }
    }

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public MinecraftModDetector(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /**
     * Detect the loader and collect entry points. Returns a result whose
     * {@code loader} is non-null iff a Minecraft mod loader was identified.
     */
    public Result detect() {
        Map<String, byte[]> res = graph.getResources();
        String manifest = graph.getManifest() != null
                ? new String(graph.getManifest(), StandardCharsets.UTF_8)
                : "";

        // Priority: Fabric metadata is the most specific; then NeoForge/Forge
        // toml; then Bukkit yml; then LaunchWrapper TweakClass; then Mixin.
        if (res.containsKey("fabric.mod.json")) {
            return detectFabric(res.get("fabric.mod.json"));
        }
        if (res.containsKey("META-INF/neoforge.mods.toml")) {
            return detectForgeLike(res.get("META-INF/neoforge.mods.toml"),
                    MinecraftModPresets.ModLoader.NEOFORGE);
        }
        if (res.containsKey("META-INF/mods.toml")) {
            return detectForgeLike(res.get("META-INF/mods.toml"),
                    MinecraftModPresets.ModLoader.FORGE);
        }
        if (res.containsKey("paper-plugin.yml")) {
            return detectBukkit(res.get("paper-plugin.yml"));
        }
        if (res.containsKey("plugin.yml")) {
            return detectBukkit(res.get("plugin.yml"));
        }
        if (manifest.contains("TweakClass:")) {
            return detectLaunchWrapper(manifest);
        }
        if (hasMixinConfig(res)) {
            return detectMixinOnly();
        }
        return new Result(null);
    }

    // ------------------------------------------------------------------
    // Fabric
    // ------------------------------------------------------------------

    private Result detectFabric(byte[] data) {
        Result r = new Result(MinecraftModPresets.ModLoader.FABRIC);
        r.protectedResources.add("fabric.mod.json");
        r.protectedResources.add("pack.mcmeta");
        String json = new String(data, StandardCharsets.UTF_8);
        // entrypoints: { "main": [...], "client": [...], ... }
        for (String key : new String[]{"main", "client", "server", "preLaunch",
                "postInit", "init", "modmenu"}) {
            for (String fqn : extractJsonStringArray(json, key)) {
                addDotted(r.entryClasses, fqn);
            }
        }
        // mixins: list of mixin config file names.
        for (String config : extractJsonStringArray(json, "mixins")) {
            r.protectedResources.add(config);
        }
        log(r, "Fabric");
        return r;
    }

    // ------------------------------------------------------------------
    // Forge / NeoForge
    // ------------------------------------------------------------------

    private Result detectForgeLike(byte[] data, MinecraftModPresets.ModLoader loader) {
        Result r = new Result(loader);
        r.protectedResources.add(loader == MinecraftModPresets.ModLoader.NEOFORGE
                ? "META-INF/neoforge.mods.toml"
                : "META-INF/mods.toml");
        r.protectedResources.add("META-INF/accesstransformer.cfg");
        r.protectedResources.add("pack.mcmeta");
        String json = new String(data, StandardCharsets.UTF_8);
        // mods.toml is TOML, not JSON. modId is listed as modId="xxxx".
        Set<String> modIds = extractTomlValues(json, "modId");
        // The @Mod(modId) annotated class is the entry point. Scan classes for
        // a @Mod annotation whose value matches one of the declared modIds.
        for (ClassNode cn : graph.getClasses().values()) {
            String modId = findModId(cn);
            if (modId != null && (modIds.isEmpty() || modIds.contains(modId))) {
                r.entryClasses.add(cn.name);
            }
        }
        // If no @Mod matched but modIds exist, keep the class named after the
        // modId as a fallback (common convention: package/ModId).
        if (r.entryClasses.isEmpty()) {
            for (String modId : modIds) {
                String candidate = modId.replace('-', '_');
                String internal = "com/" + candidate + "/" + candidate;
                if (graph.getClasses().containsKey(internal)) {
                    r.entryClasses.add(internal);
                }
            }
        }
        log(r, loader == MinecraftModPresets.ModLoader.NEOFORGE ? "NeoForge" : "Forge");
        return r;
    }

    /** Return the modId declared in an {@code @Mod(...)} annotation, or null. */
    private static String findModId(ClassNode cn) {
        List<AnnotationNode> annos = new ArrayList<>();
        if (cn.visibleAnnotations != null) annos.addAll(cn.visibleAnnotations);
        if (cn.invisibleAnnotations != null) annos.addAll(cn.invisibleAnnotations);
        for (AnnotationNode an : annos) {
            String desc = an.desc;
            if (desc.equals("Lnet/minecraftforge/fml/common/Mod;")
                    || desc.equals("Lnet/neoforged/fml/common/Mod;")) {
                if (an.values == null) continue;
                for (int i = 0; i < an.values.size(); i += 2) {
                    if ("value".equals(an.values.get(i)) && an.values.get(i + 1) instanceof String) {
                        return (String) an.values.get(i + 1);
                    }
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Bukkit / Paper
    // ------------------------------------------------------------------

    private Result detectBukkit(byte[] data) {
        Result r = new Result(MinecraftModPresets.ModLoader.BUKKIT);
        r.protectedResources.add("plugin.yml");
        r.protectedResources.add("paper-plugin.yml");
        String text = new String(data, StandardCharsets.UTF_8);
        String main = extractYamlValue(text, "main");
        if (main != null) addDotted(r.entryClasses, main);
        // Register commands' executor classes.
        for (String fqn : extractCommandExecutors(text)) {
            addDotted(r.entryClasses, fqn);
        }
        log(r, "Bukkit/Paper");
        return r;
    }

    // ------------------------------------------------------------------
    // LaunchWrapper (Forge legacy / Fabric legacy tweakers)
    // ------------------------------------------------------------------

    private Result detectLaunchWrapper(String manifest) {
        Result r = new Result(MinecraftModPresets.ModLoader.MIXIN);
        r.protectedResources.add("META-INF/MANIFEST.MF");
        String tweaker = extractManifestValue(manifest, "TweakClass");
        if (tweaker != null) addDotted(r.entryClasses, tweaker);
        String launchTarget = extractManifestValue(manifest, "LaunchTarget");
        if (launchTarget != null) addDotted(r.entryClasses, launchTarget);
        String mixinCombs = extractManifestValue(manifest, "MixinCompatibility");
        if (mixinCombs != null) {
            for (String part : mixinCombs.split("\\s+")) {
                if (!part.isEmpty()) r.keepPrefixes.add(part.replace('.', '/'));
            }
        }
        // The compatibility flags config often lists the mixin package.
        for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            if (e.getKey().endsWith(".json") && e.getKey().contains("mixin")) {
                r.protectedResources.add(e.getKey());
            }
        }
        log(r, "LaunchWrapper");
        return r;
    }

    // ------------------------------------------------------------------
    // Mixin-only jar
    // ------------------------------------------------------------------

    private Result detectMixinOnly() {
        Result r = new Result(MinecraftModPresets.ModLoader.MIXIN);
        for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            if (!e.getKey().endsWith(".json") || !e.getKey().contains("mixin")) continue;
            r.protectedResources.add(e.getKey());
            try {
                String json = new String(e.getValue(), StandardCharsets.UTF_8);
                String pkg = extractJsonString(json, "package");
                if (pkg != null) r.keepPrefixes.add(pkg.replace('.', '/'));
                String plugin = extractJsonString(json, "plugin");
                if (plugin != null) addDotted(r.entryClasses, plugin);
            } catch (Exception ignored) {}
        }
        log(r, "Mixin");
        return r;
    }

    private boolean hasMixinConfig(Map<String, byte[]> res) {
        for (String path : res.keySet()) {
            if (path.endsWith(".json") && path.contains("mixin")) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Apply detected rules to the config
    // ------------------------------------------------------------------

    /**
     * Merge the detection result into the config: keep discovered entry
     * classes/prefixes and protect loader metadata resources from renaming.
     */
    public void apply(Result r) {
        if (r == null || !r.isMod()) return;
        for (String entry : r.entryClasses) {
            cfg.getKeepPrefixes().add(entry.replace('/', '.'));
        }
        for (String prefix : r.keepPrefixes) {
            cfg.getKeepPrefixes().add(prefix);
        }
        for (String res : r.protectedResources) {
            cfg.getExcludeResourcePatterns().add(res);
        }
    }

    private void log(Result r, String loaderName) {
        KBoxLog.info(TAG, "Detected " + loaderName + " mod: "
                + r.entryClasses.size() + " entry classes, "
                + r.keepPrefixes.size() + " extra prefixes, "
                + r.protectedResources.size() + " protected resources");
    }

    // ------------------------------------------------------------------
    // Minimal parsers (no external JSON/YAML dependency)
    // ------------------------------------------------------------------

    /** "key": "value" at top level. */
    static String extractJsonString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        idx = json.indexOf(':', idx);
        if (idx < 0) return null;
        idx++;
        while (idx < json.length() && Character.isWhitespace(json.charAt(idx))) idx++;
        if (idx >= json.length() || json.charAt(idx) != '"') return null;
        int end = json.indexOf('"', idx + 1);
        if (end < 0) return null;
        return json.substring(idx + 1, end);
    }

    /** Extract all strings from a JSON array value for the given key. */
    static List<String> extractJsonStringArray(String json, String key) {
        List<String> out = new ArrayList<>();
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return out;
        idx = json.indexOf(':', idx);
        if (idx < 0) return out;
        idx++;
        while (idx < json.length() && Character.isWhitespace(json.charAt(idx))) idx++;
        if (idx >= json.length() || json.charAt(idx) != '[') return out;
        idx++;
        // Iterate comma-separated strings until closing ']'.
        StringBuilder cur = new StringBuilder();
        boolean inString = false;
        for (; idx < json.length(); idx++) {
            char c = json.charAt(idx);
            if (c == '"') {
                if (inString) {
                    if (cur.length() > 0) out.add(cur.toString());
                    cur.setLength(0);
                    inString = false;
                } else {
                    inString = true;
                }
            } else if (inString) {
                cur.append(c);
            } else if (c == ']') {
                break;
            }
        }
        return out;
    }

    /** Extract a dotted class name from a JSON string literal (also handles nested objects). */
    private static void addDotted(Set<String> set, String raw) {
        if (raw == null || raw.isEmpty()) return;
        String s = raw.trim();
        if (s.isEmpty()) return;
        // Handle {"adapter":"...","value":"com.X"} objects by taking 'value'.
        if (s.startsWith("{")) {
            String v = extractJsonString(s, "value");
            if (v != null) s = v;
        }
        if (s.isEmpty()) return;
        // A real class FQN must be dotted. Single-segment values (e.g. an
        // adapter name like "default") are not entry-point classes.
        if (s.indexOf('.') < 0) return;
        set.add(s.replace('.', '/'));
    }

    /** Extract simple TOML key="value" pairs. */
    static Set<String> extractTomlValues(String text, String key) {
        Set<String> out = new HashSet<>();
        for (String line : text.split("\\r?\\n")) {
            String t = line.trim();
            if (t.startsWith("[") || t.startsWith("#")) continue;
            int eq = t.indexOf('=');
            if (eq < 0) continue;
            String k = t.substring(0, eq).trim();
            if (!k.equals(key)) continue;
            String v = t.substring(eq + 1).trim();
            if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
                v = v.substring(1, v.length() - 1);
            }
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }

    /** Extract a YAML scalar value for the given top-level key. */
    static String extractYamlValue(String text, String key) {
        for (String line : text.split("\\r?\\n")) {
            String t = line.trim();
            if (t.startsWith("#")) continue;
            if (t.startsWith(key + ":")) {
                String v = t.substring(key.length() + 1).trim();
                if (v.isEmpty()) continue;
                if (v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length() - 1);
                return v;
            }
        }
        return null;
    }

    /** Extract command executors from a Bukkit plugin.yml "commands:" block. */
    static List<String> extractCommandExecutors(String text) {
        List<String> out = new ArrayList<>();
        String[] lines = text.split("\\r?\\n");
        boolean inCommands = false;
        for (String raw : lines) {
            String t = raw.trim();
            if (t.equals("commands:")) { inCommands = true; continue; }
            if (inCommands && !t.isEmpty() && !t.startsWith("-") && !t.contains(":")) {
                inCommands = false;
            }
            if (inCommands && t.startsWith("executor:")) {
                String v = t.substring("executor:".length()).trim();
                if (!v.isEmpty()) out.add(v);
            }
        }
        return out;
    }

    /** Extract a manifest attribute value. */
    static String extractManifestValue(String manifest, String key) {
        for (String line : manifest.split("\\r?\\n")) {
            String t = line.trim();
            if (t.startsWith(key + ":")) {
                return t.substring(key.length() + 1).trim();
            }
        }
        return null;
    }
}