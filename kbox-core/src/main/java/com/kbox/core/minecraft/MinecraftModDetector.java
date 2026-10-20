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
        /** Classes whose method bodies must stay verbatim (loader bootstrap). */
        public final Set<String> bodyExcludeClasses = new HashSet<>();

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
        if (res.containsKey("mcmod.info")) {
            // Forge 1.8.9 / 1.12.2 metadata (before the mods.toml era). FML scans
            // every class for @Mod, so this era needs the same adaptation.
            return detectLegacyForge();
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
        addManifestKeepers(r);
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
        addManifestKeepers(r);
        log(r, loader == MinecraftModPresets.ModLoader.NEOFORGE ? "NeoForge" : "Forge");
        return r;
    }

    /**
     * Legacy Forge (1.8.9 / 1.12.2) metadata: {@code mcmod.info} is a JSON array
     * of objects with a {@code modid}, and FML finds the entry point by scanning
     * every class for {@code @Mod}. Keep every annotated class (the modId match
     * is only a hint — several mods ship one info file per mod).
     */
    private Result detectLegacyForge() {
        Result r = new Result(MinecraftModPresets.ModLoader.FORGE);
        r.protectedResources.add("mcmod.info");
        r.protectedResources.add("pack.mcmeta");
        // FML loads whatever class carries @Mod, so keep every annotated class.
        for (ClassNode cn : graph.getClasses().values()) {
            if (findModId(cn) != null) r.entryClasses.add(cn.name);
        }
        // The mcmod.info branch returns before the LaunchWrapper branch, so the
        // manifest-declared bootstrap classes (FMLCorePlugin / TweakClass /
        // LaunchTarget) must be kept here too. Missing this renames the coremod
        // class while FML still resolves it by the manifest name:
        //   ClassNotFoundException: net.ccbluex.liquidbounce...MixinLoader
        addManifestKeepers(r);
        log(r, "Forge (legacy mcmod.info)");
        return r;
    }

    /**
     * Keeps classes/resources named by LaunchWrapper/FML manifest attributes.
     * These are resolved by the loader <b>before</b> any mod class is defined,
     * so they can never be renamed away from the manifest value.
     */
    private void addManifestKeepers(Result r) {
        byte[] raw = graph.getManifest();
        if (raw == null) return;
        String m = new String(raw, StandardCharsets.UTF_8);
        for (String key : new String[] {"TweakClass", "FMLCorePlugin", "LaunchTarget"}) {
            String v = extractManifestValue(m, key);
            if (v == null) continue;
            for (String part : v.trim().split("[,\\s]+")) {
                if (!part.isEmpty()) {
                    addDotted(r.entryClasses, part);
                    // Bootstrap classes are resolved before any mod code runs;
                    // keep their bodies verbatim too (no VMP/JNIC/BFVM/CF).
                    r.bodyExcludeClasses.add(part.trim().replace('.', '/'));
                }
            }
        }
        for (String key : new String[] {"FMLAT", "MixinConfigs"}) {
            String v = extractManifestValue(m, key);
            if (v == null) continue;
            for (String part : v.trim().split("[,\\s]+")) {
                if (!part.isEmpty()) r.protectedResources.add(part);
            }
        }
    }

    /** Return the modId declared in an {@code @Mod(...)} annotation, or null. */
    private static String findModId(ClassNode cn) {
        List<AnnotationNode> annos = new ArrayList<>();
        if (cn.visibleAnnotations != null) annos.addAll(cn.visibleAnnotations);
        if (cn.invisibleAnnotations != null) annos.addAll(cn.invisibleAnnotations);
        for (AnnotationNode an : annos) {
            String desc = an.desc;
            if (desc.equals("Lcpw/mods/fml/common/Mod;")
                    || desc.equals("Lnet/minecraftforge/fml/common/Mod;")
                    || desc.equals("Lnet/neoforged/fml/common/Mod;")) {
                if (an.values == null) continue;
                for (int i = 0; i < an.values.size(); i += 2) {
                    Object k = an.values.get(i);
                    // Forge 1.8.9..1.20 declared @Mod(modid = "..."); NeoForge and
                    // the newer Forge use the shorthand @Mod("...") = value.
                    if (("modid".equals(k) || "value".equals(k))
                            && an.values.get(i + 1) instanceof String) {
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
        // FMLAT: the access-transformer file. Forge applies its member signatures
        // against RAW class bytes at load time, so the file MUST survive
        // byte-for-byte (name + content) — renaming it breaks every transform.
        // Note the file name is loader-specific (e.g. "liquidbounce_at.cfg"),
        // which the generic "*.accesstransformer.cfg" rule below cannot match.
        String fmlAt = extractManifestValue(manifest, "FMLAT");
        if (fmlAt != null && !fmlAt.isEmpty()) {
            r.protectedResources.add(fmlAt.trim());
        }
        // FMLCorePlugin: the core-mod bootstrap class Forge instantiates directly
        // from the manifest — renaming it fails the mod load before any class is
        // defined. Same for a directly runnable Main-Class (CLI launch path).
        String fmlCore = extractManifestValue(manifest, "FMLCorePlugin");
        if (fmlCore != null) addDotted(r.entryClasses, fmlCore);
        String fmlMod = extractManifestValue(manifest, "FMLCorePluginContainsFMLMod");
        if ("true".equalsIgnoreCase(fmlMod == null ? "" : fmlMod.trim())) {
            // Contains an @Mod class: also keep any @Mod annotation entry.
            for (ClassNode cn : graph.getClasses().values()) {
                if (findModId(cn) != null) r.entryClasses.add(cn.name);
            }
        }
        String mainClass = extractManifestValue(manifest, "Main-Class");
        if (mainClass != null && mainClass.indexOf('.') >= 0) {
            addDotted(r.entryClasses, mainClass);
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
        for (String cls : r.bodyExcludeClasses) {
            cfg.getBodyProtectExcludePrefixes().add(cls);
            // Keep the original name too, so the exclusion stays valid after the
            // renaming stage (body-exclusion lists are matched by class name).
            cfg.getKeepPrefixes().add(cls.replace('/', '.'));
        }
        // Host class transformers run for EVERY class the loader defines, including
        // KBox's own synthetic holders. If a transformer's own body is virtualized /
        // constant-obfuscated, its `transform` method references those holders; when
        // the loader then defines the holder itself, the JVM reports
        //   ClassCircularityError: com/kbox/runtime/_<holder>
        // because the transformer asks for a class that is still being defined.
        // Keep transformer implementations verbatim: they are loader infrastructure,
        // not business logic.
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.interfaces == null) continue;
            for (Object itf : cn.interfaces) {
                String s = String.valueOf(itf);
                if ("net/minecraft/launchwrapper/IClassTransformer".equals(s)
                        || "net/minecraftforge/fml/relauncher/IFMLLoadingPlugin".equals(s)
                        || "net/minecraftforge/fml/relauncher/IClassTransformer".equals(s)) {
                    cfg.getBodyProtectExcludePrefixes().add(cn.name);
                    cfg.getKeepPrefixes().add(cn.name.replace('/', '.'));
                    break;
                }
            }
        }
        // Loader metadata that must survive byte-for-byte regardless of which loader
        // was detected (mods may mix several): accessWidener / accesstransformer carry
        // member signatures matched against RAW class bytes by the runtime loader, so
        // any rename/encrypt breaks the transform; Fabric nested mods live under
        // META-INF/jars/ as whole jars (never rename/encrypt a nested jar).
        cfg.getExcludeResourcePatterns().add("*.accesswidener");
        cfg.getExcludeResourcePatterns().add("*.accesstransformer.cfg");
        cfg.getExcludeResourcePatterns().add("META-INF/jars/");
        cfg.getExcludeResourcePatterns().add("META-INF/jars/*");
        // Class encryption must be OFF for mod jars: Forge/NeoForge discover mods by
        // ASM-parsing EVERY class in the jar (ModFileScanData / @Mod scan) before the
        // JVM loads any of them. An encrypted entry is unreadable and the whole jar
        // is rejected as corrupt. Fabric does not scan, but keeping one policy for
        // all loaders avoids a build that silently only works on Fabric.
        if (cfg.isEncryptClasses()) {
            cfg.setEncryptClasses(false);
            KBoxLog.info(TAG, "Class encryption disabled: the mod loader ASM-scans raw "
                    + "class bytes for @Mod/@Mixin metadata before loading");
        }
        // K-OTP needs the JNIC native lib's build seed at run time. Mod loaders run
        // coremod transformers long before the mod's own bootstrap, and those
        // transformer classes are loaded by the host loader without the KBox native
        // registration path -> KotpRuntime.seed() throws "native seed unavailable"
        // and the whole game fails to start. Keep the Java-side protections
        // (rename/VMP/BFVM/strings/CF) but do not make method execution depend on
        // a native seed that cannot exist at transformer time.
        if (cfg.isEnableOtp()) {
            cfg.setEnableOtp(false);
            KBoxLog.warn(TAG, "K-OTP disabled for a mod jar: the native one-time-program "
                    + "seed is unavailable while the loader's transformers run");
        }
        // The BF blob loader cannot coexist with a host mod loader: FML/Fabric
        // define mod classes themselves, while the blob lives only inside
        // BfSecureLoader. Instrumented plaintext mod classes reference engine
        // classes (VmpInterpreter, JnicIndy, ...) that would then be unreachable
        // -> NoClassDefFoundError during mod construction. Keep the mod jar as a
        // normal (obfuscated) jar; BF remains available for runnable apps.
        if (cfg.isBrainfuckLoader() || cfg.isBrainfuckMcHybrid()) {
            cfg.setBrainfuckLoader(false);
            cfg.setBrainfuckMcHybrid(false);
            KBoxLog.info(TAG, "BF blob loader disabled for a mod jar: the host loader "
                    + "owns class loading, blob-only engine classes are unreachable");
        }
        // Resource renaming/encryption is incompatible with mod jars: the host
        // loader and the mod itself open resources by their original paths
        // (ResourceBundle("luckperms"), assets/**, data/**, mixin configs, ...),
        // and no guard loader sits between them and the jar. Keep resources
        // byte-identical (string encryption still hides their names in code).
        if (cfg.isObfuscateResources()) {
            cfg.setObfuscateResources(false);
            KBoxLog.info(TAG, "Resource obfuscation disabled for a mod jar: the host "
                    + "loader reads assets/data/config files by their original paths");
        }
        // VMP replaces method bodies with an interpreter-driven program. In mod
        // jars the interpreter resolves referenced classes through the mod
        // layer; framework code that compares Class objects by identity (Gson's
        // ExclusionStrategy, Dist guards, ...) can observe a different Class
        // instance and silently take the wrong branch. Keep VMP for executable
        // apps and every other protector active for mods.
        if (cfg.isEnableVmp() && !cfg.isMcForceVmp()) {
            cfg.setEnableVmp(false);
            KBoxLog.info(TAG, "VMP disabled for a mod jar: the mod layer's class "
                    + "identity/resolution semantics break interpreter-side lookups "
                    + "(set mcForceVmp=true to override)");
        } else if (cfg.isEnableVmp()) {
            KBoxLog.warn(TAG, "VMP kept ON for this mod jar (mcForceVmp=true): "
                    + "maximum strength, framework class-identity guards may misbehave");
        }
        // Anti-decompiler level 2/3 inject deliberately malformed attributes, fake
        // StackMapTables and bad method handles into a synthetic class. FML/NeoForge
        // parse EVERY class entry during mod discovery, so one unparseable entry
        // makes the loader reject the whole jar ("probably a corrupt zip").
        if (cfg.getAntiDecompilerLevel() > 0) {
            cfg.setAntiDecompilerLevel(0);
            KBoxLog.info(TAG, "Anti-decompiler disabled: malformed-attribute decoys are "
                    + "fatal to the loader's all-class ASM scan");
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

    /** "key": "value" — only matches a KEY occurrence (not a value equal to the key). */
    static String extractJsonString(String json, String key) {
        int idx = indexOfJsonKey(json, key, 0);
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

    /** Index of {@code "key"} followed (after optional whitespace) by ':', or -1.
     *  Searching for the bare quoted token is not enough: values such as
     *  {@code "environment": "server"} contain the same text as the key
     *  {@code "server"} and used to make the entrypoint parser return nothing. */
    static int indexOfJsonKey(String json, String key, int from) {
        String needle = "\"" + key + "\"";
        while (true) {
            int idx = json.indexOf(needle, from);
            if (idx < 0) return -1;
            int p = idx + needle.length();
            while (p < json.length() && Character.isWhitespace(json.charAt(p))) p++;
            if (p < json.length() && json.charAt(p) == ':') return idx;
            from = idx + needle.length();
        }
    }

    /** Extract all strings from a JSON array value for the given key. */
    static List<String> extractJsonStringArray(String json, String key) {
        List<String> out = new ArrayList<>();
        int idx = indexOfJsonKey(json, key, 0);
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