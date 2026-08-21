package com.kbox.core.minecraft;

import com.kbox.core.config.ProtectionConfig;

/**
 * Preset keep-rule configurations for Minecraft mod loaders.
 *
 * <p>Minecraft mods use heavy reflection, annotation-based registration, and
 * mixin transformations that require specific classes to be preserved. This
 * class provides ready-to-use configurations for:</p>
 * <ul>
 *   <li>NeoForge (1.20+)</li>
 *   <li>Forge (1.16-1.20)</li>
 *   <li>Fabric (1.14+)</li>
 *   <li>Bukkit/Spigot/Paper plugins</li>
 *   <li>Mixin (SpongePowered Mixin)</li>
 * </ul>
 *
 * <p>Typical usage:</p>
 * <pre>{@code
 * ProtectionConfig cfg = MinecraftModPresets.getConfigPresets(ModLoader.NEOFORGE);
 * // user then adds their own @Mod entry-point class:
 * cfg.getKeepPrefixes().add("com.example.mymod.");
 * }</pre>
 *
 * <p>Or apply to an existing config in-place:</p>
 * <pre>{@code
 * MinecraftModPresets.applyPreset(cfg, ModLoader.FABRIC);
 * }</pre>
 */
public final class MinecraftModPresets {

    /** Supported Minecraft mod loaders / plugin platforms. */
    public enum ModLoader {
        NEOFORGE,
        FORGE,
        FABRIC,
        BUKKIT,
        MIXIN
    }

    // Private constructor - utility class
    private MinecraftModPresets() {}

    /**
     * Apply preset keep rules for the specified mod loader to the config.
     * This adds keep prefixes, keep members, and excludes specific
     * resources from obfuscation. Strength knobs are clamped to safe
     * levels that won't break mod loading or mixin transformation.
     *
     * <p>The config is modified in-place. Common keep prefixes (Minecraft,
     * Mojang, JVM core) are always added first, followed by loader-specific
     * rules.</p>
     *
     * @param cfg    the config to modify in-place (must not be null)
     * @param loader the target mod loader (must not be null)
     */
    public static void applyPreset(ProtectionConfig cfg, ModLoader loader) {
        // Common keep prefixes shared by every Minecraft target.
        for (String p : getCommonKeepPrefixes()) {
            cfg.getKeepPrefixes().add(p);
        }

        switch (loader) {
            case NEOFORGE:
                applyNeoForge(cfg);
                break;
            case FORGE:
                applyForge(cfg);
                break;
            case FABRIC:
                applyFabric(cfg);
                break;
            case BUKKIT:
                applyBukkit(cfg);
                break;
            case MIXIN:
                applyMixin(cfg);
                break;
            default:
                throw new IllegalArgumentException("Unknown mod loader: " + loader);
        }
    }

    /**
     * Build a fresh {@link ProtectionConfig} pre-populated with the keep
     * rules, resource exclusions and safe strength levels for the given
     * mod loader.
     *
     * <p>The returned config uses KBox's default toggles (rename, string
     * encryption, control-flow obfuscation enabled; class encryption / VMP /
     * JNIC off). Callers may further customise it before passing it to the
     * obfuscator pipeline.</p>
     *
     * @param loader the target mod loader (must not be null)
     * @return a new, independent config with the preset applied
     */
    public static ProtectionConfig getConfigPresets(ModLoader loader) {
        ProtectionConfig cfg = new ProtectionConfig();
        applyPreset(cfg, loader);
        return cfg;
    }

    // ------------------------------------------------------------------
    // Common rules
    // ------------------------------------------------------------------

    /**
     * Return the common keep prefixes for all mod loaders. These cover
     * Minecraft &amp; Mojang classes (which must never be renamed because the
     * game and its mappings reference them), the JVM core, the crypto
     * package used by the KBox runtime, and the standard annotation types
     * that mods rely on for registration.
     */
    private static String[] getCommonKeepPrefixes() {
        return new String[] {
            // Entry points / game classes - never rename
            "net.minecraft.",           // MC classes - never rename
            "com.mojang.",              // Mojang libraries
            // JVM & standard library
            "java.lang.",               // JVM core
            "javax.crypto.",            // Crypto (used by KBox runtime)
            // Annotation types used by mods
            "java.lang.annotation.",
        };
    }

    // ------------------------------------------------------------------
    // NeoForge (1.20+)
    // ------------------------------------------------------------------

    private static void applyNeoForge(ProtectionConfig cfg) {
        for (String p : getNeoForgeKeepPrefixes()) {
            cfg.getKeepPrefixes().add(p);
        }
        for (String r : getNeoForgeKeepResources()) {
            cfg.getExcludeResourcePatterns().add(r);
        }
        // Weaker control flow: MC's code is complex and aggressive CF
        // transforms can trip up the mod loader's verifier.
        cfg.setControlFlowStrength(1);
        capAntiDecompiler(cfg, 2);
    }

    /**
     * NeoForge-specific keep prefixes. The user is still expected to add
     * their own {@code @Mod} entry-point class via {@code keepPrefixes}.
     */
    private static String[] getNeoForgeKeepPrefixes() {
        return new String[] {
            "net.neoforged.",            // NeoForge API
            "net.neoforged.fml.",        // FML loader
            "net.neoforged.neoforge.",   // NeoForge core
            "cpw.mods.bootstraplauncher.", // Bootstrap launcher
        };
    }

    private static String[] getNeoForgeKeepResources() {
        return new String[] {
            // Specific files that must be kept untouched
            "META-INF/mods.toml",
            "META-INF/neoforge.mods.toml",
            "pack.mcmeta",
            "**/accesstransformer.cfg",
            "**/coremods.json",
            // Glob exclusions
            "*.toml",                    // mods.toml and other TOML configs
            "accesstransformer.cfg",     // AT files at any path
        };
    }

    // ------------------------------------------------------------------
    // Forge (1.16-1.20)
    // ------------------------------------------------------------------

    private static void applyForge(ProtectionConfig cfg) {
        for (String p : getForgeKeepPrefixes()) {
            cfg.getKeepPrefixes().add(p);
        }
        for (String r : getForgeKeepResources()) {
            cfg.getExcludeResourcePatterns().add(r);
        }
        cfg.setControlFlowStrength(1);
        capAntiDecompiler(cfg, 2);
    }

    private static String[] getForgeKeepPrefixes() {
        return new String[] {
            "net.minecraftforge.",       // Forge API + core
            "cpw.mods.",                 // FML / bootstrap launcher
        };
    }

    private static String[] getForgeKeepResources() {
        return new String[] {
            // Specific files
            "META-INF/mods.toml",
            "pack.mcmeta",
            "mcmod.info",
            "**/accesstransformer.cfg",
            // Glob exclusions
            "*.toml",                    // mods.toml
            "mcmod.info",
            "*.cfg",                     // AT / coremod config files
        };
    }

    // ------------------------------------------------------------------
    // Fabric (1.14+)
    // ------------------------------------------------------------------

    private static void applyFabric(ProtectionConfig cfg) {
        for (String p : getFabricKeepPrefixes()) {
            cfg.getKeepPrefixes().add(p);
        }
        for (String r : getFabricKeepResources()) {
            cfg.getExcludeResourcePatterns().add(r);
        }
        cfg.setControlFlowStrength(1);
        capAntiDecompiler(cfg, 2);
    }

    private static String[] getFabricKeepPrefixes() {
        return new String[] {
            "net.fabricmc.",             // Fabric loader + API
            "org.spongepowered.asm.mixin.", // Mixin (bundled with Fabric)
        };
    }

    private static String[] getFabricKeepResources() {
        return new String[] {
            "fabric.mod.json",           // Fabric mod metadata
            "pack.mcmeta",               // Resource pack metadata
            "**/mixins/*.json",          // Mixin config files
            "*.mixins.json",             // Mixin config (any path)
        };
    }

    // ------------------------------------------------------------------
    // Bukkit / Spigot / Paper
    // ------------------------------------------------------------------

    private static void applyBukkit(ProtectionConfig cfg) {
        for (String p : getBukkitKeepPrefixes()) {
            cfg.getKeepPrefixes().add(p);
        }
        for (String r : getBukkitKeepResources()) {
            cfg.getExcludeResourcePatterns().add(r);
        }
        // Bukkit plugins are simpler than full mods; slightly stronger CF
        // is tolerated.
        cfg.setControlFlowStrength(2);
        capAntiDecompiler(cfg, 2);
    }

    private static String[] getBukkitKeepPrefixes() {
        return new String[] {
            "org.bukkit.",               // Bukkit API
            "net.md_5.",                 // BungeeCord / Spigot
            "com.google.gson.",          // Gson (used by config serialisation)
        };
    }

    private static String[] getBukkitKeepResources() {
        return new String[] {
            "plugin.yml",                // Spigot/Bukkit plugin descriptor
            "paper-plugin.yml",          // Paper plugin descriptor
            "config.yml",                // Default config
            "*.yml",                     // Bukkit config files
        };
    }

    // ------------------------------------------------------------------
    // Mixin (SpongePowered Mixin)
    // ------------------------------------------------------------------

    /**
     * Apply Mixin-specific keep rules.
     *
     * <p><b>Important:</b> Mixin classes and their targets are extremely
     * sensitive to renaming:</p>
     * <ul>
     *   <li>Mixin JSON config files reference target class names (often by
     *       their SRG/intermediary obfuscated names); renaming the targets
     *       breaks the references silently.</li>
     *   <li>Mixin target fields &amp; methods are looked up by name at
     *       application time; renaming them silently breaks the mixin.</li>
     *   <li>The {@code @Mixin} annotation type and the entire
     *       {@code org.spongepowered.asm.*} infrastructure must be kept.</li>
     * </ul>
     *
     * <p>This preset keeps the Mixin infrastructure packages and the
     * annotation type. The user's own <em>mixin classes</em> (the classes
     * annotated with {@code @Mixin}) should be added to
     * {@code cfg.getKeepPrefixes()} manually, e.g.
     * {@code "com.example.mymod.mixins."}. Mixin <em>target</em> classes
     * are typically {@code net.minecraft.*} and are already covered by the
     * common prefixes, but any custom targets should be added explicitly.</p>
     *
     * <p>KBox's reflection scanner will additionally discover
     * {@code Class.forName} / reflective lookups inside mixin classes and
     * seed the keep-set, but it does not specifically detect the
     * {@code @Mixin} annotation, so explicit keep prefixes are strongly
     * recommended.</p>
     */
    private static void applyMixin(ProtectionConfig cfg) {
        for (String p : getMixinKeepPrefixes()) {
            cfg.getKeepPrefixes().add(p);
        }
        for (String r : getMixinKeepResources()) {
            cfg.getExcludeResourcePatterns().add(r);
        }
        // Mixin code is the most fragile: control flow transforms can
        // change method bodies that the mixin processor inspects.
        cfg.setControlFlowStrength(1);
        // Anti-decompiler transforms that edit constant pools or inner-class
        // attributes can corrupt the mixin JSON -> class references.
        capAntiDecompiler(cfg, 1);
    }

    private static String[] getMixinKeepPrefixes() {
        return new String[] {
            "org.spongepowered.asm.mixin.", // Mixin core + annotations
            "org.spongepowered.asm.",       // ASM bridge / signing / util
            // The @Mixin annotation type itself. The package prefix above
            // already covers it; listed explicitly for documentation.
            "org.spongepowered.asm.mixin.Mixin",
        };
    }

    private static String[] getMixinKeepResources() {
        return new String[] {
            "**/mixins/*.json",          // Mixin config files
            "*.mixins.json",             // Mixin config (any path)
        };
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Cap the anti-decompiler level at {@code max} without raising it.
     * This protects fragile mod-loading / mixin code from overly aggressive
     * anti-decompiler transforms (constant-pool bombs, exception-table
     * bombs, InnerClasses cycles) while still respecting the user's intent
     * if they chose a lower level.
     */
    private static void capAntiDecompiler(ProtectionConfig cfg, int max) {
        if (cfg.getAntiDecompilerLevel() > max) {
            cfg.setAntiDecompilerLevel(max);
        }
    }
}
