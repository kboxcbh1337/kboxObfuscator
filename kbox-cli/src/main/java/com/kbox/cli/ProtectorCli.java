package com.kbox.cli;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.controlflow.ControlFlowObfuscator;
import com.kbox.core.log.KBoxLog;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Command-line entry point. Usage:
 * <pre>
 *   java -jar kbox-protector.jar --input app.jar --output protected/app.jar
 *                                [--config kbox.conf] [--gui] [--verbose]
 * </pre>
 *
 * Flags:
 * <ul>
 *   <li>{@code --input PATH} — input jar (plain or Spring Boot fat jar)</li>
 *   <li>{@code --output PATH} — output jar path</li>
 *   <li>{@code --config PATH} — protection config file (optional; defaults applied)</li>
 *   <li>{@code --gui}        — launch the Swing UI instead of running headless</li>
 *   <li>{@code --verbose}    — enable DEBUG logging (full progress + stack traces)</li>
 *   <li>{@code --debug-cf}   — per-file control-flow debug to stdout (always visible)</li>
 * </ul>
 *
 * <p>When run without {@code --gui}, a CLI progress bar is printed to stderr
 * showing the current stage and percentage. The detailed log goes to stdout.
 */
public final class ProtectorCli {

    public static void main(String[] args) {
        String in = null, out = null, cfgPath = null;
        String mappingPath = null;
        String mcPreset = null;
        boolean autoMc = false;
        boolean gui = false, verbose = false, debugCf = false;
        java.util.List<String> includePatterns = new java.util.ArrayList<>();
        java.util.List<String> excludePatterns = new java.util.ArrayList<>();
        String scope = null;
        // ProGuard-style flags collected here, applied to cfg after loading.
        java.util.List<String> keepSpecs = new java.util.ArrayList<>();
        java.util.List<String> keepMemberSpecs = new java.util.ArrayList<>();
        java.util.List<String> keepAttrs = new java.util.ArrayList<>();
        java.util.List<String> libraryPrefixes = new java.util.ArrayList<>();
        java.util.List<String> userPrefixes = new java.util.ArrayList<>();
        boolean dontWarn = false, dontNote = false;
        boolean dontObfuscate = false, dontOptimize = false;
        Boolean useDefaultLibPrefixes = null;
        boolean neverFail = true; // safe default
        String logFile = null;    // optional UTF-8 log tap (fixes console mojibake)
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--input": case "-i": in = next(args, i++); break;
                case "--output": case "-o": out = next(args, i++); break;
                case "--config": case "-c": cfgPath = next(args, i++); break;
                case "--mapping": case "-mapping": mappingPath = next(args, i++); break;
                case "--gui": gui = true; break;
                case "--verbose": case "-v": verbose = true; break;
                case "--debug-cf": debugCf = true; break;
                case "--mc-preset": mcPreset = next(args, i++); break;
                case "--auto-mc": autoMc = true; break;
                case "--include": includePatterns.add(next(args, i++)); break;
                case "--exclude": excludePatterns.add(next(args, i++)); break;
                case "--scope": scope = next(args, i++); break;
                case "--log": case "--log-file": logFile = next(args, i++); break;
                // ---- ProGuard-style adaptive flags ----
                case "-keep": case "--keep":
                    keepSpecs.add(next(args, i++)); break;
                case "-keepclassmembers": case "--keepclassmembers":
                    keepMemberSpecs.add(next(args, i++)); break;
                case "-keepattributes": case "--keepattributes":
                    keepAttrs.add(next(args, i++)); break;
                case "-libraryjars": case "--libraryjars":
                    // Comma-separated list of library package prefixes to add.
                    libraryPrefixes.add(next(args, i++)); break;
                case "-userprefix": case "--userprefix":
                    // Comma-separated list of user-code prefixes (overrides library).
                    userPrefixes.add(next(args, i++)); break;
                case "-dontwarn": case "--dontwarn":
                    dontWarn = true; break;
                case "-dontnote": case "--dontnote":
                    dontNote = true; break;
                case "-dontobfuscate": case "--dontobfuscate":
                    dontObfuscate = true; break;
                case "-dontoptimize": case "--dontoptimize":
                    dontOptimize = true; break;
                case "-dontskipnonpubliclibraryclasses": case "--dontskipnonpubliclibraryclasses":
                    // No-op in KBox: we never skip library classes by default.
                    // The flag is accepted for ProGuard config compatibility.
                    break;
                case "-neverfail": case "--neverfail":
                    neverFail = bool(next(args, i++)); break;
                case "-useDefaultLibraryPrefixes": case "--useDefaultLibraryPrefixes":
                    useDefaultLibPrefixes = bool(next(args, i++)); break;
                case "--list-presets": listPresets(); return;
                case "--help": case "-h": printHelp(); return;
                default:
                    System.err.println("Unknown argument: " + args[i]);
                    printHelp();
                    System.exit(2);
            }
        }
        // Enable control-flow per-file debug output to stdout (works in both GUI and CLI mode).
        ControlFlowObfuscator.setVerboseCf(debugCf);

        if (gui) {
            // Launch GUI directly (kbox-gui is now a dependency of kbox-cli).
            try {
                Class<?> guiCls = Class.forName("com.kbox.gui.ProtectorGui");
                guiCls.getMethod("launch", String.class, String.class, String.class, boolean.class)
                        .invoke(null, in, out, cfgPath, verbose);
            } catch (Exception e) {
                System.err.println("GUI unavailable: " + e.getMessage() + " (run without --gui)");
                System.exit(2);
            }
            return;
        }
        if (in == null || out == null) {
            printHelp();
            System.exit(2);
            return;
        }
        if (verbose) KBoxLog.setLevel(KBoxLog.LEVEL_DEBUG);
        // UTF-8 file tap: decouples the log correctness from the console's
        // code page. Without this, Chinese/multibyte logs render as mojibake
        // in Windows PowerShell (which decodes UTF-8 as the local GBK codepage).
        if (logFile != null && !logFile.isEmpty()) {
            KBoxLog.setFile(java.nio.file.Paths.get(logFile));
        }

        // Install CLI progress bar listener.
        if (!verbose) {
            KBoxLog.setListener(new KBoxLog.ProgressListener() {
                private int lastPercent = -1;
                @Override public void onStage(int stage, int total, String name) {
                    System.err.print("\r\033[K[Stage " + stage + "/" + total + "] " + name + "...");
                    System.err.flush();
                    lastPercent = -1;
                }
                @Override public void onProgress(int percent, String detail) {
                    if (percent != lastPercent) {
                        System.err.print("\r\033[K  [" + percent + "%] " + detail);
                        System.err.flush();
                        lastPercent = percent;
                    }
                }
                @Override public void onComplete(String summary) {
                    System.err.println("\r\033[K" + summary);
                    System.err.flush();
                }
            });
        }

        try {
            ProtectionConfig cfg = ConfigLoader.load(cfgPath == null ? null : Paths.get(cfgPath));
            // --mapping overrides any mappingFile from the config file.
            if (mappingPath != null) cfg.setMappingFile(mappingPath);
            // Apply Minecraft mod preset if requested.
            if (mcPreset != null) {
                applyMcPreset(cfg, mcPreset);
            }
            // Enable auto-adaptation of Minecraft mods (loader detection from
            // the jar metadata). Explicit opt-in via --auto-mc.
            if (autoMc) {
                cfg.setAutoAdaptMinecraft(true);
            }
            // Apply fine-grained file selection flags.
            if (scope != null) {
                cfg.setObfuscationScope(ProtectionConfig.ObfuscationScope.valueOf(scope.toUpperCase()));
            }
            for (String p : includePatterns) cfg.getIncludePatterns().add(p);
            for (String p : excludePatterns) cfg.getExcludePatterns().add(p);

            // ---- Apply ProGuard-style adaptive flags ----
            // -keep: treat as keep prefix (class or package).
            for (String spec : keepSpecs) {
                cfg.getKeepPrefixes().add(spec.replace('/', '.'));
            }
            // -keepclassmembers: "owner#name#desc" spec -> keepMembers.
            for (String spec : keepMemberSpecs) {
                cfg.getKeepMembers().add(spec);
            }
            // -keepattributes: comma-separated attribute names.
            for (String a : keepAttrs) {
                for (String part : a.split(",")) {
                    String t = part.trim();
                    if (!t.isEmpty()) cfg.getKeepAttributes().add(t);
                }
            }
            // -libraryjars: add library package prefixes (slashed form).
            for (String p : libraryPrefixes) {
                for (String part : p.split(",")) cfg.getLibraryClassifier().addLibraryPrefix(part.trim());
            }
            // -userprefix: user-code prefixes that override library classification.
            for (String p : userPrefixes) {
                for (String part : p.split(",")) cfg.getLibraryClassifier().addUserPrefix(part.trim());
            }
            if (useDefaultLibPrefixes != null) {
                cfg.getLibraryClassifier().setUseDefaultPrefixes(useDefaultLibPrefixes);
                if (!useDefaultLibPrefixes) cfg.getLibraryClassifier().clearDefaults();
            }
            cfg.setNeverFail(neverFail);
            if (dontWarn) cfg.setSuppressWarnings(true);
            if (dontNote) cfg.setQuiet(true);
            if (dontObfuscate) cfg.setRenameIdentifiers(false);
            if (dontOptimize) {
                // In KBox "optimization" maps to control-flow obfuscation.
                cfg.setObfuscateControlFlow(false);
            }

            Path workDir = Paths.get(out).getParent() == null
                    ? Paths.get(".")
                    : Paths.get(out).getParent().resolve("kbox-work");
            new ProtectionPipeline(Paths.get(in), Paths.get(out), cfg, workDir).run();
        } catch (Exception e) {
            KBoxLog.error("cli", "Protection failed", e);
            System.exit(1);
        }
    }

    private static boolean bool(String v) {
        return "true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v);
    }

    private static String next(String[] args, int i) {
        if (i + 1 >= args.length) {
            System.err.println("Missing value for " + args[i]);
            System.exit(2);
        }
        return args[i + 1];
    }

    /** Apply a Minecraft mod-loader preset by name. */
    private static void applyMcPreset(ProtectionConfig cfg, String name) {
        try {
            com.kbox.core.minecraft.MinecraftModPresets.ModLoader loader =
                    com.kbox.core.minecraft.MinecraftModPresets.ModLoader.valueOf(name.toUpperCase());
            com.kbox.core.minecraft.MinecraftModPresets.applyPreset(cfg, loader);
            System.out.println("[kbox] Applied Minecraft preset: " + name);
        } catch (IllegalArgumentException e) {
            System.err.println("Unknown Minecraft preset: " + name
                    + " (valid: NEOFORGE, FORGE, FABRIC, BUKKIT, MIXIN)");
            System.exit(2);
        }
    }

    /** List available Minecraft mod presets. */
    private static void listPresets() {
        System.out.println("Available Minecraft mod presets:");
        for (com.kbox.core.minecraft.MinecraftModPresets.ModLoader l :
                com.kbox.core.minecraft.MinecraftModPresets.ModLoader.values()) {
            System.out.println("  " + l.name());
        }
    }

    private static void printHelp() {
        System.out.println("KBox Obfuscator — ZKM-level + JNIC + VMP Java protection");
        System.out.println("Usage: java -jar kbox-protector.jar --input <in.jar> --output <out.jar>");
        System.out.println("                                [--config kbox.conf] [--gui] [--verbose] [--debug-cf]");
        System.out.println("                                [--mc-preset NEOFORGE|FORGE|FABRIC|BUKKIT|MIXIN]");
        System.out.println("                                [--scope ALL|SELECTIVE|EXCLUDE]");
        System.out.println("                                [--include <pattern>] [--exclude <pattern>]");
        System.out.println("                                [ProGuard-style adaptive flags]");
        System.out.println("                                [--list-presets]");
        System.out.println();
        System.out.println("Flags:");
        System.out.println("  --input, -i PATH        Input jar (plain or Spring Boot fat jar)");
        System.out.println("  --output, -o PATH       Output jar path");
        System.out.println("  --mapping PATH          Write a ProGuard-compatible deobfuscation mapping file");
        System.out.println("                          (reverse obfuscation for stack traces; overrides mappingFile in config)");
        System.out.println("  --config, -c PATH       Protection config file (optional)");
        System.out.println("  --gui                   Launch the Swing UI (built-in, no separate jar needed)");
        System.out.println("  --verbose, -v           Enable DEBUG logging (full progress + stack traces)");
        System.out.println("  --debug-cf              Per-file control-flow debug to stdout (always visible)");
        System.out.println("  --log PATH              Also write every log line to PATH as UTF-8");
        System.out.println("                          (fixes Chinese mojibake in GBK consoles)");
        System.out.println();
        System.out.println("  --mc-preset NAME         Apply a Minecraft mod-loader preset:");
        System.out.println("                           NEOFORGE, FORGE, FABRIC, BUKKIT, MIXIN");
        System.out.println("  --auto-mc                Auto-detect the Minecraft mod loader from the jar");
        System.out.println("                           metadata (fabric.mod.json / mods.toml / plugin.yml /");
        System.out.println("                           TweakClass / mixins.json) and keep its entry points.");
        System.out.println("  --scope SCOPE            Obfuscation scope (default: ALL):");
        System.out.println("                           ALL = obfuscate everything");
        System.out.println("                           SELECTIVE = only obfuscate files matching --include");
        System.out.println("                           EXCLUDE = obfuscate all except files matching --exclude");
        System.out.println("  --include PATTERN        Class pattern to include (repeatable).");
        System.out.println("                           e.g. com/example/** com/foo/Bar");
        System.out.println("  --exclude PATTERN        Class pattern to exclude (repeatable).");
        System.out.println("  --list-presets           List available Minecraft mod presets");
        System.out.println("  --help, -h               Show this help message");
        System.out.println();
        System.out.println("ProGuard-style adaptive flags (for compatibility & fine-grained control):");
        System.out.println("  -keep SPEC               Keep a class/package (e.g. com.example.api. or com.example.Main)");
        System.out.println("                           repeatable; accepts dotted or slashed form");
        System.out.println("  -keepclassmembers SPEC   Keep specific members: owner#name#desc");
        System.out.println("                           e.g. com.foo.Bar#valueOf#(Ljava/lang/String;)Lcom/foo/Bar;");
        System.out.println("  -keepattributes LIST     Preserve attributes (comma-separated):");
        System.out.println("                           Signature,InnerClasses,EnclosingMethod,");
        System.out.println("                           RuntimeVisibleAnnotations,Exceptions,Deprecated,Synthetic");
        System.out.println("  -libraryjars PREFIXES   Add library package prefixes (comma-separated, repeatable)");
        System.out.println("                           e.g. org/apache/commons/,com/google/common/");
        System.out.println("  -userprefix PREFIXES     User-code prefixes that override library classification");
        System.out.println("                           (comma-separated, repeatable)");
        System.out.println("  -dontskipnonpubliclibraryclasses  Accepted for ProGuard compat (KBox never skips)");
        System.out.println("  -dontwarn                Suppress warning messages");
        System.out.println("  -dontnote                Suppress informational notes");
        System.out.println("  -dontobfuscate           Skip identifier renaming");
        System.out.println("  -dontoptimize            Skip control-flow obfuscation");
        System.out.println("  -neverfail true|false    When true (default), per-class errors roll back to");
        System.out.println("                           original bytes instead of aborting the build");
        System.out.println("  -useDefaultLibraryPrefixes true|false  Toggle the bundled library prefix list");
        System.out.println("                           (default: true). Set to false for full manual control.");
        System.out.println();
        System.out.println("Patterns use glob syntax: ** = any path segments, * = within a package.");
        System.out.println("Example: --scope SELECTIVE --include com/myapp/** --exclude com/myapp/api/*");
        System.out.println("Adaptive example: java -jar kbox.jar -i app.jar -o out.jar -keep com.example.Main -dontwarn");
    }
}
