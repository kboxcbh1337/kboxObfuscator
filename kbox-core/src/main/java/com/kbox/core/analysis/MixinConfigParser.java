package com.kbox.core.analysis;

import com.kbox.core.log.KBoxLog;

import java.util.*;

/**
 * Parses a Mixin configuration file ({@code mixins.*.json}) and extracts:
 * <ol>
 *   <li>The mixin package (e.g. {@code leader.mixin}) — all classes under this
 *       package are mixin classes and MUST NOT be bytecode-transformed.</li>
 *   <li>The target classes of each mixin — extracted from the {@code @Mixin}
 *       annotation on each mixin class.</li>
 *   <li>The refmap method mappings — method descriptors that Mixin's injector
 *       resolves at runtime. These methods must keep their exact signatures
 *       (name + descriptor) or the injection will fail.</li>
 * </ol>
 *
 * <p>This is a zero-dependency JSON parser (no Jackson/Gson). The Mixin config
 * format is simple enough to parse with basic string manipulation.
 *
 * <p>Usage in ProtectionPipeline:
 * <pre>{@code
 *   MixinConfigParser.Result r = MixinConfigParser.parse(graph);
 *   for (String target : r.targetClasses) cfg.getKeepPrefixes().add(target);
 *   for (String sig : r.keptMethodSigs) cfg.getKeepMembers().add(sig);
 * }</pre>
 */
public final class MixinConfigParser {

    private static final String TAG = "mixin-config";

    /** Parsed result of a Mixin config scan. */
    public static final class Result {
        /** Mixin class internal names (e.g. {@code leader/mixin/MixinEntity}). */
        public final Set<String> mixinClasses = new HashSet<>();
        /** Target class internal names extracted from @Mixin annotations. */
        public final Set<String> targetClasses = new HashSet<>();
        /** Target method signatures that Mixin injects into (owner + name + desc). */
        public final Set<String> targetMethodSigs = new HashSet<>();
        /** Mixin config package prefix (all classes under this are mixins). */
        public String mixinPackage;

        Result(String pkg) { this.mixinPackage = pkg; }

        /** True if the given class is a mixin class (not a target). */
        public boolean isMixinClass(String internal) {
            return mixinClasses.contains(internal);
        }

        /** True if the given class is a target of some mixin. */
        public boolean isTargetClass(String internal) {
            return targetClasses.contains(internal);
        }

        /** All mixin-affected classes: mixins + their targets. */
        public Set<String> allAffected() {
            Set<String> all = new HashSet<>(mixinClasses);
            all.addAll(targetClasses);
            return all;
        }
    }

    /**
     * Main entry: scan the class graph for Mixin config files and @Mixin
     * annotations, building a complete picture of the mixin ecosystem.
     */
    public static Result parse(ClassGraph graph) {
        Result r = new Result(null);

        // Step 1: find and parse mixins.*.json files in resources.
        List<String> configPaths = new ArrayList<>();
        for (String resourcePath : graph.getResources().keySet()) {
            if (resourcePath.endsWith(".json") && resourcePath.contains("mixins")) {
                configPaths.add(resourcePath);
            }
        }

        Map<String, byte[]> resources = graph.getResources();
        String mixinPackage = null;
        for (String path : configPaths) {
            byte[] data = resources.get(path);
            if (data == null) continue;
            try {
                String json = new String(data, java.nio.charset.StandardCharsets.UTF_8);
                String pkg = extractJsonString(json, "package");
                if (pkg != null) {
                    mixinPackage = pkg.replace('.', '/');
                }
            } catch (Exception e) {
                KBoxLog.warn(TAG, "Failed to parse Mixin config: " + path + ": " + e.getMessage());
            }
        }

        // Step 2: scan all classes for @Mixin annotation.
        // If we found a mixinPackage, only scan that package; otherwise scan all.
        if (mixinPackage != null) {
            r.mixinPackage = mixinPackage;

            // Also look for the plugin class (FMLLoadingPlugin) to keep it.
            for (String path : configPaths) {
                byte[] data = resources.get(path);
                if (data == null) continue;
                String json = new String(data, java.nio.charset.StandardCharsets.UTF_8);
                String plugin = extractJsonString(json, "plugin");
                if (plugin != null) {
                    String pluginInternal = plugin.replace('.', '/');
                    r.mixinClasses.add(pluginInternal);
                }
            }
        }

        // Step 3: scan classes and collect @Mixin annotations.
        for (org.objectweb.asm.tree.ClassNode cn : graph.getClasses().values()) {
            // If we have a known mixin package, only check classes under it.
            if (mixinPackage != null && !cn.name.startsWith(mixinPackage + "/")) {
                continue;
            }

            // Check for @Mixin annotation on the class.
            List<String> targets = getMixinTargets(cn);
            if (!targets.isEmpty()) {
                r.mixinClasses.add(cn.name);

                for (String target : targets) {
                    r.targetClasses.add(target);
                }

                // Also scan the mixin class for @Inject/@Redirect/@ModifyArg
                // annotations to find the target method signatures.
                scanInjectionPoints(cn, targets, r);
            }
        }

        // If no mixinPackage found from config, try the class scan approach.
        if (mixinPackage == null && !r.mixinClasses.isEmpty()) {
            // Infer mixin package from the found mixin classes.
            KBoxLog.info(TAG, "Mixin package not in config; inferred from " + r.mixinClasses.size()
                    + " @Mixin-annotated classes");
        }

        // Step 4: parse refmap.json to find explicit method mappings if available.
        for (String path : configPaths) {
            if (!path.contains("refmap")) continue;
            byte[] data = resources.get(path);
            if (data == null) continue;
            parseRefmap(new String(data, java.nio.charset.StandardCharsets.UTF_8), r);
        }

        KBoxLog.info(TAG, "Mixin analysis: " + r.mixinClasses.size() + " mixin classes, "
                + r.targetClasses.size() + " target classes, "
                + r.targetMethodSigs.size() + " target method sigs"
                + (r.mixinPackage != null ? ", package=" + r.mixinPackage : ""));
        return r;
    }

    // ========================================================================
    // @Mixin annotation scanning
    // ========================================================================

    @SuppressWarnings("unchecked")
    private static List<String> getMixinTargets(org.objectweb.asm.tree.ClassNode cn) {
        List<String> targets = new ArrayList<>();
        if (cn.visibleAnnotations != null) {
            for (org.objectweb.asm.tree.AnnotationNode an :
                    (List<org.objectweb.asm.tree.AnnotationNode>) cn.visibleAnnotations) {
                if (!an.desc.equals("Lorg/spongepowered/asm/mixin/Mixin;")) continue;
                // Extract 'value' or 'targets' field.
                extractMixinAnnotationTargets(an, targets);
            }
        }
        if (cn.invisibleAnnotations != null) {
            for (org.objectweb.asm.tree.AnnotationNode an :
                    (List<org.objectweb.asm.tree.AnnotationNode>) cn.invisibleAnnotations) {
                if (!an.desc.equals("Lorg/spongepowered/asm/mixin/Mixin;")) continue;
                extractMixinAnnotationTargets(an, targets);
            }
        }
        return targets;
    }

    private static void extractMixinAnnotationTargets(org.objectweb.asm.tree.AnnotationNode an,
                                                       List<String> targets) {
        if (an.values == null) return;
        for (int i = 0; i < an.values.size(); i += 2) {
            String key = (String) an.values.get(i);
            Object val = an.values.get(i + 1);
            if ("value".equals(key)) {
                // value can be a single Type or a list of Types.
                collectTypes(val, targets);
            } else if ("targets".equals(key)) {
                // targets is a list of String (class names with dots).
                if (val instanceof List) {
                    for (Object item : (List<?>) val) {
                        if (item instanceof String) {
                            targets.add(((String) item).replace('.', '/'));
                        }
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void collectTypes(Object val, List<String> targets) {
        if (val instanceof org.objectweb.asm.Type) {
            // val is a single Type descriptor (Lcom/example/Target;)
            String desc = ((org.objectweb.asm.Type) val).getDescriptor();
            targets.add(desc.substring(1, desc.length() - 1));
        } else if (val instanceof List) {
            for (Object item : (List<?>) val) {
                if (item instanceof org.objectweb.asm.Type) {
                    String desc = ((org.objectweb.asm.Type) item).getDescriptor();
                    targets.add(desc.substring(1, desc.length() - 1));
                }
            }
        }
    }

    // ========================================================================
    // @Inject / @Redirect / @ModifyArg annotation scanning on mixin methods
    // ========================================================================

    @SuppressWarnings("unchecked")
    private static void scanInjectionPoints(org.objectweb.asm.tree.ClassNode cn,
                                             List<String> targets, Result r) {
        if (cn.methods == null) return;

        for (org.objectweb.asm.tree.MethodNode mn :
                (List<org.objectweb.asm.tree.MethodNode>) cn.methods) {
            // Check both visible and invisible annotations.
            checkInjectAnnotations(mn.visibleAnnotations, targets, r);
            checkInjectAnnotations(mn.invisibleAnnotations, targets, r);

            // Also check @Shadow and @Overwrite which also target specific methods.
            checkShadowAnnotations(mn.visibleAnnotations, targets, r);
            checkShadowAnnotations(mn.invisibleAnnotations, targets, r);

            // @Accessor targets fields, not methods, but we still need the class.
            checkAccessorAnnotation(mn.visibleAnnotations, targets, r);
            checkAccessorAnnotation(mn.invisibleAnnotations, targets, r);
        }
    }

    @SuppressWarnings("unchecked")
    private static void checkInjectAnnotations(List<org.objectweb.asm.tree.AnnotationNode> annos,
                                                List<String> targets, Result r) {
        if (annos == null) return;
        for (org.objectweb.asm.tree.AnnotationNode an : annos) {
            String desc = an.desc;
            boolean isInject = desc.equals("Lorg/spongepowered/asm/mixin/injection/Inject;")
                    || desc.equals("Lorg/spongepowered/asm/mixin/injection/Redirect;")
                    || desc.equals("Lorg/spongepowered/asm/mixin/injection/ModifyArg;")
                    || desc.equals("Lorg/spongepowered/asm/mixin/injection/ModifyArgs;")
                    || desc.equals("Lorg/spongepowered/asm/mixin/injection/ModifyConstant;")
                    || desc.equals("Lorg/spongepowered/asm/mixin/injection/ModifyVariable;");
            if (!isInject) continue;

            // Extract 'method' value from annotation.
            String methodSig = extractAnnotationStringValue(an, "method");
            if (methodSig != null) {
                // method is in the format "methodName(LargTypes;)ReturnType"
                // We need to find which target class this belongs to.
                // Try each target class.
                for (String target : targets) {
                    String sig = target + "." + methodSig;
                    r.targetMethodSigs.add(sig);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void checkShadowAnnotations(List<org.objectweb.asm.tree.AnnotationNode> annos,
                                                List<String> targets, Result r) {
        if (annos == null) return;
        for (org.objectweb.asm.tree.AnnotationNode an : annos) {
            if (!an.desc.equals("Lorg/spongepowered/asm/mixin/Shadow;")
                    && !an.desc.equals("Lorg/spongepowered/asm/mixin/Overwrite;")) continue;

            // @Shadow methods reference a target method by NEW name.
            // The mixin method name IS the target method name (or the aliased name).
            // We don't have the method descriptor easily from the annotation context,
            // but the @Shadow method's own descriptor matches the target.
            // This is handled by keeping the mixin class methods as-is.
        }
    }

    @SuppressWarnings("unchecked")
    private static void checkAccessorAnnotation(List<org.objectweb.asm.tree.AnnotationNode> annos,
                                                 List<String> targets, Result r) {
        if (annos == null) return;
        for (org.objectweb.asm.tree.AnnotationNode an : annos) {
            if (!an.desc.equals("Lorg/spongepowered/asm/mixin/gen/Accessor;")
                    && !an.desc.equals("Lorg/spongepowered/asm/mixin/gen/Invoker;")) continue;

            String target = extractAnnotationStringValue(an, "value");
            if (target != null) {
                // target is in format "owner.name desc" or just "name desc" or "owner.name"
                // Add as keep member.
                r.targetMethodSigs.add(target);
            }
        }
    }

    private static String extractAnnotationStringValue(org.objectweb.asm.tree.AnnotationNode an,
                                                        String key) {
        if (an.values == null) return null;
        for (int i = 0; i < an.values.size(); i += 2) {
            if (key.equals(an.values.get(i))) {
                Object val = an.values.get(i + 1);
                return val == null ? null : val.toString();
            }
        }
        return null;
    }

    // ========================================================================
    // Refmap parsing (extracts target-side method descriptors)
    // ========================================================================

    /**
     * Parses the refmap JSON and extracts method descriptor mappings.
     * The refmap format is:
     * <pre>{@code
     * { "mappings": {
     *     "leader/mixin/MixinClass": {
     *       "mixinMethodName": "Ltarget/Class;method(desc)V"
     *     }
     * }}</pre>
     * The VALUE of each mapping is the TARGET method descriptor. We need to
     * keep this descriptor on the target class.
     */
    private static void parseRefmap(String json, Result r) {
        // Find the "mappings" block.
        int mappingsStart = json.indexOf("\"mappings\"");
        if (mappingsStart < 0) {
            // Also try "mappings" without quotes in case of variations.
            mappingsStart = json.indexOf("mappings");
            if (mappingsStart < 0) return;
        }
        mappingsStart = json.indexOf('{', mappingsStart);
        if (mappingsStart < 0) return;

        // Simple state machine to extract key-value pairs.
        // We look for patterns like: "methodName": "Ltarget/Class;method(desc)V"
        // and extract the target side.
        int depth = 0;
        int i = mappingsStart;
        String currentMixinTarget = null;  // The key after "mappings" -> '{' -> mixin class

        // We can't easily handle nested parsing without a full JSON parser.
        // Instead, use regex: find all "L...;method(" patterns in the JSON.
        // These are the target method descriptors we need to keep.
        java.util.regex.Pattern targetMethodPattern =
                java.util.regex.Pattern.compile(
                        "\"L([a-zA-Z0-9_/$]+);([a-zA-Z0-9_<>$]+)(\\([^)]*\\))([A-Z\\[]+)?\"");
        java.util.regex.Matcher m = targetMethodPattern.matcher(json);
        while (m.find()) {
            String targetClass = m.group(1).replace('.', '/');
            String methodName = m.group(2);
            String paramDesc = m.group(3);
            String retDesc = m.group(4) != null ? m.group(4) : "V";
            String fullDesc = paramDesc + retDesc;

            // If the target class is already in our targetClasses set, add the method.
            if (r.targetClasses.contains(targetClass) || targetClass.startsWith("net/minecraft/")) {
                // For Minecraft classes, we can't keep them (they're library classes),
                // but for user-defined target classes, we need them.
                if (r.targetClasses.contains(targetClass)) {
                    r.targetMethodSigs.add(targetClass + "." + methodName + fullDesc);
                }
            }

            // Also track the mixin class itself from the section header.
            // Look backwards for the section key.
            int sectionStart = json.lastIndexOf('"', m.start() - 1);
            if (sectionStart > 0) {
                int sectionKeyEnd = json.lastIndexOf('"', sectionStart - 1);
                if (sectionKeyEnd > 0) {
                    String sectionKey = json.substring(sectionKeyEnd + 1, sectionStart);
                    sectionKey = sectionKey.replace('.', '/');
                    // If this section key matches a known mixin class, mark it.
                }
            }
        }
    }

    // ========================================================================
    // Minimal JSON helpers (no dependency on Jackson/Gson)
    // ========================================================================

    /** Extracts a top-level string value from a simple JSON object. */
    private static String extractJsonString(String json, String key) {
        // Look for "key": "value"
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        idx = json.indexOf(':', idx);
        if (idx < 0) return null;
        // Skip whitespace.
        idx++;
        while (idx < json.length() && Character.isWhitespace(json.charAt(idx))) idx++;
        if (idx >= json.length() || json.charAt(idx) != '"') return null;
        int end = json.indexOf('"', idx + 1);
        if (end < 0) return null;
        return json.substring(idx + 1, end);
    }
}
