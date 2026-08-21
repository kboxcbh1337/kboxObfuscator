package com.kbox.core.analysis;

import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Scans the class graph for {@code @Native} and {@code @NotNative} annotations
 * and seeds the native-method config automatically. This is the ZKM-style
 * annotation-based targeting mechanism that gives developers fine-grained
 * control over which code is translated to native (JNI/C++) vs. kept as Java.
 *
 * <p>Rules:
 * <ol>
 *   <li>A class annotated with {@code @Native} adds <b>all</b> its non-static,
 *       non-abstract, non-native methods to the native set (unless excluded by
 *       {@code @NotNative}). Static methods in {@code @Native} classes are NOT
 *       auto-included — they must be individually annotated.</li>
 *   <li>A method annotated with {@code @Native} is always added.</li>
 *   <li>A method annotated with {@code @NotNative} is always excluded, even if
 *       its class is {@code @Native}.</li>
 *   <li>Methods matching explicit {@code nativeMethod} config take precedence
 *       over annotations (config overrides annotations).</li>
 * </ol>
 */
public final class NativeAnnotationScanner {

    private static final String TAG = "native-ann";
    private static final String NATIVE_ANNOTATION = "Lcom/kbox/annotations/Native;";
    private static final String NOT_NATIVE_ANNOTATION = "Lcom/kbox/annotations/NotNative;";

    private final com.kbox.core.analysis.ClassGraph graph;
    private final ProtectionConfig cfg;

    public NativeAnnotationScanner(com.kbox.core.analysis.ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /**
     * Scans all classes and populates the nativeMethods set from annotations.
     * Returns a summary of what was found.
     */
    public ScanResult scan() {
        Set<String> nativeClasses = new HashSet<>();
        Set<String> nativeMethods = new HashSet<>();
        Set<String> excludedMethods = new HashSet<>();

        // Pass 1: collect @NotNative exclusions which take priority.
        for (ClassNode cn : graph.getClasses().values()) {
            for (MethodNode mn : cn.methods) {
                if (hasAnnotation(mn.visibleAnnotations, NOT_NATIVE_ANNOTATION)
                        || hasAnnotation(mn.invisibleAnnotations, NOT_NATIVE_ANNOTATION)) {
                    excludedMethods.add(ProtectionConfig.memberKey(cn.name, mn.name, mn.desc));
                }
            }
        }

        // Pass 2: collect @Native classes and methods.
        for (ClassNode cn : graph.getClasses().values()) {
            boolean classNative = hasAnnotation(cn.visibleAnnotations, NATIVE_ANNOTATION)
                    || hasAnnotation(cn.invisibleAnnotations, NATIVE_ANNOTATION);

            // Check each method for @Native annotation.
            for (MethodNode mn : cn.methods) {
                // Skip abstract/native/bridge methods — they have no body to translate.
                if ((mn.access & (org.objectweb.asm.Opcodes.ACC_ABSTRACT
                        | org.objectweb.asm.Opcodes.ACC_NATIVE
                        | org.objectweb.asm.Opcodes.ACC_BRIDGE)) != 0) continue;

                String key = ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);

                // Skip @NotNative exclusions.
                if (excludedMethods.contains(key)) continue;

                // Skip methods already in explicit config (config takes priority).
                if (cfg.getNativeMethods().contains(key)) continue;

                boolean methodNative = hasAnnotation(mn.visibleAnnotations, NATIVE_ANNOTATION)
                        || hasAnnotation(mn.invisibleAnnotations, NATIVE_ANNOTATION);

                // A method is native-eligible if: individually annotated, OR
                // its class is @Native and it's non-static (static methods in
                // @Native classes are often utility methods, not instance logic).
                boolean include = methodNative || (classNative
                        && (mn.access & org.objectweb.asm.Opcodes.ACC_STATIC) == 0
                        && !mn.name.equals("<init>") && !mn.name.equals("<clinit>"));

                if (include) {
                    nativeMethods.add(key);
                }
            }

            if (classNative) {
                nativeClasses.add(cn.name);
            }
        }

        // Seed the config.
        for (String m : nativeMethods) {
            cfg.getNativeMethods().add(m);
        }

        if (!nativeClasses.isEmpty() || !nativeMethods.isEmpty()) {
            KBoxLog.info(TAG, "@Native scan: " + nativeClasses.size() + " classes, "
                    + nativeMethods.size() + " methods; "
                    + excludedMethods.size() + " @NotNative exclusions");
        }

        return new ScanResult(nativeClasses, nativeMethods, excludedMethods);
    }

    public static final class ScanResult {
        public final Set<String> nativeClasses;
        public final Set<String> nativeMethods;
        public final Set<String> excludedMethods;

        ScanResult(Set<String> classes, Set<String> methods, Set<String> excluded) {
            this.nativeClasses = classes;
            this.nativeMethods = methods;
            this.excludedMethods = excluded;
        }
    }

    @SuppressWarnings("unchecked")
    private static boolean hasAnnotation(List<AnnotationNode> annotations, String desc) {
        if (annotations == null) return false;
        for (AnnotationNode ann : annotations) {
            if (ann.desc.equals(desc)) return true;
        }
        return false;
    }
}
