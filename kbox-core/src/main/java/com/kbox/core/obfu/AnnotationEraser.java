package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Erases runtime-visible/invisible annotations from classes, methods and
 * fields, except a small allow-list of framework-critical annotations
 * (Mixin, SPI, serialization, etc.). Stripping annotations removes a rich
 * source of semantic metadata that decompilers and reverse engineers rely
 * on to understand the code.
 *
 * <p>Allow-listed annotations are preserved so the application keeps
 * working (e.g. {@code @Mixin}, {@code @Inject}, {@code @Service},
 * {@code @Serializable}, etc.). Everything else is dropped.
 */
public final class AnnotationEraser {

    private static final String TAG = "anno";

    /** Annotations that must survive to keep the app functional. */
    private static final Set<String> KEEP = new HashSet<>();
    static {
        // Mixin / SpongePowered
        KEEP.add("Lorg/spongepowered/asm/mixin/Mixin;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/Inject;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/Redirect;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/At;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/ModifyArg;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/ModifyArgs;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/ModifyConstant;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/ModifyVariable;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/Overwrite;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/Shadow;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/Constant;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfoReturnable;");
        KEEP.add("Lorg/spongepowered/asm/mixin/injection/callback/LocalCapture;");
        KEEP.add("Lorg/spongepowered/asm/mixin/Unique;");
        KEEP.add("Lorg/spongepowered/asm/mixin/Final;");
        KEEP.add("Lorg/spongepowered/asm/mixin/Implements;");
        KEEP.add("Lorg/spongepowered/asm/mixin/Interface;");
        KEEP.add("Lorg/spongepowered/asm/mixin/SoftOverride;");
        // Java standard / serialization / SPI
        KEEP.add("Lkotlin/Metadata;");
        KEEP.add("Lkotlin/jvm/internal/SerializedIr;");
        KEEP.add("Ljava/lang/Override;");
        KEEP.add("Ljava/io/Serializable;");
        KEEP.add("Ljakarta/annotation/Generated;");
        // Spring / framework component scanning
        KEEP.add("Lorg/springframework/stereotype/Component;");
        KEEP.add("Lorg/springframework/stereotype/Service;");
        KEEP.add("Lorg/springframework/stereotype/Repository;");
        KEEP.add("Lorg/springframework/context/annotation/Configuration;");
        KEEP.add("Lorg/springframework/context/annotation/Bean;");
        KEEP.add("Lorg/springframework/web/bind/annotation/RequestMapping;");
        KEEP.add("Lorg/springframework/web/bind/annotation/GetMapping;");
        KEEP.add("Lorg/springframework/web/bind/annotation/PostMapping;");
        // Fabric / Minecraft entry points
        KEEP.add("Lnet/fabricmc/api/ModInitializer;");
        KEEP.add("Lnet/fabricmc/api/ClientModInitializer;");
        KEEP.add("Lnet/fabricmc/api/DedicatedServerModInitializer;");
        KEEP.add("Lnet/fabricmc/api/Environment;");
        KEEP.add("Lorg/spongepowered/asm/mixin/Mixins;");
    }

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public AnnotationEraser(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isEraseAnnotations()) return;
        int erased = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            erased += eraseClassLevel(cn);
            erased += eraseMemberAnnotations(cn);
        }
        KBoxLog.info(TAG, "Erased " + erased + " annotation" + (erased == 1 ? "" : "s")
                + " (framework annotations preserved)");
    }

    private static int eraseClassLevel(ClassNode cn) {
        int n = 0;
        if (cn.visibleAnnotations != null) {
            n += filter(cn.visibleAnnotations);
            if (cn.visibleAnnotations.isEmpty()) cn.visibleAnnotations = null;
        }
        if (cn.invisibleAnnotations != null) {
            n += filter(cn.invisibleAnnotations);
            if (cn.invisibleAnnotations.isEmpty()) cn.invisibleAnnotations = null;
        }
        return n;
    }

    @SuppressWarnings("unchecked")
    private static int eraseMemberAnnotations(ClassNode cn) {
        int n = 0;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.visibleAnnotations != null) {
                n += filter(mn.visibleAnnotations);
                if (mn.visibleAnnotations.isEmpty()) mn.visibleAnnotations = null;
            }
            if (mn.invisibleAnnotations != null) {
                n += filter(mn.invisibleAnnotations);
                if (mn.invisibleAnnotations.isEmpty()) mn.invisibleAnnotations = null;
            }
            if (mn.visibleParameterAnnotations != null) {
                for (List<AnnotationNode> anns : mn.visibleParameterAnnotations) {
                    if (anns != null) { n += filter(anns); }
                }
            }
            if (mn.invisibleParameterAnnotations != null) {
                for (List<AnnotationNode> anns : mn.invisibleParameterAnnotations) {
                    if (anns != null) { n += filter(anns); }
                }
            }
        }
        for (FieldNode fn : (List<FieldNode>) cn.fields) {
            if (fn.visibleAnnotations != null) {
                n += filter(fn.visibleAnnotations);
                if (fn.visibleAnnotations.isEmpty()) fn.visibleAnnotations = null;
            }
            if (fn.invisibleAnnotations != null) {
                n += filter(fn.invisibleAnnotations);
                if (fn.invisibleAnnotations.isEmpty()) fn.invisibleAnnotations = null;
            }
        }
        return n;
    }

    /** Removes annotations not in the keep set; returns how many were removed. */
    private static int filter(List<AnnotationNode> list) {
        int removed = 0;
        for (int i = list.size() - 1; i >= 0; i--) {
            AnnotationNode a = list.get(i);
            if (!KEEP.contains(a.desc)) {
                list.remove(i);
                removed++;
            }
        }
        return removed;
    }
}