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
        KEEP.add("Lorg/spongepowered/asm/mixin/Shadow;");   // org.spongepowered.asm.mixin.Shadow
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
        // JPA / Hibernate persistence mapping. These are READ AT RUNTIME by the
        // JPA provider: Hibernate discovers entities by scanning for @Entity and
        // builds the mapping from @Table/@Id/@Column/@JoinColumn/… Erasing them is
        // not a "smaller attack surface" — the application stops working with
        // "Not a managed type: class com.example.domain.Foo" while every class
        // still loads fine, so the failure looks nothing like an obfuscation
        // problem. Both the jakarta and the legacy javax packages are covered
        // because Boot 2 / Java EE apps still use the latter.
        for (String p : new String[]{"jakarta/persistence/", "javax/persistence/"}) {
            for (String a : new String[]{
                    "Entity", "Table", "Access", "Id", "IdClass", "EmbeddedId",
                    "Column", "Enumerated", "Temporal", "Lob", "Version",
                    "Basic", "Transient", "Convert",
                    "GeneratedValue", "SequenceGenerator", "TableGenerator",
                    "OneToOne", "OneToMany", "ManyToOne", "ManyToMany",
                    "JoinColumn", "JoinTable", "OrderBy", "OrderColumn", "MapsId",
                    "PrimaryKeyJoinColumn", "MapKey", "MapKeyJoinColumn",
                    "ElementCollection", "CollectionTable", "Embeddable",
                    "Embedded", "Inheritance", "DiscriminatorColumn",
                    "DiscriminatorValue", "SecondaryTable", "SecondaryTables",
                    "NamedQuery", "NamedQueries", "NamedNativeQuery",
                    "NamedNativeQueries", "AttributeOverride", "AttributeOverrides",
                    "AssociationOverride", "AssociationOverrides",
                    "PrePersist", "PostPersist", "PreUpdate", "PostUpdate",
                    "PreRemove", "PostRemove", "PostLoad",
                    "EntityListeners", "ExcludeSuperclassListeners",
                    "Cacheable", "Converter", "Converts", "PersistenceContext",
                    "PersistenceUnit"}) {
                KEEP.add("L" + p + a + ";");
            }
        }
        // Spring Data query declarations and every other annotation a runtime
        // framework READS (rather than a compiler). Same failure mode as JPA:
        // erasing @Query makes Spring Data fall back to deriving the query from
        // the method name and die with "No property 'xyz' found for type 'Foo'".
        for (String a : new String[]{
                "Lorg/springframework/data/jpa/repository/Query;",
                "Lorg/springframework/data/jpa/repository/Modifying;",
                "Lorg/springframework/data/jpa/repository/Lock;",
                "Lorg/springframework/data/jpa/repository/Procedure;",
                "Lorg/springframework/data/jpa/repository/EntityGraph;",
                "Lorg/springframework/data/jpa/repository/QueryHints;",
                "Lorg/springframework/data/repository/query/Query;",
                "Lorg/springframework/data/repository/query/Param;",
                "Lorg/springframework/data/repository/query/Procedure;",
                "Lcom/fasterxml/jackson/annotation/JsonProperty;",
                "Lcom/fasterxml/jackson/annotation/JsonIgnore;",
                "Lcom/fasterxml/jackson/annotation/JsonCreator;",
                "Lcom/fasterxml/jackson/annotation/JsonValue;",
                "Lcom/fasterxml/jackson/annotation/JsonAnySetter;",
                "Lcom/fasterxml/jackson/annotation/JsonDeserialize;",
                "Lcom/fasterxml/jackson/annotation/JsonSerialize;",
                "Lcom/fasterxml/jackson/annotation/JsonTypeInfo;",
                "Lcom/fasterxml/jackson/annotation/JsonSubTypes;",
                "Ljakarta/validation/Valid;",
                "Ljakarta/validation/constraints/NotNull;",
                "Ljavax/validation/Valid;",
        }) {
            KEEP.add(a);
        }
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
        java.util.concurrent.atomic.AtomicInteger erased = new java.util.concurrent.atomic.AtomicInteger();
        // Per-class pass: classes are independent → fan out over the workers
        // (0 = auto CPU cores; 1 = serial). Failures are caught + logged by the
        // processor and leave that class untouched.
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, cn -> {
            erased.addAndGet(eraseClassLevel(cn));
            erased.addAndGet(eraseMemberAnnotations(cn));
        }, cfg.getParallelThreads());
        int e = erased.get();
        KBoxLog.info(TAG, "Erased " + e + " annotation" + (e == 1 ? "" : "s")
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

    /**
     * True if this annotation must survive erasure.
     *
     * <p>Mixin annotations are matched by PACKAGE PREFIX rather than by an
     * explicit list. Enumerating them one by one is dangerously fragile: the list
     * below used to say {@code Lorg/spongepowered/asm/mixin/injection/Shadow;}
     * while {@code @Shadow} actually lives at
     * {@code Lorg/spongepowered/asm/mixin/Shadow;} — the single wrong package
     * segment silently erased {@code @Shadow} from every Mixin class and the whole
     * 1.8.9 client died during startup with
     * <pre>
     *   Mixin apply failed ...:gui.MixinGuiScreen -&gt; net.minecraft.client.gui.GuiScreen
     *   InvalidMixinException: ... NullPointerException
     *     at ...injection.code.Injector.findTargetNodes(InsnList.indexOf)
     * </pre>
     * The Mixin runtime reads these reflectively to decide member ownership
     * ({@code @Shadow}), injection points ({@code @At}), target class
     * ({@code @Mixin}) and replacements, so none of them may ever be dropped.
     */
    /**
     * Annotation package families consumed at RUNTIME by a framework (or the JVM).
     *
     * <p>Erasing an annotation in one of these families silently disables behaviour
     * that is driven purely by it: Spring's component scan and
     * {@code @ConfigurationProperties} binding, Hibernate entity mapping, Spring
     * Data query derivation, Jackson binding, Mixin, Fabric entry points. An
     * enumerative name list is inherently incomplete and the gap only shows up as a
     * runtime error far from its cause ({@code Not a managed type},
     * {@code No property 'x' found for type 'Foo'},
     * {@code required a bean of type ... could not be found}). Exempting the package
     * families is therefore the correct default; annotations from unknown
     * third-party packages are still erased, which is where the obfuscation value
     * actually lies. (The explicit {@code KEEP} entries above / below are the
     * documented cases and are subsumed by these prefixes.)
     */
    private static final String[] KEEP_PREFIXES = {
            "Lorg/springframework/",
            "Ljakarta/",
            "Ljavax/",
            "Lcom/fasterxml/jackson/",
            "Lkotlin/",
            "Lorg/spongepowered/asm/mixin/",
            "Lnet/fabricmc/",
    };

    private static boolean keep(AnnotationNode a) {
        if (a == null || a.desc == null) return true;
        if (KEEP.contains(a.desc)) return true;
        for (String p : KEEP_PREFIXES) {
            if (a.desc.startsWith(p)) return true;
        }
        return false;
    }

    /** Removes annotations not in the keep set; returns how many were removed. */
    private static int filter(List<AnnotationNode> list) {
        int removed = 0;
        for (int i = list.size() - 1; i >= 0; i--) {
            if (!keep(list.get(i))) {
                list.remove(i);
                removed++;
            }
        }
        return removed;
    }
}