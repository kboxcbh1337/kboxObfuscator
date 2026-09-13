package com.kbox.core.name;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.analysis.MemberRef;
import com.kbox.core.config.ProtectionConfig;
import org.objectweb.asm.tree.ClassNode;

import java.util.List;

/**
 * Decision tree that decides whether a class, method or field must keep its
 * original name. Returns {@code true} (keep) as soon as the first rule fires;
 * otherwise the member is eligible for renaming.
 *
 * <p>Order matters: cheap structural checks first, then set-membership checks.
 */
public final class RetentionDecision {

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public RetentionDecision(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /** Keep the whole class? (package + class name unchanged) */
    public boolean keepClass(String internal) {
        // 0. Library classes are never renamed (JDK + common shaded libs).
        //    The LibraryClassifier check covers java/, javax/, org/apache/,
        //    com/google/, kotlin/, org/springframework/, etc.
        if (cfg.isLibraryClass(internal)) return true;
        // 1. User-configured keep prefix.
        if (cfg.isKept(internal)) return true;
        // 2. Explicitly seeded into the keep-set (reflection, manifest, SPI).
        if (graph.getKeepSet().contains(MemberRef.ofClass(internal))) return true;
        // 3. Annotations defined with runtime retention are referenced by name
        //    from the bytecode (kept automatically); nothing to do here.
        // 4. Native methods declared by the user reference the class by name
        //    in the JNI symbol table -> the class loader needs the original name.
        //    We detect "is any method natively owned by user code" cheaply.
        return false;
    }

    /** Keep this method's name? (descriptor stays untouched regardless) */
    public boolean keepMethod(ClassNode cn, String name, String desc) {
        // 1. Constructors and static initializers cannot be renamed.
        if (name.charAt(0) == '<') return true;
        // 2. main(String[]) is the JVM bootstrap entry; never rename.
        if (name.equals("main") && desc.equals("([Ljava/lang/String;)V")) return true;
        // 3. Object/Object-wait-family and finalize must match the superclass.
        if (isInheritedFromObject(cn, name, desc)) return true;
        // 4. Serializable contract methods (kept by convention; ObjectInputStream
        //    reflectively looks these up by exact name).
        if (isSerializableMethod(name, desc)) return true;
        // 5. Enum synthetic methods values/valueOf.
        if ((cn.access & 0x4000) != 0 && isEnumMethod(name, desc)) return true; // ACC_ENUM
        // 6. The class is fully kept (prefix / reflection seed).
        if (keepClass(cn.name)) return true;
        // 7. User-configured keep-member spec.
        if (cfg.getKeepMembers().contains(ProtectionConfig.memberKey(cn.name, name, desc))) return true;
        // 8. Reflection scanner seeded this exact member into the keep-set.
        if (graph.getKeepSet().contains(new MemberRef(cn.name, name, desc))) return true;
        // 9. User-declared native methods: keep the name so a pre-existing JNI
        //    symbol (e.g. Java_..._nativeFoo) keeps working.
        //    (Methods we converted via JNIC are re-declared native; those we *can*
        //    rename because we generate the JNI symbol ourselves.)
        if (isUserDeclaredNative(cn, name, desc) && !cfg.getNativeMethods()
                .contains(ProtectionConfig.memberKey(cn.name, name, desc))) {
            return true;
        }
        // 10. Override equivalence: if the parent/interface declares a kept
        //     method, the override here must keep the same name. We approximate
        //     by walking super chain; the NameObfuscator refines this precisely.
        if (overridesKeptMethod(cn, name, desc)) return true;
        // 11. The declaring class extends/implements a type that lives OUTSIDE the
        //     analysed jar (Forge, LaunchWrapper, Minecraft, Mixin, ...). Its method
        //     table is not on the obfuscation classpath, so we cannot tell which of
        //     this class's methods are overrides. Renaming an override of an external
        //     INTERFACE leaves the interface method unimplemented ->
        //     AbstractMethodError at the first framework call (a Forge
        //     IClassTransformer.transform does exactly that); renaming an override of
        //     an external SUPERCLASS silently rebinds dispatch to the parent. Keep
        //     every method that could override.
        if (mayOverrideExternalSupertype(cn, name, desc)) return true;
        // 11b. Spring Data repository query methods are parsed BY NAME at runtime.
        if (isSpringDataRepository(graph, cn.name)) return true;
        // 12. "any-kept" wildcard from reflection scanner (getDeclaredMethod("x")).
        if (graph.getKeepSet().contains(new MemberRef("__anykept__", name, ""))) {
            return true;
        }
        return false;
    }

    /** Spring Data repository base types (internal names). */
    private static final java.util.Set<String> SPRING_DATA_REPOSITORY_TYPES =
            new java.util.HashSet<>(java.util.Arrays.asList(
                    "org/springframework/data/repository/Repository",
                    "org/springframework/data/repository/CrudRepository",
                    "org/springframework/data/repository/ListCrudRepository",
                    "org/springframework/data/repository/PagingAndSortingRepository",
                    "org/springframework/data/repository/ListPagingAndSortingRepository",
                    "org/springframework/data/repository/query/QueryByExampleExecutor",
                    "org/springframework/data/jpa/repository/JpaRepository",
                    "org/springframework/data/jpa/repository/JpaSpecificationExecutor",
                    "org/springframework/data/repository/reactive/ReactiveCrudRepository",
                    "org/springframework/data/mongodb/repository/MongoRepository"));

    /**
     * True when {@code internal} is, or (transitively) extends, a Spring Data
     * repository type.
     *
     * <p>Spring Data turns the <em>method names</em> of these interfaces into
     * queries ({@code findByNameAndStatus} -> {@code where name=? and status=?}).
     * Only {@code @Query}-annotated methods carry their query separately, and the
     * two cannot be told apart reliably, so every method name on a repository type
     * has to survive renaming — otherwise the provider fails at startup with
     * {@code No property 'xyz' found for type 'Foo'} while all classes still load
     * perfectly.
     */
    public static boolean isSpringDataRepository(ClassGraph graph, String internal) {
        if (graph == null || internal == null) return false;
        if (SPRING_DATA_REPOSITORY_TYPES.contains(internal)) return true;
        java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        queue.add(internal);
        while (!queue.isEmpty()) {
            String n = queue.poll();
            if (!seen.add(n)) continue;
            if (SPRING_DATA_REPOSITORY_TYPES.contains(n)) return true;
            ClassNode node = graph.getClasses().get(n);
            if (node == null) continue;
            if (node.superName != null) queue.add(node.superName);
            if (node.interfaces != null) {
                for (Object i : node.interfaces) queue.add(String.valueOf(i));
            }
        }
        return false;
    }

    /**
     * True when {@code cn.name(owner)} may override a method of a supertype that is
     * not part of the analysed jar, so its name cannot be trusted to be safe to
     * rename.
     *
     * <p>Static and private methods never participate in overriding, and
     * {@code <init>}/{@code <clinit>} are already pinned, so those are excluded.
     * {@code java/*} supertypes are deliberately ignored here: every class extends
     * {@code java/lang/Object}, treating that as "external" would pin every method
     * in the jar and disable method renaming entirely. JDK callback contracts are
     * covered by the {@code overridesKeptMethod}/callback rules instead.
     */
    @SuppressWarnings("unchecked")
    private boolean mayOverrideExternalSupertype(ClassNode cn, String name, String desc) {
        if (name.charAt(0) == '<') return false;              // ctor / static init
        if ((cn.access & 0x0200) != 0) return false;          // ACC_INTERFACE
        if (cn.methods != null) {
            for (Object m : (List<org.objectweb.asm.tree.MethodNode>) cn.methods) {
                org.objectweb.asm.tree.MethodNode mn = (org.objectweb.asm.tree.MethodNode) m;
                if (!mn.name.equals(name) || !mn.desc.equals(desc)) continue;
                if ((mn.access & 0x0008) != 0) return false;  // ACC_STATIC
                if ((mn.access & 0x0002) != 0) return false;  // ACC_PRIVATE
                break;
            }
        }
        return hasExternalSupertype(cn);
    }

    /** Cached result of {@link #hasExternalSupertype(ClassNode)} per class name. */
    private final java.util.Map<String, Boolean> externalSuperMemo = new java.util.HashMap<>();

    /**
     * JDK interfaces that are invoked by NAME from outside the application, so
     * every implementation must keep the interface's method names. See
     * {@link #walkExternal} for why only a curated interface list is treated as
     * "external" instead of the whole {@code java/*} namespace.
     */
    private static final java.util.Set<String> JDK_CALLBACK_INTERFACES =
            new java.util.HashSet<>(java.util.Arrays.asList(
                    "java/lang/reflect/InvocationHandler",
                    "java/lang/Runnable",
                    "java/lang/Comparable",
                    "java/util/Comparator",
                    "java/util/concurrent/Callable",
                    "java/util/concurrent/ThreadFactory",
                    "java/lang/Thread$UncaughtExceptionHandler",
                    "java/util/Iterator",
                    "java/lang/Iterable",
                    "java/util/Map$Entry",
                    "java/io/Closeable",
                    "java/lang/AutoCloseable",
                    "java/security/PrivilegedAction",
                    "java/security/PrivilegedExceptionAction",
                    "java/util/Spliterator",
                    "java/util/function/Function",
                    "java/util/function/BiFunction",
                    "java/util/function/Supplier",
                    "java/util/function/Consumer",
                    "java/util/function/BiConsumer",
                    "java/util/function/Predicate",
                    "java/util/function/BiPredicate",
                    "java/util/function/UnaryOperator",
                    "java/util/function/BinaryOperator",
                    "java/util/function/ToIntFunction",
                    "java/util/function/ToLongFunction",
                    "java/util/function/ToDoubleFunction"));

    /** Walks the supertype graph (classes AND interfaces, transitively through
     *  in-jar types) and reports whether it leaves the jar. */
    private boolean hasExternalSupertype(ClassNode cn) {
        Boolean memo = externalSuperMemo.get(cn.name);
        if (memo != null) return memo;
        // Cycle guard: assume "in-jar only" while recursing.
        externalSuperMemo.put(cn.name, Boolean.FALSE);
        boolean result = walkExternal(cn);
        externalSuperMemo.put(cn.name, result);
        return result;
    }

    private boolean walkExternal(ClassNode cn) {
        java.util.Deque<String> queue = new java.util.ArrayDeque<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        if (cn.superName != null) queue.add(cn.superName);
        if (cn.interfaces != null) {
            for (Object i : cn.interfaces) queue.add((String) i);
        }
        while (!queue.isEmpty()) {
            String t = queue.poll();
            if (t == null || !seen.add(t)) continue;
            if (t.startsWith("java/")) {
                // JDK interfaces whose methods the JVM or a framework invokes BY
                // NAME. An implementation that renames an override no longer
                // implements the interface method, and the first callback dies with
                // AbstractMethodError — e.g. a class implementing
                // java.lang.reflect.InvocationHandler stops being a usable JDK
                // dynamic-proxy handler ("Receiver class X does not define or
                // inherit an implementation of the resolved method 'abstract
                // java.lang.Object invoke(...)'"). Abstract CLASSES from the JDK are
                // still skipped: every class extends java/lang/Object, so treating
                // all java/* supertypes as external would pin every method in the
                // jar and disable method renaming entirely.
                if (JDK_CALLBACK_INTERFACES.contains(t)) return true;
                continue;
            }
            ClassNode n = graph.getClasses().get(t);
            if (n == null) return true;                       // leaves the jar
            if (n.superName != null) queue.add(n.superName);
            if (n.interfaces != null) {
                for (Object i : n.interfaces) queue.add((String) i);
            }
        }
        return false;
    }

    /** Keep this field's name? */
    public boolean keepField(ClassNode cn, String name, String desc) {
        if (keepClass(cn.name)) return true;
        if (cfg.getKeepMembers().contains(ProtectionConfig.memberKey(cn.name, name, desc))) return true;
        if (graph.getKeepSet().contains(new MemberRef(cn.name, name, desc))) return true;
        if (graph.getKeepSet().contains(new MemberRef("__anykept__", name, ""))) return true;
        // serialVersionUID must keep its exact name for the JVM serial-version check.
        if (name.equals("serialVersionUID") && desc.equals("J")) return true;
        // enum constant names are exposed via Enum.name() / values().
        if ((cn.access & 0x4000) != 0 && (cn.fields != null) && isEnumConstant(cn, name)) return true;
        return false;
    }

    private boolean isUserDeclaredNative(ClassNode cn, String name, String desc) {
        if (cn.methods == null) return false;
        for (Object m : cn.methods) {
            org.objectweb.asm.tree.MethodNode mn = (org.objectweb.asm.tree.MethodNode) m;
            if (mn.name.equals(name) && mn.desc.equals(desc)) {
                return (mn.access & 0x0100) != 0; // ACC_NATIVE
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private boolean overridesKeptMethod(ClassNode cn, String name, String desc) {
        // Walk super-classes (interfaces handled by NameObfuscator for consistency).
        String cur = cn.superName;
        while (cur != null && !cur.startsWith("java/")) {
            ClassNode sup = graph.getClasses().get(cur);
            if (sup == null) break;
            for (Object m : (List<org.objectweb.asm.tree.MethodNode>) sup.methods) {
                org.objectweb.asm.tree.MethodNode mn = (org.objectweb.asm.tree.MethodNode) m;
                if (mn.name.equals(name) && mn.desc.equals(desc)) {
                    if (keepMethod(sup, name, desc)) return true;
                }
            }
            cur = sup.superName;
        }
        return false;
    }

    private boolean isInheritedFromObject(ClassNode cn, String name, String desc) {
        // Object methods: wait/notify/notifyAll/clone/finalize/getClass/registerNatives etc.
        // The JVM requires overrides to keep these names.
        switch (name) {
            case "wait": case "notify": case "notifyAll":
                return desc.startsWith("()") || desc.startsWith("(J") || desc.startsWith("(JI");
            case "clone": return desc.equals("()Ljava/lang/Object;");
            case "finalize": return desc.equals("()V");
            case "getClass": return desc.equals("()Ljava/lang/Class;");
            case "equals": return desc.equals("(Ljava/lang/Object;)Z");
            case "hashCode": return desc.equals("()I");
            case "toString": return desc.equals("()Ljava/lang/String;");
            default: return false;
        }
    }

    private boolean isSerializableMethod(String name, String desc) {
        if (name.equals("readObject") && desc.equals("(Ljava/io/ObjectInputStream;)V")) return true;
        if (name.equals("writeObject") && desc.equals("(Ljava/io/ObjectOutputStream;)V")) return true;
        if (name.equals("readResolve") && desc.equals("()Ljava/lang/Object;")) return true;
        if (name.equals("writeReplace") && desc.equals("()Ljava/lang/Object;")) return true;
        if (name.equals("readObjectNoData") && desc.equals("()V")) return true;
        return false;
    }

    private boolean isEnumMethod(String name, String desc) {
        if (name.equals("values") && desc.startsWith("()[L")) return true;
        if (name.equals("valueOf") && desc.equals("(Ljava/lang/String;)Ljava/lang/Enum;")) return true;
        if (name.equals("valueOf")) {
            // enum valueOf(Class, String) is inherited from Enum; enum-specific valueOf(Class) returns the enum.
            return desc.startsWith("(Ljava/lang/String;)");
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private boolean isEnumConstant(ClassNode cn, String name) {
        if (cn.fields == null) return false;
        for (Object f : cn.fields) {
            org.objectweb.asm.tree.FieldNode fn = (org.objectweb.asm.tree.FieldNode) f;
            if (fn.name.equals(name)) {
                // enum constants are public static final with the enum type
                return (fn.access & 0x0008 | fn.access & 0x0010) != 0 && fn.desc.equals("L" + cn.name + ";");
            }
        }
        return false;
    }
}
