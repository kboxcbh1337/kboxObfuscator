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
        // 11. "any-kept" wildcard from reflection scanner (getDeclaredMethod("x")).
        if (graph.getKeepSet().contains(new MemberRef("__anykept__", name, ""))) {
            return true;
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
