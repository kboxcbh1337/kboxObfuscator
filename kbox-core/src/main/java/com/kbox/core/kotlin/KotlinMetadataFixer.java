package com.kbox.core.kotlin;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import com.kbox.core.name.Mapping;
import kotlin.Metadata;
import kotlinx.metadata.KmClass;
import kotlinx.metadata.KmClassifier;
import kotlinx.metadata.KmConstructor;
import kotlinx.metadata.KmFunction;
import kotlinx.metadata.KmPackage;
import kotlinx.metadata.KmProperty;
import kotlinx.metadata.KmType;
import kotlinx.metadata.KmTypeAlias;
import kotlinx.metadata.KmTypeParameter;
import kotlinx.metadata.KmValueParameter;
import kotlinx.metadata.jvm.JvmExtensionsKt;
import kotlinx.metadata.jvm.JvmFieldSignature;
import kotlinx.metadata.jvm.JvmMethodSignature;
import kotlinx.metadata.jvm.KotlinClassMetadata;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Rewrites the {@code @kotlin.Metadata} annotation carried by every Kotlin
 * compiled class so it stays consistent with the identifier remapping done by
 * {@code NameObfuscator}.
 *
 * <p>Unlike a naive string replacement, this implementation parses the ProtoBuf
 * metadata with {@code kotlinx-metadata-jvm}, walks the structured {@code KmClass}
 * / {@code KmPackage} tree and:
 * <ul>
 *   <li>renames the class FQN ({@code KmClass.name} and every type reference
 *       to a remapped class in supertypes / return types / parameter types /
 *       type arguments / upper bounds),</li>
 *   <li>renames the JVM binding of every function
 *       ({@code JvmMethodSignature}), property backing field
 *       ({@code JvmFieldSignature}) and property accessor
 *       ({@code JvmGetterSignature}/{@code JvmSetterSignature}) using the same
 *       maps that {@code NameObfuscator} populated.</li>
 * </ul>
 * This keeps Kotlin reflection ({@code ::class.memberProperties}, data-class
 * deserialization, {@code KProperty.call}) working even after the underlying
 * JVM fields/methods have been obfuscated.
 *
 * <p>The Kotlin-level names ({@code KmFunction.name}, {@code KmProperty.name})
 * are intentionally <b>not</b> renamed: Kotlin reflection resolves references
 * by those names, and commercial tools (ZKM) also preserve them. The metadata
 * version is preserved so the runtime accepts the rewritten bytes.
 *
 * <p>Failure to rewrite a single annotation is logged and non-fatal.
 */
public final class KotlinMetadataFixer {

    private static final String TAG = "kotlin-md";
    private static final String METADATA_DESC = "Lkotlin/Metadata;";
    private static final String KOTLIN_MODULE_SUFFIX = ".kotlin_module";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private int fixedClasses;
    private int fixedModules;

    public KotlinMetadataFixer(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void fix(Mapping mapping) {
        if (!cfg.isFixKotlinMetadata()) return;
        if (!mapping.getClassMap().isEmpty()) {
            fixClassMetadata(mapping);
            fixModuleFiles(mapping);
        }
        KBoxLog.info(TAG, "Fixed @Metadata on " + fixedClasses + " classes, "
                + fixedModules + " .kotlin_module files");
    }

    @SuppressWarnings("unchecked")
    private void fixClassMetadata(Mapping mapping) {
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.visibleAnnotations == null) continue;
            for (AnnotationNode an : (List<AnnotationNode>) cn.visibleAnnotations) {
                if (!METADATA_DESC.equals(an.desc)) continue;
                try {
                    rewriteAnnotation(cn, an, mapping);
                } catch (Throwable t) {
                    KBoxLog.debug(TAG, "Skipping @Metadata rewrite for " + cn.name
                            + ": " + t);
                }
            }
        }
    }

    /** Rewrite one class's @Metadata annotation in place. */
    @SuppressWarnings("unchecked")
    private void rewriteAnnotation(ClassNode cn, AnnotationNode an, Mapping mapping) {
        if (an.values == null) return;

        Integer kind = null;
        int[] mv = null;
        String[] d1 = null;
        String[] d2 = null;
        String xs = null;
        String pn = null;
        Integer xi = null;

        for (int i = 0; i < an.values.size() - 1; i += 2) {
            String key = (String) an.values.get(i);
            Object v = an.values.get(i + 1);
            switch (key) {
                case "k": kind = (Integer) v; break;
                case "mv": mv = toIntArray(v); break;
                case "d1": d1 = toStringArr(v); break;
                case "d2": d2 = toStringArr(v); break;
                case "xs": xs = (String) v; break;
                case "pn": pn = (String) v; break;
                case "xi": xi = (Integer) v; break;
                default: break;
            }
        }
        if (kind == null || d1 == null) return;

        Metadata in = metadataProxy(kind, mv, d1, d2, xs, pn, xi);
        // Strict read first: metadata parsed strictly can be written back with
        // md.write(). A lenient read marks the tree as read-only and write()
        // throws "cannot be written because it represents metadata read in
        // lenient mode", which would silently leave @Metadata un-fixed and
        // break Kotlin reflection after renaming. Fall back to lenient only if
        // strict parsing rejects the schema (e.g. newer metadata version).
        KotlinClassMetadata md;
        try {
            md = KotlinClassMetadata.readStrict(in);
        } catch (Throwable strictErr) {
            try {
                md = KotlinClassMetadata.readLenient(in);
            } catch (Throwable lenientErr) {
                return;
            }
        }
        if (md == null) return;

        String owner = cn.name; // JVM member maps are keyed by original owner.
        boolean[] changed = {false};

        if (md instanceof KotlinClassMetadata.Class) {
            remapKmClass(((KotlinClassMetadata.Class) md).getKmClass(), mapping, owner, changed);
        } else if (md instanceof KotlinClassMetadata.FileFacade) {
            remapKmPackage(((KotlinClassMetadata.FileFacade) md).getKmPackage(), mapping, owner, changed);
        } else if (md instanceof KotlinClassMetadata.SyntheticClass) {
            KotlinClassMetadata.SyntheticClass sc = (KotlinClassMetadata.SyntheticClass) md;
            if (sc.getKmLambda() != null) {
                KmFunction f = sc.getKmLambda().getFunction();
                if (f != null) remapFunction(f, mapping, owner, changed);
            }
        } else if (md instanceof KotlinClassMetadata.MultiFileClassPart) {
            remapKmPackage(((KotlinClassMetadata.MultiFileClassPart) md).getKmPackage(), mapping, owner, changed);
        }
        // MultiFileClassFacade / Unknown: nothing class-name specific to rewrite.

        if (!changed[0]) return;

        Metadata out = md.write();
        // Rebuild the annotation values from the rewritten metadata. ASM stores
        // annotation array values as java.util.List (see ClassReader), so we
        // must write back List<Integer> for int[] and List<String> for String[].
        java.util.List<Object> vals = new java.util.ArrayList<>();
        addPair(vals, "k", out.k());
        if (out.mv() != null) addPair(vals, "mv", toList(out.mv()));
        if (out.bv() != null && out.bv().length > 0) addPair(vals, "bv", toList(out.bv()));
        if (out.d1() != null) addPair(vals, "d1", toList(out.d1()));
        if (out.d2() != null) addPair(vals, "d2", toList(out.d2()));
        if (out.xs() != null && !out.xs().isEmpty()) addPair(vals, "xs", out.xs());
        if (out.pn() != null && !out.pn().isEmpty()) addPair(vals, "pn", out.pn());
        if (out.xi() != 0) addPair(vals, "xi", out.xi());
        an.values.clear();
        an.values.addAll(vals);
        fixedClasses++;
    }

    private static void addPair(List<Object> vals, String k, Object v) {
        vals.add(k);
        vals.add(v);
    }

    /** ASM stores an int[] annotation value as List<Integer>. */
    @SuppressWarnings("unchecked")
    private static int[] toIntArray(Object v) {
        if (v instanceof int[]) return (int[]) v;
        if (v instanceof List) {
            List<?> l = (List<?>) v;
            int[] a = new int[l.size()];
            for (int i = 0; i < a.length; i++) a[i] = (Integer) l.get(i);
            return a;
        }
        return null;
    }

    /** ASM stores a String[] annotation value as List<String>. */
    @SuppressWarnings("unchecked")
    private static String[] toStringArr(Object v) {
        if (v instanceof String[]) return (String[]) v;
        if (v instanceof List) {
            List<?> l = (List<?>) v;
            String[] a = new String[l.size()];
            for (int i = 0; i < a.length; i++) a[i] = (String) l.get(i);
            return a;
        }
        return null;
    }

    private static List<Object> toList(int[] a) {
        List<Object> l = new java.util.ArrayList<>();
        for (int x : a) l.add(x);
        return l;
    }

    private static List<Object> toList(String[] a) {
        List<Object> l = new java.util.ArrayList<>();
        for (String s : a) l.add(s);
        return l;
    }

    // ------------------------------------------------------------------
    // Metadata tree rewriting
    // ------------------------------------------------------------------

    private void remapKmClass(KmClass c, Mapping m, String owner, boolean[] changed) {
        // KmClass.name is a dotted FQN (e.g. "com.kbox.ktdemo.Person"); the
        // mapping is keyed by slash-form internal names, so convert before
        // lookup and convert the result back to dotted form.
        String newName = mapDotted(m, c.getName());
        if (!newName.equals(c.getName())) {
            c.setName(newName);
            changed[0] = true;
        }
        for (KmType st : c.getSupertypes()) remapType(st, m, changed);
        // Sealed subclasses use slash package + '.'-separated nested names
        // (e.g. "com/kbox/ktdemo/Shape.Circle") — map via the JVM internal
        // form (last '.' -> '$') and restore the '.'-separated form.
        for (int i = 0; i < c.getSealedSubclasses().size(); i++) {
            String sc = c.getSealedSubclasses().get(i);
            String ns = mapSealed(m, sc);
            if (!ns.equals(sc)) {
                c.getSealedSubclasses().set(i, ns);
                changed[0] = true;
            }
        }
        // Nested classes are stored as relative simple names (e.g. "Circle").
        // Resolve them against the (mapped) owner to rewrite the simple name
        // to the renamed nested class's simple name.
        String ownerInternal = owner.replace('.', '/');
        String newOwnerInternal = m.mapClass(ownerInternal);
        for (int i = 0; i < c.getNestedClasses().size(); i++) {
            String nc = c.getNestedClasses().get(i);
            String oldInternal = ownerInternal + "$" + nc;
            String newInternal = m.mapClass(oldInternal);
            if (!newInternal.equals(oldInternal)) {
                int dollar = newInternal.lastIndexOf('$');
                String newSimple = dollar >= 0 ? newInternal.substring(dollar + 1) : newInternal;
                if (!newSimple.equals(nc)) {
                    c.getNestedClasses().set(i, newSimple);
                    changed[0] = true;
                }
            }
        }
        for (KmFunction f : c.getFunctions()) remapFunction(f, m, owner, changed);
        for (KmProperty p : c.getProperties()) remapProperty(p, m, owner, changed);
        for (KmConstructor ct : c.getConstructors()) remapConstructor(ct, m, owner, changed);
        for (KmTypeAlias ta : c.getTypeAliases()) {
            if (ta.getUnderlyingType() != null) remapType(ta.getUnderlyingType(), m, changed);
            if (ta.getExpandedType() != null) remapType(ta.getExpandedType(), m, changed);
        }
    }

    private void remapKmPackage(KmPackage pkg, Mapping m, String owner, boolean[] changed) {
        for (KmFunction f : pkg.getFunctions()) remapFunction(f, m, owner, changed);
        for (KmProperty p : pkg.getProperties()) remapProperty(p, m, owner, changed);
        for (KmTypeAlias ta : pkg.getTypeAliases()) {
            if (ta.getUnderlyingType() != null) remapType(ta.getUnderlyingType(), m, changed);
            if (ta.getExpandedType() != null) remapType(ta.getExpandedType(), m, changed);
        }
    }

    private void remapFunction(KmFunction f, Mapping m, String owner, boolean[] changed) {
        JvmMethodSignature sig = JvmExtensionsKt.getSignature(f);
        if (sig != null) {
            String nn = m.mapMethod(owner, sig.getName(), sig.getDesc());
            if (!nn.equals(sig.getName())) {
                JvmExtensionsKt.setSignature(f, new JvmMethodSignature(nn, sig.getDesc()));
                changed[0] = true;
            }
        }
        if (f.getReturnType() != null) remapType(f.getReturnType(), m, changed);
        if (f.getReceiverParameterType() != null) remapType(f.getReceiverParameterType(), m, changed);
        if (f.getValueParameters() != null) {
            for (KmValueParameter vp : f.getValueParameters()) remapValueParameter(vp, m, changed);
        }
        if (f.getTypeParameters() != null) {
            for (KmTypeParameter tp : f.getTypeParameters()) remapTypeParameter(tp, m, changed);
        }
    }

    private void remapProperty(KmProperty p, Mapping m, String owner, boolean[] changed) {
        JvmFieldSignature fs = JvmExtensionsKt.getFieldSignature(p);
        if (fs != null) {
            String nn = m.mapField(owner, fs.getName(), fs.getDesc());
            if (!nn.equals(fs.getName())) {
                JvmExtensionsKt.setFieldSignature(p, new JvmFieldSignature(nn, fs.getDesc()));
                changed[0] = true;
            }
        }
        remapAccessor(JvmExtensionsKt.getGetterSignature(p), nn -> {
            JvmExtensionsKt.setGetterSignature(p, nn);
            changed[0] = true;
        }, m, owner);
        remapAccessor(JvmExtensionsKt.getSetterSignature(p), nn -> {
            JvmExtensionsKt.setSetterSignature(p, nn);
            changed[0] = true;
        }, m, owner);
        remapAccessor(JvmExtensionsKt.getSyntheticMethodForAnnotations(p), nn -> {
            JvmExtensionsKt.setSyntheticMethodForAnnotations(p, nn);
            changed[0] = true;
        }, m, owner);
        remapAccessor(JvmExtensionsKt.getSyntheticMethodForDelegate(p), nn -> {
            JvmExtensionsKt.setSyntheticMethodForDelegate(p, nn);
            changed[0] = true;
        }, m, owner);
        if (p.getReturnType() != null) remapType(p.getReturnType(), m, changed);
        if (p.getReceiverParameterType() != null) remapType(p.getReceiverParameterType(), m, changed);
        if (p.getSetterParameter() != null) remapValueParameter(p.getSetterParameter(), m, changed);
    }

    private void remapAccessor(JvmMethodSignature sig, java.util.function.Consumer<JvmMethodSignature> setter,
                               Mapping m, String owner) {
        if (sig == null) return;
        String nn = m.mapMethod(owner, sig.getName(), sig.getDesc());
        if (!nn.equals(sig.getName())) {
            setter.accept(new JvmMethodSignature(nn, sig.getDesc()));
        }
    }

    private void remapConstructor(KmConstructor ct, Mapping m, String owner, boolean[] changed) {
        JvmMethodSignature sig = JvmExtensionsKt.getSignature(ct);
        if (sig != null) {
            String nn = m.mapMethod(owner, sig.getName(), sig.getDesc());
            if (!nn.equals(sig.getName())) {
                JvmExtensionsKt.setSignature(ct, new JvmMethodSignature(nn, sig.getDesc()));
                changed[0] = true;
            }
        }
        if (ct.getValueParameters() != null) {
            for (KmValueParameter vp : ct.getValueParameters()) remapValueParameter(vp, m, changed);
        }
    }

    private void remapValueParameter(KmValueParameter vp, Mapping m, boolean[] changed) {
        if (vp.getType() != null) remapType(vp.getType(), m, changed);
        if (vp.getVarargElementType() != null) remapType(vp.getVarargElementType(), m, changed);
    }

    private void remapTypeParameter(KmTypeParameter tp, Mapping m, boolean[] changed) {
        if (tp.getUpperBounds() != null) {
            for (KmType ub : tp.getUpperBounds()) remapType(ub, m, changed);
        }
    }

    private void remapType(KmType t, Mapping m, boolean[] changed) {
        if (t == null) return;
        KmClassifier cl = t.getClassifier();
        if (cl instanceof KmClassifier.Class) {
            String oldName = ((KmClassifier.Class) cl).getName();
            String newName = m.mapClass(oldName);
            if (!newName.equals(oldName)) {
                t.setClassifier(new KmClassifier.Class(newName));
                changed[0] = true;
            }
        }
        if (t.getArguments() != null) {
            for (kotlinx.metadata.KmTypeProjection arg : t.getArguments()) {
                if (arg.getType() != null) remapType(arg.getType(), m, changed);
            }
        }
        remapType(t.getAbbreviatedType(), m, changed);
        remapType(t.getOuterType(), m, changed);
        if (t.getFlexibleTypeUpperBound() != null) {
            remapType(t.getFlexibleTypeUpperBound().getType(), m, changed);
        }
    }

    /**
     * Maps a dotted FQN (e.g. {@code com.kbox.ktdemo.Person}) through the
     * slash-keyed class mapping and returns the result in dotted form. If the
     * class is not in the mapping the original dotted name is returned.
     *
     * <p>Nested-class FQNs are ambiguous: package dots become {@code '/'} while
     * nested-class dots become {@code '$'} in the JVM internal name (e.g.
     * {@code com.kbox.ktdemo.Greeter.Companion} -> {@code com/kbox/ktdemo/Greeter$Companion}).
     * We therefore enumerate every plausible internal-name split and map whichever
     * one is actually recorded in the rename map.
     */
    private static String mapDotted(Mapping m, String dotted) {
        for (String internal : internalCandidates(dotted)) {
            if (m.getClassMap().containsKey(internal)) {
                String ns = m.mapClass(internal);
                if (ns.equals(internal)) return dotted;
                return ns.replace('/', '.').replace('$', '.');
            }
        }
        return dotted;
    }

    /**
     * Enumerates all internal-name candidates for a dotted FQN, from the pure
     * package form (all dots -> '/') down through progressively nested forms
     * (trailing dots -> '$'). E.g. {@code a.b.C.D} yields
     * {@code a/b/C/D, a/b/C$D, a/b$C$D, a$b$C$D}.
     */
    private static java.util.List<String> internalCandidates(String dotted) {
        java.util.List<String> out = new java.util.ArrayList<>();
        String cur = dotted.replace('.', '/');
        out.add(cur);
        int slash = cur.lastIndexOf('/');
        while (slash > 0) {
            cur = cur.substring(0, slash) + "$" + cur.substring(slash + 1);
            out.add(cur);
            slash = cur.lastIndexOf('/');
        }
        return out;
    }

    /**
     * Maps a sealed-subclass reference, which uses slash package + '.'-separated
     * nested names (e.g. {@code com/kbox/ktdemo/Shape.Circle}). The last '.' is
     * the nested-class separator in the JVM internal name ({@code '$'}).
     */
    private static String mapSealed(Mapping m, String ref) {
        String internal = ref;
        if (internal.contains(".")) {
            int lastDot = internal.lastIndexOf('.');
            internal = internal.substring(0, lastDot) + "$" + internal.substring(lastDot + 1);
        }
        String ns = m.mapClass(internal);
        if (ns.equals(internal)) return ref;
        if (ns.contains("$")) {
            int lastDollar = ns.lastIndexOf('$');
            return ns.substring(0, lastDollar) + "." + ns.substring(lastDollar + 1);
        }
        return ns;
    }

    // ------------------------------------------------------------------
    // .kotlin_module files
    // ------------------------------------------------------------------

    private void fixModuleFiles(Mapping mapping) {
        Map<String, byte[]> updated = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            String path = e.getKey();
            if (!path.endsWith(KOTLIN_MODULE_SUFFIX)) continue;
            String text = new String(e.getValue(), StandardCharsets.UTF_8);
            String rewritten = rewriteAllClassRefs(text, mapping);
            if (!rewritten.equals(text)) {
                updated.put(path, rewritten.getBytes(StandardCharsets.UTF_8));
                fixedModules++;
            }
        }
        updated.forEach((k, v) -> graph.getResources().put(k, v));
    }

    private String rewriteAllClassRefs(String text, Mapping mapping) {
        String result = text;
        for (Map.Entry<String, String> e : mapping.getClassMap().entrySet()) {
            result = result.replace(e.getKey(), e.getValue());
            String oldDotted = e.getKey().replace('/', '.');
            String newDotted = e.getValue().replace('/', '.');
            result = result.replace(oldDotted, newDotted);
        }
        return result;
    }

    // ------------------------------------------------------------------
    // kotlin.Metadata proxy (annotation instances from raw values)
    // ------------------------------------------------------------------

    private static Metadata metadataProxy(Integer kind, int[] mv, String[] d1, String[] d2,
                                          String xs, String pn, Integer xi) {
        InvocationHandler h = (proxy, method, args) -> {
            switch (method.getName()) {
                case "k": return kind;
                case "mv": return mv == null ? new int[0] : mv;
                case "bv": return new int[0];
                case "d1": return d1 == null ? new String[0] : d1;
                case "d2": return d2 == null ? new String[0] : d2;
                case "xs": return xs == null ? "" : xs;
                case "pn": return pn == null ? "" : pn;
                case "xi": return xi == null ? 0 : xi;
                case "annotationType": return Metadata.class;
                case "toString": return "@kotlin.Metadata(k=" + kind + ")";
                case "hashCode": return 0;
                case "equals": return proxy == args[0];
                default: {
                    Object d = method.getDefaultValue();
                    return d;
                }
            }
        };
        return (Metadata) Proxy.newProxyInstance(
                Metadata.class.getClassLoader(),
                new Class<?>[]{Metadata.class},
                h);
    }
}