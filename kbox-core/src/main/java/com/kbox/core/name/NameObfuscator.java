package com.kbox.core.name;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.analysis.MemberRef;
import com.kbox.core.config.FileSelector;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ZKM-style identifier obfuscation: renames classes (simple name only; packages
 * are preserved to keep Spring/component-scan &amp; resource-path lookups working),
 * methods and fields while respecting override equivalence and the retention
 * decision tree.
 *
 * <p>Algorithm:
 * <ol>
 *   <li>Union-find over the class hierarchy so two classes that share an
 *       inheritance edge end up in the same <em>component</em>.</li>
 *   <li>For every distinct {@code (name, desc)} pair, gather all declaring
 *       owners; those that share a component form one <em>rename group</em>.</li>
 *   <li>A group is renamed iff <strong>none</strong> of its members is kept
 *       (so a single kept override pins the whole group, matching JVM
 *       override semantics). The same new name is assigned to every member.</li>
 *   <li>Classes are renamed if not kept; only the simple name changes.</li>
 * </ol>
 *
 * The resulting {@link Mapping} is applied via a custom {@link Remapper} that
 * walks the super chain for inherited members so method/field instructions
 * referencing an inheritor still resolve to the group's new name.
 */
public final class NameObfuscator {

    private static final String TAG = "names";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final Mapping mapping = new Mapping();
    private final RetentionDecision decision;

    public NameObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
        this.decision = new RetentionDecision(graph, cfg);
    }

    public Mapping compute() {
        // Z9 incremental: pre-load class renames from a previous build's
        // mapping file (if configured) so they're reused below.
        MappingLoader.loadInto(mapping, cfg.getUseMapping());
        buildUnionFind();
        renameClasses();
        renameMethods();
        renameFields();
        KBoxLog.info(TAG, "Renamed " + mapping.getClassMap().size() + " classes, "
                + mapping.getMethodMap().size() + " methods, "
                + mapping.getFieldMap().size() + " fields");
        return mapping;
    }

    // ---------- class renaming ----------

    /**
     * Renames classes. When {@code renamePackages} is enabled, the entire
     * package path is replaced with a random obfuscated package, so the
     * decompiled directory structure becomes meaningless (e.g.
     * {@code com.example.service.User} -> {@code a.b.c.X}). Otherwise only the
     * simple class name is renamed and the package is preserved (default, for
     * Spring/component-scan &amp; resource-path compatibility).
     *
     * <p>Package renaming keeps the same depth as the original to preserve
     * Spring Boot's {@code BOOT-INF/classes/} layout expectations, and never
     * renames the package of a kept class (entry points, reflection targets,
     * Mixin classes, etc.).
     */
    private void renameClasses() {
        if (!cfg.isRenameIdentifiers()) return;   // rename=false: 类/方法/字段均不重命名
        // Deterministic package map when renamePackages is on: every class of
        // an ORIGINAL package (including nested '$' classes, which share the
        // enclosing class's package) must land in the SAME new package, and a
        // package that contains a kept or library class keeps its original
        // name. Otherwise package-private access breaks (e.g. a package-private
        // enum used by its enclosing class ends up in a different package ->
        // IllegalAccessError at runtime).
        Map<String, String> newPkgs = null;
        if (cfg.isRenamePackages()) {
            newPkgs = new HashMap<>();
            Map<String, Boolean> pkgSpecial = new HashMap<>();
            for (String internal : graph.getClasses().keySet()) {
                int slash = internal.lastIndexOf('/');
                if (slash < 0) continue;
                String pkg = internal.substring(0, slash);
                boolean special = decision.keepClass(internal)
                        || !cfg.shouldTransformClass(internal);
                pkgSpecial.merge(pkg, special, Boolean::logicalOr);
            }
            for (String internal : graph.getClasses().keySet()) {
                int slash = internal.lastIndexOf('/');
                if (slash < 0) continue;
                String pkg = internal.substring(0, slash);
                if (Boolean.TRUE.equals(pkgSpecial.get(pkg))) {
                    newPkgs.put(pkg, pkg);
                } else {
                    newPkgs.computeIfAbsent(pkg, k -> randomPackageName(k));
                }
            }
        }
        for (String internal : graph.getClasses().keySet()) {
            if (decision.keepClass(internal)) continue;
            // Library classes are never renamed (single canonical decision via
            // LibraryClassifier — covers JDK, commons-lang3, Guava, Spring, etc.).
            if (!cfg.shouldTransformClass(internal)) continue;
            int slash = internal.lastIndexOf('/');
            String newName;
            // Z9 incremental reuse: if the old mapping already renamed this
            // class (loaded via MappingLoader.loadInto), reuse that exact name
            // so the class keeps the same obfuscated identity across versions.
            // Only honoured when the mapped name is not itself already taken by
            // a different current class (safe collision guard).
            String oldMapped = mapping.getClassMap().get(internal);
            if (oldMapped != null && !oldMapped.equals(internal)
                    && !graph.getClasses().containsKey(oldMapped)) {
                newName = oldMapped;
            } else if (cfg.isRenamePackages()) {
                // Folder/package randomization: replace the whole package path
                // with a freshly generated one of the same depth. This makes
                // the decompiled directory structure meaningless while keeping
                // the same nesting depth (preserves tooling assumptions).
                String pkg = slash >= 0 ? internal.substring(0, slash) : "";
                String newPkg = pkg.isEmpty() ? "" : newPkgs.get(pkg);
                newName = newPkg.isEmpty() ? mapping.newName() : newPkg + "/" + mapping.newName();
            } else {
                String pkg = slash >= 0 ? internal.substring(0, slash + 1) : "";
                newName = pkg + mapping.newName();
            }
            mapping.mapClass(internal, newName);
        }
    }

    /**
     * Generate a random package of the same depth as the original. Each path
     * segment is a short random identifier. The first segment is short (1-2
     * chars) to keep the layout compact; deeper segments use longer names.
     */
    private String randomPackageName(String pkg) {
        String[] segs = pkg.split("/");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segs.length; i++) {
            if (i > 0) sb.append('/');
            // Each obfuscated segment is a fresh short name. We reuse the
            // mapping's name generator so the names are consistent with the
            // class-name generator's pool.
            sb.append(mapping.newName());
        }
        return sb.toString();
    }

    // ---------- method renaming (override-equivalence aware) ----------

    @SuppressWarnings("unchecked")
    private void renameMethods() {
        if (!cfg.isRenameIdentifiers()) return;   // rename=false: 跳过
        // 1. Index every declared method by (name#desc) -> list of owners.
        Map<String, List<String>> byNameDesc = new HashMap<>();
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.methods == null) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.name.charAt(0) == '<') continue; // never rename ctors
                byNameDesc.computeIfAbsent(mn.name + "#" + mn.desc,
                        k -> new ArrayList<>()).add(cn.name);
            }
        }
        // 2. For each (name,desc), group owners by inheritance component and decide.
        for (Map.Entry<String, List<String>> e : byNameDesc.entrySet()) {
            int hash = e.getKey().indexOf('#');
            String name = e.getKey().substring(0, hash);
            String desc = e.getKey().substring(hash + 1);
            List<String> owners = e.getValue();
            // Group by find() component.
            Map<String, List<String>> groups = new HashMap<>();
            for (String o : owners) {
                groups.computeIfAbsent(find(o), k -> new ArrayList<>()).add(o);
            }
            for (List<String> group : groups.values()) {
                renameMethodGroup(group, name, desc);
            }
        }
    }

    private void renameMethodGroup(List<String> owners, String name, String desc) {
        // If ANY member is kept, pin the entire group to its original name.
        for (String o : owners) {
            ClassNode cn = graph.getClasses().get(o);
            if (cn != null && decision.keepMethod(cn, name, desc)) {
                return; // keep original name for everyone
            }
        }
        // Otherwise assign one shared new name to all members of the group.
        String newName = mapping.newName();
        for (String o : owners) {
            mapping.mapMethod(o, name, desc, newName);
        }
    }

    // ---------- field renaming ----------

    @SuppressWarnings("unchecked")
    private void renameFields() {
        if (!cfg.isRenameIdentifiers()) return;   // rename=false: 跳过
        // Fields don't have override semantics, but a field hidden by a same-named
        // field in a subclass is independent; rename each declaration independently.
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.fields == null) continue;
            for (FieldNode fn : (List<FieldNode>) cn.fields) {
                if (decision.keepField(cn, fn.name, fn.desc)) continue;
                mapping.mapField(cn.name, fn.name, fn.desc, mapping.newName());
            }
        }
    }

    // ---------- union-find over the class hierarchy ----------

    private final Map<String, String> parent = new HashMap<>();

    private void buildUnionFind() {
        for (String c : graph.getClasses().keySet()) parent.put(c, c);
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.superName != null && graph.getClasses().containsKey(cn.superName)) {
                union(cn.name, cn.superName);
            }
            if (cn.interfaces != null) {
                for (String itf : (List<String>) cn.interfaces) {
                    if (graph.getClasses().containsKey(itf)) union(cn.name, itf);
                }
            }
        }
    }

    private String find(String x) {
        String root = x;
        while (true) {
            String p = parent.get(root);
            if (p == null || p.equals(root)) break;
            root = p;
        }
        // Path compression.
        String cur = x;
        while (!cur.equals(root)) {
            String p = parent.get(cur);
            parent.put(cur, root);
            cur = p;
        }
        return root;
    }

    private void union(String a, String b) {
        String ra = find(a), rb = find(b);
        if (!ra.equals(rb)) parent.put(ra, rb);
    }

    // ---------- apply to a single class ----------

    /** Rewrite one ClassNode in place using the computed mapping. */
    public ClassNode apply(ClassNode src) {
        // Pre-pass: rewrite LambdaMetafactory SAM-method names so lambda
        // invokedynamic bootstrap args stay consistent after renaming the
        // functional-interface method (see rewriteLambdas javadoc).
        rewriteLambdas(src);
        ClassNode out = new ClassNode();
        ClassRemapper remapper = new ClassRemapper(out, new KBoxRemapper(graph, mapping, decision));
        src.accept(remapper);
        return out;
    }

    /**
     * Rewrites the SAM-method name of {@code LambdaMetafactory} call sites so
     * the function generated for a lambda implements the <em>renamed</em>
     * functional-interface method.
     *
     * <p>Two things must stay consistent after renaming an interface SAM:
     * <ul>
     *   <li><b>the invokedynamic {@code name}</b> — this is what the JVM's
     *       {@code LambdaMetafactory} uses to select which interface method the
     *       generated {@code X$$Lambda} class implements. ASM's
     *       {@link ClassRemapper} leaves it untouched, so if the engine renames
     *       the SAM it keeps the old name and the lambda silently binds to the
     *       wrong method.</li>
     *   <li>the plain {@link String} SAM name sometimes present as an extra
     *       bootstrap arg (index 3 / alt-index), kept in sync for compilers that
     *       emit it.</li>
     * </ul>
     * Without this the JVM fails with {@code VerifyError: ... does not define or
     * inherit an implementation of the resolved method '...' (a lambda-wrapper
     * that only surfaces when the obfuscated tool processes real input)). This
     * is required for renaming any JVM code that uses lambdas.
     */
    private void rewriteLambdas(ClassNode cn) {
        if (cn == null || cn.methods == null) return;
        for (Object mo : cn.methods) {
            org.objectweb.asm.tree.MethodNode mn = (org.objectweb.asm.tree.MethodNode) mo;
            if (mn.instructions == null) continue;
            for (org.objectweb.asm.tree.AbstractInsnNode i = mn.instructions.getFirst(); i != null; i = i.getNext()) {
                if (i instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode) {
                    org.objectweb.asm.tree.InvokeDynamicInsnNode indy =
                            (org.objectweb.asm.tree.InvokeDynamicInsnNode) i;
                    if (indy.bsm != null
                            && "java/lang/invoke/LambdaMetafactory".equals(indy.bsm.getOwner())
                            && indy.bsmArgs != null && indy.bsmArgs.length >= 3) {
                        // SAM method type is bootstrap arg 0 (the erasure of the
                        // interface method). Its name matches the indy name.
                        String samName = indy.name;
                        String samDesc = (indy.bsmArgs[0] instanceof Type)
                                ? ((Type) indy.bsmArgs[0]).getDescriptor() : null;
                        // The functional interface is the invokedynamic's return
                        // type (e.g. ()Lcom/kbox/core/concurrent/ae;). Resolve
                        // against that owner first, falling back to the classes
                        // the declaring class implements.
                        String mapped = resolveSamByOwner(indy.desc, samName, samDesc);
                        if (mapped == null) {
                            mapped = resolveSamInInterfaces(cn, samName, samDesc);
                        }
                        if (mapped != null && !mapped.equals(samName)) {
                            indy.name = mapped;
                            // Some compilers also embed the SAM name as an extra
                            // String bootstrap arg (metafactory index 3, alt index 4).
                            // Keep it in sync if present.
                            for (int ai = 3; ai < indy.bsmArgs.length; ai++) {
                                if (indy.bsmArgs[ai] instanceof String) {
                                    indy.bsmArgs[ai] = mapped;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /** Find the renamed name of the SAM method on the interfaces this class implements. */
    private String resolveSamInInterfaces(ClassNode cn, String samName, String samDesc) {
        if (samName == null) return null;
        Set<String> visited = new java.util.HashSet<>();
        java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
        collectInterfaces(cn, visited, queue);
        while (!queue.isEmpty()) {
            String itf = queue.poll();
            if (!itf.startsWith("java/") && mapping.hasMethod(itf, samName, samDesc)) {
                return mapping.mapMethod(itf, samName, samDesc);
            }
        }
        return null;
    }

    /**
     * Resolve the SAM method name from a LambdaMetafactory invokedynamic using
     * the functional-interface owner taken from the indy descriptor's return
     * type (e.g. {@code ()Lcom/kbox/core/concurrent/ae;} -> owner
     * {@code com/kbox/core/concurrent/ae}). The declaring class often does not
     * itself implement the interface (it just captures a lambda), so we cannot
     * rely on {@link #resolveSamInInterfaces} alone.
     */
    private String resolveSamByOwner(String indyDesc, String samName, String samDesc) {
        if (samName == null || indyDesc == null) return null;
        try {
            Type ret = Type.getMethodType(indyDesc).getReturnType();
            String owner = ret.getInternalName();
            if (owner != null && !owner.startsWith("java/")
                    && mapping.hasMethod(owner, samName, samDesc)) {
                return mapping.mapMethod(owner, samName, samDesc);
            }
        } catch (Exception ignore) {
            // fall through to resolveSamInInterfaces
        }
        return null;
    }

    private void collectInterfaces(ClassNode node, Set<String> visited, java.util.ArrayDeque<String> queue) {
        if (node == null) return;
        if (node.interfaces != null) {
            for (Object o : node.interfaces) {
                String itf = (String) o;
                if (visited.add(itf)) queue.add(itf);
            }
        }
        if (node.superName != null && !node.superName.startsWith("java/")) {
            ClassNode sup = graph.getClasses().get(node.superName);
            if (sup != null) collectInterfaces(sup, visited, queue);
        }
    }

    public Mapping getMapping() { return mapping; }

    /**
     * Remapper that consults {@link Mapping} and walks the inheritance chain
     * for inherited members (instructions often reference an inheriting class
     * rather than the actual declaring class).
     */
    static final class KBoxRemapper extends Remapper {
        private final ClassGraph graph;
        private final Mapping mapping;
        private final RetentionDecision decision;

        KBoxRemapper(ClassGraph g, Mapping m, RetentionDecision d) {
            this.graph = g; this.mapping = m; this.decision = d;
        }

        @Override
        public String map(String internalName) {
            return mapping.mapClass(internalName);
        }

        @Override
        public String mapMethodName(String owner, String name, String desc) {
            // Constructors keep their name.
            if (name.charAt(0) == '<') return name;
            String mapped = resolveMethod(owner, name, desc);
            return mapped != null ? mapped : name;
        }

        @Override
        public String mapFieldName(String owner, String name, String desc) {
            String mapped = resolveField(owner, name, desc);
            return mapped != null ? mapped : name;
        }

        /** Walk owner via super classes AND interfaces until the declaring member is found. */
        private String resolveMethod(String owner, String name, String desc) {
            Set<String> visited = new HashSet<>(8);
            java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
            queue.add(owner);
            visited.add(owner);
            while (!queue.isEmpty()) {
                String cur = queue.poll();
                if (cur.startsWith("java/")) continue;
                if (mapping.hasMethod(cur, name, desc)) {
                    return mapping.mapMethod(cur, name, desc);
                }
                ClassNode cn = graph.getClasses().get(cur);
                if (cn == null) continue;
                if (cn.superName != null && visited.add(cn.superName)) queue.add(cn.superName);
                if (cn.interfaces != null) {
                    for (String itf : (List<String>) cn.interfaces) {
                        if (visited.add(itf)) queue.add(itf);
                    }
                }
            }
            return null;
        }

        private String resolveField(String owner, String name, String desc) {
            Set<String> visited = new HashSet<>(8);
            java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
            queue.add(owner);
            visited.add(owner);
            while (!queue.isEmpty()) {
                String cur = queue.poll();
                if (cur.startsWith("java/")) continue;
                if (mapping.hasField(cur, name, desc)) {
                    return mapping.mapField(cur, name, desc);
                }
                ClassNode cn = graph.getClasses().get(cur);
                if (cn == null) continue;
                if (cn.superName != null && visited.add(cn.superName)) queue.add(cn.superName);
                if (cn.interfaces != null) {
                    for (String itf : (List<String>) cn.interfaces) {
                        if (visited.add(itf)) queue.add(itf);
                    }
                }
            }
            return null;
        }
    }
}
