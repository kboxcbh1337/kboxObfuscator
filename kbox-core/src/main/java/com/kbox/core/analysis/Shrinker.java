package com.kbox.core.analysis;

import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 可达性收缩（unused class / method / field / resource）。
 *
 * <p>以入口点与 keep 集合为根，沿 {@link ClassGraph#getReferences()} 做传递闭包；
 * 未被任何根到达且不属于库/KBox 运行时的类被删除。成员层只删除
 * <b>private</b> 且未被任何字节码引用的成员（含 invokedynamic 的 MethodHandle），
 * 避免破坏虚调用、反射与序列化契约。</p>
 *
 * <p>默认关闭：删除反射加载的类会改变运行期行为。开启后 MC mod 会自动跳过
 * （宿主加载器按名称/注解发现类）。资源删除额外要求 {@code shrinkResources}
 * 且只处理文本类资源。</p>
 */
public final class Shrinker {

    private static final String TAG = "shrink";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public Shrinker(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isShrink()) return;
        if (isMinecraftMod()) {
            KBoxLog.warn(TAG, "Shrinking skipped for a Minecraft mod jar "
                    + "(the host loader discovers classes by name/annotation)");
            return;
        }

        Set<String> roots = collectRoots();
        Set<String> live = closure(roots);
        int removedClasses = 0;
        Iterator<Map.Entry<String, ClassNode>> ci = graph.getClasses().entrySet().iterator();
        while (ci.hasNext()) {
            Map.Entry<String, ClassNode> e = ci.next();
            String n = e.getKey();
            if (live.contains(n)) continue;
            if (isProtected(n)) continue;
            ci.remove();
            graph.getOriginalBytes().remove(n);
            removedClasses++;
        }

        int removedMembers = 0;
        if (cfg.isShrinkMembers()) {
            removedMembers = shrinkMembers(live);
        }
        int removedResources = 0;
        if (cfg.isShrinkResources()) {
            removedResources = shrinkResources(live);
        }
        KBoxLog.info(TAG, "Reachability: roots=" + roots.size() + " live=" + live.size()
                + " removed_classes=" + removedClasses
                + " removed_members=" + removedMembers
                + " removed_resources=" + removedResources);
    }

    // ------------------------------------------------------------------

    private Set<String> collectRoots() {
        Set<String> roots = new HashSet<String>();
        if (graph.getManifestMainClass() != null) {
            roots.add(graph.getManifestMainClass().replace('.', '/'));
        }
        if (graph.getManifestStartClass() != null) {
            roots.add(graph.getManifestStartClass().replace('.', '/'));
        }
        if (cfg.getMainClass() != null && !cfg.getMainClass().isEmpty()) {
            roots.add(cfg.getMainClass().replace('.', '/'));
        }
        for (String e : cfg.getEntryPoints()) {
            if (e != null && !e.isEmpty()) roots.add(e.replace('.', '/'));
        }
        for (MemberRef m : graph.getKeepSet()) {
            if (m.isClassRef()) roots.add(m.owner);
        }
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.name.startsWith("com/kbox/")) roots.add(cn.name);
        }
        return roots;
    }

    private Set<String> closure(Set<String> roots) {
        Set<String> live = new HashSet<String>();
        ArrayDeque<String> q = new ArrayDeque<String>();
        for (String r : roots) {
            if (r != null && graph.getClasses().containsKey(r)) q.add(r);
        }
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!live.add(c)) continue;
            Set<String> refs = graph.getReferences().get(c);
            if (refs == null) continue;
            for (String r : refs) {
                if (r != null && graph.getClasses().containsKey(r) && !live.contains(r)) {
                    q.add(r);
                }
            }
        }
        return live;
    }

    private boolean isProtected(String n) {
        if (n == null) return true;
        if (n.startsWith("com/kbox/")) return true;
        if (cfg.isLibraryClass(n)) return true;
        if (graph.getNestedJarClasses().contains(n)) return true;
        if (graph.getMultiReleaseClasses().contains(n)) return true;
        if (cfg.isKept(n)) return true;
        for (String p : cfg.getKeepPrefixes()) {
            if (p == null || p.isEmpty()) continue;
            if (n.replace('/', '.').startsWith(p) || n.startsWith(p)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------

    private int shrinkMembers(Set<String> live) {
        Set<String> refs = new HashSet<String>();
        for (String owner : live) {
            ClassNode cn = graph.getClasses().get(owner);
            if (cn == null) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null;
                     ins = ins.getNext()) {
                    if (ins instanceof MethodInsnNode) {
                        MethodInsnNode mi = (MethodInsnNode) ins;
                        refs.add(mi.owner + "#" + mi.name + "#" + mi.desc);
                    } else if (ins instanceof FieldInsnNode) {
                        FieldInsnNode fi = (FieldInsnNode) ins;
                        refs.add(fi.owner + "#" + fi.name + "#" + fi.desc);
                    } else if (ins instanceof InvokeDynamicInsnNode) {
                        InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) ins;
                        addHandle(refs, id.bsm);
                        for (Object a : id.bsmArgs) {
                            if (a instanceof Handle) addHandle(refs, (Handle) a);
                        }
                    } else if (ins instanceof LdcInsnNode) {
                        Object c = ((LdcInsnNode) ins).cst;
                        if (c instanceof Handle) addHandle(refs, (Handle) c);
                    }
                }
            }
        }
        for (MemberRef m : graph.getKeepSet()) {
            if (!m.isClassRef()) {
                refs.add(m.owner + "#" + m.name + "#" + (m.desc == null ? "" : m.desc));
            }
        }

        int removed = 0;
        for (String owner : live) {
            ClassNode cn = graph.getClasses().get(owner);
            if (cn == null) continue;
            List<MethodNode> keepMethods = new ArrayList<MethodNode>();
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                boolean priv = (mn.access & Opcodes.ACC_PRIVATE) != 0;
                boolean special = mn.name.startsWith("<");
                boolean referenced = refs.contains(owner + "#" + mn.name + "#" + mn.desc);
                boolean kept = cfg.isKeptMember(owner, mn.name, mn.desc);
                if (priv && !special && !referenced && !kept) {
                    removed++;
                } else {
                    keepMethods.add(mn);
                }
            }
            if (keepMethods.size() != cn.methods.size()) cn.methods = keepMethods;

            List<FieldNode> keepFields = new ArrayList<FieldNode>();
            for (FieldNode fn : (List<FieldNode>) cn.fields) {
                boolean priv = (fn.access & Opcodes.ACC_PRIVATE) != 0;
                boolean referenced = refs.contains(owner + "#" + fn.name + "#" + fn.desc);
                boolean kept = cfg.isKeptMember(owner, fn.name, fn.desc)
                        || "serialVersionUID".equals(fn.name);
                if (priv && !referenced && !kept) {
                    removed++;
                } else {
                    keepFields.add(fn);
                }
            }
            if (keepFields.size() != cn.fields.size()) cn.fields = keepFields;
        }
        return removed;
    }

    private static void addHandle(Set<String> refs, Handle h) {
        if (h == null) return;
        refs.add(h.getOwner() + "#" + h.getName() + "#" + h.getDesc());
    }

    // ------------------------------------------------------------------

    private int shrinkResources(Set<String> live) {
        Set<String> strings = new HashSet<String>();
        for (String owner : live) {
            ClassNode cn = graph.getClasses().get(owner);
            if (cn == null) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null;
                     ins = ins.getNext()) {
                    if (ins instanceof LdcInsnNode) {
                        Object c = ((LdcInsnNode) ins).cst;
                        if (c instanceof String) strings.add((String) c);
                    }
                }
            }
        }
        int removed = 0;
        Iterator<Map.Entry<String, byte[]>> it = graph.getResources().entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, byte[]> e = it.next();
            String path = e.getKey();
            if (path == null) continue;
            if (!isTextResource(path)) continue;
            if (path.startsWith("META-INF/")) continue;
            if (isProtectedResource(path)) continue;
            boolean referenced = false;
            for (String s : strings) {
                if (s != null && (s.equals(path) || path.endsWith(s)
                        || s.endsWith(path))) {
                    referenced = true;
                    break;
                }
            }
            if (!referenced) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    private static boolean isTextResource(String path) {
        String p = path.toLowerCase(java.util.Locale.ROOT);
        return p.endsWith(".txt") || p.endsWith(".json") || p.endsWith(".xml")
                || p.endsWith(".properties") || p.endsWith(".yml") || p.endsWith(".yaml")
                || p.endsWith(".csv") || p.endsWith(".conf") || p.endsWith(".cfg");
    }

    private boolean isProtectedResource(String path) {
        for (String p : cfg.getExcludeResourcePatterns()) {
            if (p == null || p.isEmpty()) continue;
            String pp = p.replace("*", "");
            if (path.equals(pp) || path.startsWith(pp) || path.endsWith(pp)) return true;
        }
        return false;
    }

    private boolean isMinecraftMod() {
        Map<String, byte[]> r = graph.getResources();
        return r.containsKey("fabric.mod.json") || r.containsKey("META-INF/mods.toml")
                || r.containsKey("META-INF/neoforge.mods.toml")
                || r.containsKey("mcmod.info") || r.containsKey("plugin.yml")
                || (graph.getManifest() != null
                    && new String(graph.getManifest(), StandardCharsets.UTF_8)
                        .contains("TweakClass:"));
    }
}
