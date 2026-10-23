package com.kbox.core.sedvx;

import com.kbox.core.analysis.ClassGraph;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * SED-VX part A: the Semantic Atlas.
 *
 * <p>Builds the internal map the rest of the pipeline consults instead of
 * "obfuscate everything": classes, methods, call edges, sensitive string
 * literals and member names, plus the reflection/serialization/framework
 * markers that constrain what may be rewritten.
 *
 * <p>This is deliberately an <em>analysis-only</em> component. It does not
 * change a single byte; it produces the protection candidate list that
 * {@link CriticalSlicer} ranks and {@link SedVxWeaver} later rewrites. Keeping
 * analysis and rewriting separate is what lets the report describe exactly
 * which evidence was found and which of it was actually diffused.
 *
 * <p>The sensitivity lexicon is configurable in spirit but fixed here: it
 * covers the categories the SED-VX design names as high-value semantic
 * evidence (authentication, licensing, thresholds, money, secrets, SQL).
 */
public final class SemanticAtlas {

    /** One method plus the evidence and graph edges discovered for it. */
    public static final class MethodInfo {
        public final String owner;
        public final String name;
        public final String desc;
        /** Sensitive literals found in this method body (class/method evidence). */
        public final List<String> evidence = new ArrayList<>();
        public final List<String> callees = new ArrayList<>();
        public final List<String> callers = new ArrayList<>();
        /** Graph distance to the nearest evidence-bearing method (0 = itself). */
        public int depth = Integer.MAX_VALUE;
        /** Framework constraint: reflection/serialization/JNI sensitive. */
        public boolean constrained;

        MethodInfo(String owner, String name, String desc) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
        }

        public String key() { return owner + "#" + name + desc; }
        public boolean sensitive() { return !evidence.isEmpty(); }
    }

    private static final Pattern SENSITIVE = Pattern.compile(
            "password|passwd|pwd|token|secret|apikey|api_key|license|licen[cs]e|activation|"
                    + "auth|credential|signature|verify|validate|admin|root|balance|"
                    + "amount|price|payment|order|quota|expire|entitle|sql|select |insert |"
                    + "update |delete |jdbc|verifylicense|serial|machinecode");

    private final Map<String, MethodInfo> methods = new LinkedHashMap<>();
    private final Map<String, String> superOf = new LinkedHashMap<>();
    private final Map<String, Integer> classEvidence = new LinkedHashMap<>();
    private int classCount;
    private int methodCount;

    public Map<String, MethodInfo> methods() { return methods; }
    public Map<String, String> superOf() { return superOf; }
    public Map<String, Integer> classEvidence() { return classEvidence; }
    public int classCount() { return classCount; }
    public int methodCount() { return methodCount; }

    /** Builds the atlas from an already-parsed class graph (read-only). */
    @SuppressWarnings("unchecked")
    public static SemanticAtlas build(ClassGraph graph) {
        SemanticAtlas a = new SemanticAtlas();
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.name == null || cn.name.startsWith("com/kbox/runtime/")) continue;
            a.classCount++;
            a.superOf.put(cn.name, cn.superName);
            int classHits = score(cn.name.replace('/', '.'));
            for (FieldNode fn : (List<FieldNode>) cn.fields) {
                if (fn.name == null) continue;
                int s = score(fn.name) + (fn.value instanceof String ? score((String) fn.value) : 0);
                if (s > 0) {
                    MethodInfo mi = a.methods.get(cn.name + "#<fields>");
                    if (mi == null) {
                        mi = new MethodInfo(cn.name, "<fields>", "");
                        a.methods.put(mi.key(), mi);
                    }
                    mi.evidence.add("field:" + fn.name);
                    classHits += s;
                }
            }
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                a.methodCount++;
                MethodInfo mi = new MethodInfo(cn.name, mn.name, mn.desc);
                int s = score(mn.name);
                if (s > 0) mi.evidence.add("name:" + mn.name);
                boolean constrained = false;
                for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
                    if (ins instanceof LdcInsnNode) {
                        Object c = ((LdcInsnNode) ins).cst;
                        if (c instanceof String) {
                            int ls = score((String) c);
                            if (ls > 0) {
                                mi.evidence.add("str:" + clip((String) c));
                                s += ls;
                            }
                        }
                    } else if (ins instanceof MethodInsnNode) {
                        MethodInsnNode m = (MethodInsnNode) ins;
                        mi.callees.add(m.owner + "#" + m.name + m.desc);
                        if (isReflective(m.owner, m.name)) constrained = true;
                    } else if (ins.getOpcode() == Opcodes.INVOKEDYNAMIC) {
                        constrained = true; // indy: string concat / lambda / proxy
                    }
                }
                if (mn.name.startsWith("access$") || mn.name.equals("<clinit>")) constrained = true;
                mi.constrained = constrained;
                if (s > 0) classHits += s;
                a.methods.put(mi.key(), mi);
            }
            if (classHits > 0) a.classEvidence.put(cn.name, classHits);
        }
        // Reverse edges + depth propagation (BFS from evidence-bearing methods).
        for (MethodInfo mi : a.methods.values()) {
            for (String c : mi.callees) {
                MethodInfo callee = a.methods.get(c);
                if (callee != null) callee.callers.add(mi.key());
            }
        }
        List<MethodInfo> frontier = new ArrayList<>();
        for (MethodInfo mi : a.methods.values()) {
            if (mi.sensitive()) { mi.depth = 0; frontier.add(mi); }
        }
        for (int d = 1; d <= 2 && !frontier.isEmpty(); d++) {
            List<MethodInfo> next = new ArrayList<>();
            for (MethodInfo mi : frontier) {
                for (String ck : mi.callers) {
                    MethodInfo up = a.methods.get(ck);
                    if (up != null && up.depth > d) { up.depth = d; next.add(up); }
                }
                for (String ck : mi.callees) {
                    MethodInfo down = a.methods.get(ck);
                    if (down != null && down.depth > d) { down.depth = d; next.add(down); }
                }
            }
            frontier = next;
        }
        return a;
    }

    private static boolean isReflective(String owner, String name) {
        return ("java/lang/Class".equals(owner)
                && ("forName".equals(name) || "getDeclaredMethod".equals(name)
                || "getMethod".equals(name) || "getField".equals(name)
                || "getDeclaredField".equals(name)))
                || "java/lang/invoke/MethodHandles".equals(owner)
                || "java/lang/reflect/Proxy".equals(owner);
    }

    /** Cheap lexical sensitivity score; higher = more semantic evidence. */
    static int score(String s) {
        if (s == null || s.isEmpty()) return 0;
        String lower = s.toLowerCase(java.util.Locale.ROOT);
        java.util.regex.Matcher m = SENSITIVE.matcher(lower);
        int hits = 0;
        while (m.find()) hits++;
        return hits;
    }

    private static String clip(String s) {
        String t = s.replace('\n', ' ').replace('\r', ' ').replace('"', '\'');
        return t.length() > 48 ? t.substring(0, 48) + "..." : t;
    }

    /** Serialises the atlas summary (counts + ranked evidence, no bytecode). */
    public String toJson(int maxRows) {
        StringBuilder sb = new StringBuilder(1024);
        sb.append("{\"classes\":").append(classCount)
                .append(",\"methods\":").append(methodCount)
                .append(",\"sensitiveMethods\":").append(sensitiveCount())
                .append(",\"sensitiveClasses\":").append(classEvidence.size())
                .append(",\"methodsWithEvidence\":[");
        int n = 0;
        for (MethodInfo mi : methods.values()) {
            if (!mi.sensitive()) continue;
            if (n++ > 0) sb.append(',');
            if (n > maxRows) { sb.append("{\"truncated\":true}"); break; }
            sb.append("{\"owner\":\"").append(esc(mi.owner))
                    .append("\",\"name\":\"").append(esc(mi.name))
                    .append("\",\"desc\":\"").append(esc(mi.desc))
                    .append("\",\"score\":").append(mi.evidence.size())
                    .append(",\"evidence\":[");
            for (int i = 0; i < mi.evidence.size() && i < 6; i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(esc(mi.evidence.get(i))).append('"');
            }
            sb.append("]}");
        }
        sb.append("]}");
        return sb.toString();
    }

    public int sensitiveCount() {
        int n = 0;
        for (MethodInfo mi : methods.values()) if (mi.sensitive()) n++;
        return n;
    }

    static String esc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }
}
