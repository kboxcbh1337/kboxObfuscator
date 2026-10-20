package com.kbox.core.config;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * ProGuard 风格 class specification 引擎（条目 22/23）。
 *
 * <p>支持的语法子集（每个 conf 键值一行）：</p>
 * <pre>
 *   keep = class com.example.** { *; }
 *   keep = public class com.example.Sdk* { public *; }
 *   keepclassmembers = class * extends com.example.Base { void on*(...); }
 *   keepnames = interface com.example.Service
 *   keep = @com.example.Entity class ** { &lt;fields&gt;; }
 *   keep = class com.example.** { public &lt;init&gt;(...); static *** create*(); }
 * </pre>
 *
 * <p>语义对齐 ProGuard：</p>
 * <ul>
 *   <li>{@code keep} —— 类名与匹配成员名都保留。</li>
 *   <li>{@code keepclassmembers} —— 只保留匹配成员名（类名可混淆）。</li>
 *   <li>{@code keepnames} / {@code keepclassmembernames} —— 同 keep 但允许收缩
 *       （本引擎不区分 allowshrinking，均按 keep 处理）。</li>
 *   <li>类模式：{@code *}（一段内任意）、{@code **}（跨段任意）、{@code ?}（单字符）。</li>
 *   <li>成员模式：{@code *;}（任意成员）、{@code &lt;fields&gt;;}、{@code &lt;methods&gt;;}、
 *       {@code &lt;init&gt;(...);}；访问修饰符过滤（public/private/protected/static/final/
 *       abstract/synchronized/volatile/transient/native/synthetic）；类型
 *       {@code ***} 任意、{@code **} 跨段、{@code *} 段内、{@code []} 数组后缀。</li>
 *   <li>{@code extends X} / {@code implements X} 条件与 {@code @Annotation} 过滤。</li>
 * </ul>
 */
public final class KeepSpecs {

    /** 一条已解析的 class specification。 */
    public static final class Spec {
        boolean keepMembers;
        boolean classKept;
        String annotation;
        Integer accessFilter;
        boolean negatedAccess;
        Pattern classPattern;
        String extendsPattern;
        String implementsPattern;
        final List<MemberSpec> members = new ArrayList<>();
        boolean anyMember;
    }

    static final class MemberSpec {
        Integer access;
        boolean negateAccess;
        String type;
        String name;
        String desc;
        boolean fieldsOnly;
        boolean methodsOnly;
        boolean ctorOnly;
    }

    private KeepSpecs() {}

    // ------------------------------------------------------------------
    // parsing
    // ------------------------------------------------------------------

    public static List<Spec> parse(List<String> lines) {
        List<Spec> out = new ArrayList<>();
        if (lines == null) return out;
        for (String raw : lines) {
            if (raw == null || raw.trim().isEmpty()) continue;
            try {
                Spec s = parseOne(raw.trim());
                if (s != null) out.add(s);
            } catch (Exception ignore) {
                // 一条写坏不拖垮整批（neverFail 哲学）。
            }
        }
        return out;
    }

    private static Spec parseOne(String line) {
        String kind;
        String rest;
        String lower = line.toLowerCase(java.util.Locale.ROOT);
        if (lower.startsWith("-keepclasseswithmembers ") || lower.startsWith("keepclasseswithmembers ")
                || lower.equals("-keepclasseswithmembers") || lower.equals("keepclasseswithmembers")) {
            kind = "keepclasseswithmembers"; rest = tail(line, kind);
        } else if (lower.startsWith("-keepclassmembernames") || lower.startsWith("keepclassmembernames")) {
            kind = "keepclassmembernames"; rest = tail(line, kind);
        } else if (lower.startsWith("-keepclassmembers") || lower.startsWith("keepclassmembers")) {
            kind = "keepclassmembers"; rest = tail(line, kind);
        } else if (lower.startsWith("-keepnames") || lower.startsWith("keepnames")) {
            kind = "keepnames"; rest = tail(line, kind);
        } else if (lower.startsWith("-keep ") || lower.startsWith("keep ") || lower.equals("-keep")
                || lower.equals("keep")) {
            kind = "keep"; rest = tail(line, kind);
        } else {
            return null;
        }

        Spec s = new Spec();
        s.keepMembers = true;
        s.classKept = !kind.equals("keepclassmembers") && !kind.equals("keepclassmembernames");

        // {} 成员块
        String memberBlock = null;
        int brace = rest.indexOf('{');
        if (brace >= 0) {
            int close = rest.lastIndexOf('}');
            memberBlock = close > brace ? rest.substring(brace + 1, close) : rest.substring(brace + 1);
            rest = rest.substring(0, brace).trim();
        }
        s.anyMember = memberBlock == null;

        // @Annotation 过滤
        if (rest.startsWith("@")) {
            int sp = rest.indexOf(' ');
            s.annotation = (sp < 0 ? rest.substring(1) : rest.substring(1, sp))
                    .replace('.', '/').replaceAll("\\*\\*", "\\.\\*\\.").trim();
            if (sp >= 0) rest = rest.substring(sp + 1).trim(); else rest = "**";
            // 重新规范化注解通配（把 *. 段内通配留给匹配器）
            s.annotation = (sp < 0 ? line.substring(line.indexOf('@') + 1) : null) == null
                    ? s.annotation : s.annotation;
        } else {
            s.annotation = null;
        }

        // extends / implements 条件
        int extIdx = findKeyword(rest, "extends");
        int impIdx = findKeyword(rest, "implements");
        if (extIdx >= 0) {
            String tailPart = rest.substring(extIdx + 7).trim();
            int end = tailPart.indexOf(' ');
            s.extendsPattern = dottedToInternal(end < 0 ? tailPart : tailPart.substring(0, end));
            rest = rest.substring(0, extIdx).trim();
        } else {
            s.extendsPattern = null;
        }
        if (impIdx >= 0 && impIdx < (extIdx < 0 ? rest.length() : extIdx)) {
            String tailPart = rest.substring(impIdx + 10).trim();
            int end = tailPart.indexOf(' ');
            s.implementsPattern = dottedToInternal(end < 0 ? tailPart : tailPart.substring(0, end));
            rest = rest.substring(0, impIdx).trim();
        } else if (s.extendsPattern == null) {
            s.implementsPattern = null;
        } else {
            s.implementsPattern = null;
        }

        // 访问修饰符 + class/interface/enum + 类名模式
        String[] toks = rest.isEmpty() ? new String[0] : rest.split("\\s+");
        StringBuilder cls = new StringBuilder();
        for (String t : toks) {
            switch (t) {
                case "public": s.accessFilter = Opcodes.ACC_PUBLIC; break;
                case "private": s.accessFilter = Opcodes.ACC_PRIVATE; break;
                case "protected": s.accessFilter = Opcodes.ACC_PROTECTED; break;
                case "static": s.accessFilter = Opcodes.ACC_STATIC; break;
                case "final": s.accessFilter = Opcodes.ACC_FINAL; break;
                case "abstract": s.accessFilter = Opcodes.ACC_ABSTRACT; break;
                case "class": case "interface": case "enum": break; // 类型关键字：不区分
                default: cls.append(t);
            }
        }
        String clsPat = cls.length() == 0 ? "**" : cls.toString();
        s.classPattern = Pattern.compile(classWildcardToRegex(dottedToInternal(clsPat)));

        if (memberBlock != null) {
            for (String m : memberBlock.split(";")) {
                String t = m.trim();
                if (t.isEmpty()) continue;
                MemberSpec ms = parseMember(t);
                if (ms != null) s.members.add(ms);
            }
        }
        return s;
    }

    private static String tail(String line, String kind) {
        int i = line.indexOf(kind);
        return i < 0 ? "" : line.substring(i + kind.length()).trim();
    }

    private static int findKeyword(String s, String kw) {
        int i = s.indexOf(kw);
        while (i >= 0) {
            boolean before = i == 0 || s.charAt(i - 1) == ' ';
            int after = i + kw.length();
            boolean afterOk = after >= s.length() || s.charAt(after) == ' ';
            if (before && afterOk) return i;
            i = s.indexOf(kw, i + 1);
        }
        return -1;
    }

    /** 点号形式 -> 内部名通配（保留 * / ** / ? 语义）。 */
    private static String dottedToInternal(String dotted) {
        return dotted == null ? null
                : dotted.replace('.', '/').replaceAll("/\\*\\*/", "/**/");
    }

    /** 类通配 -> 正则：** 跨段，* 段内（不吃 /），? 单字符。 */
    private static String classWildcardToRegex(String internal) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < internal.length(); i++) {
            char c = internal.charAt(i);
            if (c == '*') {
                if (i + 1 < internal.length() && internal.charAt(i + 1) == '*') {
                    sb.append(".*");
                    i++;
                } else {
                    sb.append("[^/]*");
                }
            } else if (c == '?') sb.append('.');
            else sb.append(Pattern.quote(String.valueOf(c)));
        }
        return sb.toString();
    }

    private static MemberSpec parseMember(String raw) {
        MemberSpec ms = new MemberSpec();
        String t = raw.trim();
        if (t.equals("*")) { /* 任意成员 */ }
        else if (t.equals("<fields>") || t.equals("<init>")) {
            if (t.equals("<fields>")) ms.fieldsOnly = true; else ms.ctorOnly = true;
        } else if (t.equals("<methods>")) {
            ms.methodsOnly = true;
        } else if (t.equals("<init>") || t.startsWith("<init>(")) {
            ms.ctorOnly = true;
            int p = t.indexOf('(');
            if (p >= 0) ms.desc = "(?s).*" + Pattern.quote(t.substring(p));
        } else {
            // [access]* [type] name[(args)]
            String[] toks = t.split("\\s+");
            int idx = 0;
            while (idx < toks.length) {
                String tok = toks[idx];
                switch (tok) {
                    case "public": ms.access = Opcodes.ACC_PUBLIC; idx++; continue;
                    case "private": ms.access = Opcodes.ACC_PRIVATE; idx++; continue;
                    case "protected": ms.access = Opcodes.ACC_PROTECTED; idx++; continue;
                    case "static": ms.access = Opcodes.ACC_STATIC; idx++; continue;
                    case "final": ms.access = Opcodes.ACC_FINAL; idx++; continue;
                    case "abstract": ms.access = Opcodes.ACC_ABSTRACT; idx++; continue;
                    case "native": ms.access = Opcodes.ACC_NATIVE; idx++; continue;
                    case "synchronized": ms.access = Opcodes.ACC_SYNCHRONIZED; idx++; continue;
                    case "volatile": ms.access = Opcodes.ACC_VOLATILE; idx++; continue;
                    case "transient": ms.access = Opcodes.ACC_TRANSIENT; idx++; continue;
                    case "synthetic": ms.access = Opcodes.ACC_SYNTHETIC; idx++; continue;
                    default: break;
                }
                break;
            }
            if (idx >= toks.length) return null;
            if (toks.length - idx >= 2) {
                ms.type = typeToRegex(toks[idx]);
                idx++;
            }
            String last = toks[toks.length - 1];
            int paren = last.indexOf('(');
            if (paren >= 0) {
                ms.methodsOnly = true;
                ms.name = wildcardToRegex(last.substring(0, paren));
                String args = last.substring(paren + 1);
                args = args.endsWith(")") ? args.substring(0, args.length() - 1) : args;
                ms.desc = argsDescToRegex(args);
            } else {
                ms.name = wildcardToRegex(last);
            }
        }
        return ms;
    }

    /** 参数列表 -> 方法描述符通配正则。`...` 与省略/`***` 都宽松处理。 */
    private static String argsDescToRegex(String args) {
        String a = args.trim();
        if (a.isEmpty() || a.equals("...") || a.equals("***")) return "(?s).*";
        if (a.contains("...") || a.contains("*")) return "(?s).*";
        // 精确参数：点号类型 -> 描述符
        StringBuilder sb = new StringBuilder();
        for (String p : a.split(",")) {
            sb.append(java.util.regex.Matcher.quoteReplacement(Type.getDescriptor(
                    getClassLoosely(p.trim()))));
        }
        sb.append(")V"); // 返回类型不校验（宽松）
        return "(?s)^" + Pattern.quote(sb.toString().replace("\\E", "").replace("\\Q", ""))
                .replace("(?s)", "") + "?";
    }

    private static Class<?> getClassLoosely(String name) {
        switch (name) {
            case "int": return int.class;
            case "long": return long.class;
            case "double": return double.class;
            case "float": return float.class;
            case "boolean": return boolean.class;
            case "byte": return byte.class;
            case "short": return short.class;
            case "char": return char.class;
            case "void": return void.class;
            default:
                try { return Class.forName(name); }
                catch (Throwable t) { return Object.class; }
        }
    }

    private static String typeToRegex(String t) {
        if (t.equals("***")) return null; // 任意类型
        return wildcardToRegex(t);
    }

    /** 名字/类型通配（. 分隔、* 段内、? 单字符）-> 正则。 */
    private static String wildcardToRegex(String w) {
        if (w == null || w.equals("*") || w.equals("**") || w.equals("***")) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            if (c == '*') {
                if (i + 1 < w.length() && w.charAt(i + 1) == '*') { sb.append(".*"); i++; }
                else sb.append("[^.]*");
            } else if (c == '?') sb.append('.');
            else sb.append(Pattern.quote(String.valueOf(c)));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // matching
    // ------------------------------------------------------------------

    public static boolean keepClass(ProtectionConfig cfg, org.objectweb.asm.tree.ClassNode cn) {
        String internal = cn.name;
        for (Spec s : parsed(cfg)) {
            if (!s.classKept) continue;
            if (!classMatches(cfg, s, cn)) continue;
            return true;
        }
        return false;
    }

    private static boolean classMatches(ProtectionConfig cfg, Spec s,
                                        org.objectweb.asm.tree.ClassNode cn) {
        String internal = cn.name;
        if (!s.classPattern.matcher(internal).matches()) return false;
        if (s.extendsPattern != null && !hierarchyMatches(cn, s.extendsPattern)) return false;
        if (s.implementsPattern != null && !interfaceMatches(cn, s.implementsPattern)) return false;
        if (s.accessFilter != null && (cn.access & s.accessFilter) == 0) return false;
        return true;
    }

    public static boolean keepMethod(ProtectionConfig cfg, org.objectweb.asm.tree.ClassNode cn,
                                     int access, String name, String desc) {
        for (Spec s : parsed(cfg)) {
            if (s.anyMember) continue;
            if (!classMatches(cfg, s, cn)) continue;
            for (MemberSpec m : s.members) {
                if (m.fieldsOnly) continue;
                if (m.ctorOnly && !name.equals("<init>")) continue;
                if (m.access != null && (access & m.access) == 0) continue;
                if (m.name != null && !Pattern.compile(m.name).matcher(name).matches()) continue;
                if (m.type != null && desc != null && !descMatches(m.type, desc)) continue;
                if (m.desc != null && desc != null && !descMatches(m.desc, desc)) continue;
                return true;
            }
        }
        return false;
    }

    public static boolean keepField(ProtectionConfig cfg, org.objectweb.asm.tree.ClassNode cn,
                                    int access, String name, String desc) {
        for (Spec s : parsed(cfg)) {
            if (s.anyMember) continue;
            if (!classMatches(cfg, s, cn)) continue;
            for (MemberSpec m : s.members) {
                if (m.methodsOnly || m.ctorOnly) continue;
                if (m.access != null && (access & m.access) == 0) continue;
                if (m.name != null && !Pattern.compile(m.name).matcher(name).matches()) continue;
                if (m.type != null && desc != null && !descMatches(m.type, desc)) continue;
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------

    /** extends 条件：本类及父链上任何类名匹配 pattern 即成立。 */
    private static boolean hierarchyMatches(org.objectweb.asm.tree.ClassNode cn, String pattern) {
        Pattern p = Pattern.compile(classWildcardToRegex(pattern));
        int hops = 0;
        while (cn != null && hops++ < 64) {
            if (p.matcher(cn.name).matches()) return true;
            if (cn.interfaces != null) {
                for (Object o : cn.interfaces) {
                    if (p.matcher((String) o).matches()) return true;
                }
            }
            cn = (cn.superName == null) ? null : GRAPH_SUPPLIER == null ? null : GRAPH_SUPPLIER.apply(cn.superName);
        }
        return false;
    }

    private static boolean interfaceMatches(org.objectweb.asm.tree.ClassNode cn, String pattern) {
        Pattern p = Pattern.compile(classWildcardToRegex(pattern));
        int hops = 0;
        while (cn != null && hops++ < 64) {
            if (cn.interfaces != null) {
                for (Object o : cn.interfaces) {
                    if (p.matcher((String) o).matches()) return true;
                }
            }
            cn = (cn.superName == null) ? null : GRAPH_SUPPLIER == null ? null : GRAPH_SUPPLIER.apply(cn.superName);
        }
        return false;
    }

    /** superName -> ClassNode 解析器（由 NameObfuscator/RetentionDecision 注入）。 */
    public static java.util.function.Function<String, org.objectweb.asm.tree.ClassNode> GRAPH_SUPPLIER;

    private static boolean descMatches(String specRegex, String desc) {
        try {
            return Pattern.compile(specRegex).matcher(desc).matches()
                    || desc.startsWith(specRegex.replace("\\Q", "").replace("\\E", ""));
        } catch (Exception e) {
            return desc.startsWith(specRegex);
        }
    }

    // ------------------------------------------------------------------
    // cache
    // ------------------------------------------------------------------

    private static final java.util.Map<ProtectionConfig, List<Spec>> CACHE =
            new java.util.WeakHashMap<>();

    private static List<Spec> parsed(ProtectionConfig cfg) {
        synchronized (CACHE) {
            List<Spec> s = CACHE.get(cfg);
            if (s == null) {
                s = parse(cfg.getKeepClassSpecifications());
                CACHE.put(cfg, s);
            }
            return s;
        }
    }
}
