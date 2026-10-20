package com.kbox.core.name;

import java.util.HashMap;
import java.util.Map;

/**
 * Bidirectional rename mapping: old name -> new name for classes, methods and
 * fields. Methods/fields are keyed by "owner#name#desc" so overloads (same
 * name, different desc) can map to the same new name without collision (the
 * JVM disambiguates by descriptor at link time).
 *
 * <p>Class renaming also records the package change so resource files that
 * reference class names (e.g. {@code META-INF/services/com.example.Service})
 * can be rewritten by the {@link com.kbox.core.packaging.ResourceReferenceUpdater}.
 */
public final class Mapping {

    /** internal old class name -> new class name. */
    private final Map<String, String> classes = new HashMap<>();
    /** "owner#name#desc" -> new method name. */
    private final Map<String, String> methods = new HashMap<>();
    /** "owner#name#desc" -> new field name. */
    private final Map<String, String> fields = new HashMap<>();

    private int seq = 0;
    /** 字段独立命名空间计数器（separateFieldNamespace 开启时使用）。 */
    private int fieldSeq = 0;

    /** 新名生成风格。 */
    public enum NameStyle { ASCII, KEYWORDS, DICTIONARY }

    private NameStyle style = NameStyle.ASCII;
    /** 客户词典（DICTIONARY 风格时按序取词，用尽后回退 ASCII）。 */
    private java.util.List<String> dictionary = new java.util.ArrayList<>();
    private int dictIdx = 0;

    public void setNameStyle(NameStyle s) { style = (s == null) ? NameStyle.ASCII : s; }
    public void setDictionary(java.util.Collection<String> words) {
        dictionary = new java.util.ArrayList<>();
        if (words != null) {
            for (String w : words) {
                if (w != null && !w.trim().isEmpty()) dictionary.add(w.trim());
            }
        }
    }

    /** JVM 内合法、但不是合法 Java 标识符的关键字表（砸反编译器专用）。 */
    private static final String[] KEYWORDS = {
        "if", "do", "int", "for", "new", "try", "case", "else", "goto", "long",
        "null", "true", "void", "byte", "char", "enum", "auto", "bool", "cast",
        "false", "final", "float", "short", "super", "switch", "throw", "while",
        "break", "class", "const", "catch", "import", "native", "package", "public",
        "return", "static", "assert", "extends", "default", "double", "abstract",
        "finally", "private", "boolean", "volatile", "strictfp", "transient",
        "continue", "instanceof", "interface", "protected", "implements", "synchronized"
    };

    /** 歧义哨兵：同一 owner#name 下不同描述符映射到不同新名时使用。 */
    private static final String AMBIGUOUS = "\u0000AMBIGUOUS";
    /** "owner#name" -> 新名（歧义时记 {@link #AMBIGUOUS}）。 */
    private final Map<String, String> methodByOwnerName = new HashMap<>();

    public void mapClass(String oldName, String newName) { classes.put(oldName, newName); }
    public void mapMethod(String owner, String name, String desc, String newName) {
        methods.put(key(owner, name, desc), newName);
        String k2 = owner + "#" + name;
        String prev = methodByOwnerName.get(k2);
        if (prev == null) methodByOwnerName.put(k2, newName);
        else if (!prev.equals(newName)) methodByOwnerName.put(k2, AMBIGUOUS);
    }
    public void mapField(String owner, String name, String desc, String newName) {
        fields.put(key(owner, name, desc), newName);
    }

    public String mapClass(String oldName) { return classes.getOrDefault(oldName, oldName); }
    public String mapMethod(String owner, String name, String desc) {
        return methods.getOrDefault(key(owner, name, desc), name);
    }
    public String mapField(String owner, String name, String desc) {
        return fields.getOrDefault(key(owner, name, desc), name);
    }

    public boolean hasClass(String n) { return classes.containsKey(n); }
    public boolean hasMethod(String owner, String n, String d) { return methods.containsKey(key(owner, n, d)); }
    public boolean hasField(String owner, String n, String d) { return fields.containsKey(key(owner, n, d)); }

    /**
     * 忽略描述符的方法改名查询：返回 {@code owner#name} 的新名。
     *
     * <p>用途：{@code invokedynamic}（LambdaMetafactory）把「函数式接口的 SAM 方法名」
     * 放在 indy 的 name 上而<b>不在</b> bsmArgs 里，因此重命名阶段拿不到描述符，
     * 只能用 (owner, name) 查表。若同一名字对应多个描述符且新名不一致，返回
     * {@code null} 以避免误改。</p>
     */
    public String mapMethodByName(String owner, String name) {
        String v = methodByOwnerName.get(owner + "#" + name);
        return (v == null || AMBIGUOUS.equals(v)) ? null : v;
    }

    public Map<String, String> getClassMap() { return classes; }
    public Map<String, String> getMethodMap() { return methods; }
    public Map<String, String> getFieldMap() { return fields; }

    public int nextSeq() { return seq++; }

    private static String key(String owner, String name, String desc) {
        return owner + "#" + name + "#" + desc;
    }

    /** Allocate a fresh obfuscated name according to the configured style. */
    public String newName() {
        return generate(nextSeq());
    }

    /** Fresh name from the FIELD namespace (independent counter — only used
     *  when the caller wants fields in their own alphabet). */
    public String newFieldName() {
        int n = fieldSeq++;
        return generate(n);
    }

    /** Deterministic name for a given index (hash-naming / overload pools). */
    public String nameFor(int n) { return generate(n); }

    /** SHA-256(salt|key) -> base-26 稳定短名（确定性 hash 命名，便于 CI 差分）。 */
    public String hashName(String salt, String key, int len) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest((salt + "|" + key).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            java.math.BigInteger v = new java.math.BigInteger(1, d);
            java.math.BigInteger base = java.math.BigInteger.valueOf(26);
            StringBuilder sb = new StringBuilder();
            while (sb.length() < len) {
                sb.append((char) ('a' + v.mod(base).intValue()));
                v = v.divide(base);
            }
            return sb.toString();
        } catch (Exception e) {
            return generate(0);
        }
    }

    private String generate(int n) {
        if (style == NameStyle.DICTIONARY && dictIdx < dictionary.size()) {
            String w = dictionary.get(dictIdx++);
            // 确保唯一：词典词可能重名，加序号后缀（首个不带）。
            String base = w;
            int suffix = 1;
            while (isTaken(base)) base = w + (suffix++);
            return base;
        }
        if (style == NameStyle.KEYWORDS) {
            // 组合关键字：单关键字用尽后拼两个（"if"+"do" -> "ifdo"），仍是
            // 合法 JVM 内部名但不是合法 Java 标识符 -> 反编译器直接报错。
            int kw = KEYWORDS.length;
            int head = n % kw;
            int rest = n / kw;
            if (rest == 0) return KEYWORDS[head];
            StringBuilder sb = new StringBuilder(KEYWORDS[head]);
            int v = rest - 1;
            do {
                sb.append(KEYWORDS[v % kw]);
                v /= kw;
            } while (v > 0);
            return sb.toString();
        }
        int base = 26;
        int v = n;
        StringBuilder sb = new StringBuilder();
        do {
            sb.append((char) ('a' + (v % base)));
            v /= base;
        } while (v > 0);
        return sb.toString();
    }

    /** Has any rename already produced this name? (dictionary uniqueness check) */
    private boolean isTaken(String n) {
        return classes.containsValue(n) || methods.containsValue(n) || fields.containsValue(n);
    }
}
