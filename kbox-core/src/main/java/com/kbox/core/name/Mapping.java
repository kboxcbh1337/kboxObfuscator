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

    /** Allocate a fresh obfuscated name from a,b,...,z,aa,...  (ASCII-safe). */
    public String newName() {
        int n = nextSeq();
        StringBuilder sb = new StringBuilder();
        // Mix in an 'I'/'O'-free alphabet (avoid confusing 0/O, 1/l/I) and make names
        // short but unique. Pure base-26 with offset keeps identifiers legal & distinct.
        int base = 26;
        int v = n;
        do {
            sb.append((char) ('a' + (v % base)));
            v /= base;
        } while (v > 0);
        return sb.toString();
    }
}
