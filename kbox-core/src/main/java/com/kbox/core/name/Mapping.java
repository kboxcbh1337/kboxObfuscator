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

    public void mapClass(String oldName, String newName) { classes.put(oldName, newName); }
    public void mapMethod(String owner, String name, String desc, String newName) {
        methods.put(key(owner, name, desc), newName);
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
