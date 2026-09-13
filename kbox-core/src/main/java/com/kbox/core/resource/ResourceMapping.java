package com.kbox.core.resource;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Holds the resource name remapping produced by {@link ResourceNameObfuscator}.
 *
 * <p>Each entry maps an original jar path (e.g. {@code config/db.properties}) to
 * a tuple of (newPath, encrypted). The {@code encrypted} flag tells the runtime
 * loader whether the stored bytes need AES-GCM decryption before being handed
 * back to the application.
 *
 * <p>The mapping is serialized into the protected jar as {@code META-INF/kbox/resources.map}
 * (AES-encrypted) and read at boot time by {@code ResourceGuardLauncher} so the
 * replacement class loader can transparently resolve original resource names.
 */
public final class ResourceMapping {

    /** originalPath -> {newPath, encrypted} */
    private final Map<String, Entry> forward = new LinkedHashMap<>();

    public static final class Entry {
        public final String newPath;
        public final boolean encrypted;
        public Entry(String newPath, boolean encrypted) {
            this.newPath = newPath;
            this.encrypted = encrypted;
        }
    }

    public void map(String original, String newPath, boolean encrypted) {
        forward.put(original, new Entry(newPath, encrypted));
    }

    public Entry lookup(String original) {
        return forward.get(original);
    }

    public int size() {
        return forward.size();
    }

    public Map<String, Entry> entries() {
        return forward;
    }

    /**
     * Serializes the mapping to a compact, parseable text format.
     * Each line: {@code original<TAB>newPath<TAB>0|1}
     */
    public byte[] serialize() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Entry> e : forward.entrySet()) {
            sb.append(e.getKey()).append('\t')
              .append(e.getValue().newPath).append('\t')
              .append(e.getValue().encrypted ? '1' : '0').append('\n');
        }
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** Inverse of {@link #serialize()}. */
    public static ResourceMapping deserialize(byte[] data) {
        ResourceMapping m = new ResourceMapping();
        String s = new String(data, java.nio.charset.StandardCharsets.UTF_8);
        for (String line : s.split("\n")) {
            if (line.isEmpty()) continue;
            String[] parts = line.split("\t", 3);
            if (parts.length == 3) {
                m.map(parts[0], parts[1], "1".equals(parts[2]));
            }
        }
        return m;
    }
}
