package com.kbox.core.packaging;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * P3-15: per-build renaming of the Brainfuck-specific runtime surface.
 *
 * <p>These classes ship as <b>plaintext</b> jar entries (or as blob members) and
 * their names gave the scheme away ({@code BfSecureLoader} as the manifest
 * Main-Class, {@code BfInterpreter}/{@code bfvm/*} as injected runtime). The
 * rename is applied to:</p>
 *
 * <ul>
 *   <li>the injected class files themselves (name + every internal reference),</li>
 *   <li>every class serialized into the jar/blob (so VMP/BFVM stubs that call
 *       {@code BfRuntime.call} / {@code BfInterpreter} stay linked),</li>
 *   <li>string constants that name these classes (e.g. the
 *       {@code Class.forName("com.kbox.runtime.BfSecureLoader")} lookups),</li>
 *   <li>the manifest Main-Class and the native decoder's {@code FindClass}
 *       (the latter gets the mapped name as a compile-time macro).</li>
 * </ul>
 *
 * <p>The same {@link Map} instance is handed to {@code BfNativeBuilder} and the
 * packager, so the native loader-method hashes are computed over exactly the
 * bytes that ship.</p>
 */
public final class RuntimeRename {

    /** BF-specific runtime classes (internal names). VMP/JNIC infrastructure is
     *  intentionally left alone: it is shared with the non-BF paths and is not
     *  a giveaway of the Brainfuck scheme. */
    private static final String[] CLASSES = {
            "com/kbox/runtime/BfSecureLoader",
            "com/kbox/runtime/BfBlobInputStream",
            "com/kbox/runtime/BfResourceHandler",
            "com/kbox/runtime/BfResourceConnection",
            "com/kbox/runtime/BfInterpreter",
            "com/kbox/runtime/BfInterpreter$BfRng",
            "com/kbox/runtime/bfvm/BfRuntime",
            "com/kbox/runtime/bfvm/BfInterpreter",
            "com/kbox/runtime/bfvm/VmCore",
            "com/kbox/runtime/bfvm/VmCore$Cursor",
            "com/kbox/runtime/bfvm/VmCore$State",
            "com/kbox/runtime/bfvm/VmCore$Uninitialized",
            "com/kbox/runtime/bfvm/Opcode",
            "com/kbox/runtime/bfvm/BfVmException"
    };

    private static final String ALPHA = "abcdefghijklmnopqrstuvwxyz";

    private RuntimeRename() {}

    /** Builds one mapping for this build. All targets share a single random
     *  package: {@code BfSecureLoader.callerIsKbox()} authorises callers by
     *  their package prefix, so the whole BF surface must stay together. */
    public static Map<String, String> build(SecureRandom rnd) {
        if (rnd == null) rnd = new SecureRandom();
        StringBuilder pkg = new StringBuilder();
        int plen = 1 + rnd.nextInt(2);
        for (int i = 0; i < plen; i++) pkg.append(ALPHA.charAt(rnd.nextInt(ALPHA.length())));
        Map<String, String> m = new LinkedHashMap<>();
        java.util.Set<String> used = new java.util.HashSet<>();
        for (String old : CLASSES) {
            String fresh;
            do {
                int len = 1 + rnd.nextInt(2);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < len; i++) sb.append(ALPHA.charAt(rnd.nextInt(ALPHA.length())));
                fresh = sb.toString();
            } while (!used.add(fresh));
            m.put(old, pkg + "/" + fresh);
        }
        return m;
    }

    /** Rewrites internal names, descriptors, owners and class-naming string
     *  constants. Returns the input unchanged when the map is empty. */
    public static byte[] remap(byte[] bytes, final Map<String, String> map) {
        if (bytes == null || map == null || map.isEmpty()) return bytes;
        final Map<String, String> dotted = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : map.entrySet()) {
            dotted.put(e.getKey().replace('/', '.'), e.getValue().replace('/', '.'));
        }
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(0);
        Remapper r = new Remapper() {
            @Override
            public String map(String internalName) {
                String v = map.get(internalName);
                return v != null ? v : internalName;
            }

            @Override
            public Object mapValue(Object value) {
                if (value instanceof String) {
                    String v = dotted.get(value);
                    if (v != null) return v;
                }
                return super.mapValue(value);
            }
        };
        cr.accept(new ClassRemapper(cw, r), 0);
        return cw.toByteArray();
    }

    /** Mapped internal name (or the input when unmapped). */
    public static String name(Map<String, String> map, String internal) {
        if (map == null || internal == null) return internal;
        String v = map.get(internal);
        return v != null ? v : internal;
    }
}
