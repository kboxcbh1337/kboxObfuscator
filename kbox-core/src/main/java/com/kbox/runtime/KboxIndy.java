package com.kbox.runtime;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;

/**
 * invokedynamic bootstrap hub for call-site rewriting (条目 59/61/62).
 *
 * <p>The build-side rewriter replaces selected {@code INVOKESTATIC} /
 * {@code INVOKEVIRTUAL} / {@code GETSTATIC} / {@code PUTSTATIC} instructions
 * with an {@code INVOKEDYNAMIC} whose bootstrap argument is an XOR-encrypted
 * {@code owner\0name\0descriptor} string. The constant pool therefore holds
 * no {@code CONSTANT_Methodref}/{@code Fieldref} pointing at the real target;
 * the linkage is resolved here at first execution and cached in a
 * {@link ConstantCallSite}.
 *
 * <p>The {@link MethodHandles.Lookup} passed by the JVM belongs to the
 * <em>caller</em> class, so access rights are exactly those of the original
 * call site — private/package-private targets keep working when the original
 * instruction could reach them.
 */
public final class KboxIndy {

    private KboxIndy() {}

    /** Static method call site. */
    public static CallSite bootStatic(MethodHandles.Lookup l, String name,
                                      MethodType type, String enc) throws Throwable {
        String[] p = meta(enc);
        Class<?> owner = resolve(l, p[0]);
        MethodType target = MethodType.fromMethodDescriptorString(p[2], loader(l));
        return new ConstantCallSite(l.findStatic(owner, p[1], target));
    }

    /** Virtual/interface method call site (receiver is the first indy argument). */
    public static CallSite bootVirtual(MethodHandles.Lookup l, String name,
                                       MethodType type, String enc) throws Throwable {
        String[] p = meta(enc);
        Class<?> owner = resolve(l, p[0]);
        MethodType target = MethodType.fromMethodDescriptorString(p[2], loader(l));
        return new ConstantCallSite(l.findVirtual(owner, p[1], target));
    }

    /** Static field getter. */
    public static CallSite bootGet(MethodHandles.Lookup l, String name,
                                   MethodType type, String enc) throws Throwable {
        String[] p = meta(enc);
        Class<?> owner = resolve(l, p[0]);
        Class<?> ftype = MethodType.fromMethodDescriptorString("()" + p[2], loader(l))
                .returnType();
        return new ConstantCallSite(l.findStaticGetter(owner, p[1], ftype));
    }

    /** Static field setter. */
    public static CallSite bootPut(MethodHandles.Lookup l, String name,
                                   MethodType type, String enc) throws Throwable {
        String[] p = meta(enc);
        Class<?> owner = resolve(l, p[0]);
        Class<?> ftype = MethodType.fromMethodDescriptorString("()" + p[2], loader(l))
                .returnType();
        return new ConstantCallSite(l.findStaticSetter(owner, p[1], ftype));
    }

    /** Decrypts {@code owner\0name\0desc}. */
    private static String[] meta(String enc) {
        byte[] raw = java.util.Base64.getDecoder().decode(enc);
        int key = ((raw[0] & 0xFF) << 24) | ((raw[1] & 0xFF) << 16)
                | ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
        byte[] data = new byte[raw.length - 4];
        for (int i = 0; i < data.length; i++) {
            int shift = (i * 7) % 32;
            int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
            data[i] = (byte) (raw[i + 4] ^ (k & 0xFF));
        }
        String s = new String(data, StandardCharsets.UTF_8);
        String[] p = s.split("\u0000", 3);
        if (p.length != 3) throw new IllegalStateException("KBox indy metadata corrupt");
        return p;
    }

    private static Class<?> resolve(MethodHandles.Lookup l, String binaryName)
            throws ClassNotFoundException {
        return Class.forName(binaryName, false, loader(l));
    }

    private static ClassLoader loader(MethodHandles.Lookup l) {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl != null) return cl;
        cl = l.lookupClass().getClassLoader();
        return cl != null ? cl : KboxIndy.class.getClassLoader();
    }
}
