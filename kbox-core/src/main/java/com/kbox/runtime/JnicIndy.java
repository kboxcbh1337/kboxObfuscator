package com.kbox.runtime;

import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runtime resolver for JNIC-native methods that contain {@code invokedynamic}.
 *
 * <p>When a native-ized method body includes an invokedynamic call site, the C
 * interpreter cannot resolve it by itself (bootstrap resolution is a JVM
 * facility). Instead it forwards each site's metadata here. This class
 * faithfully reproduces the JVM's bootstrap protocol:
 * <ol>
 *   <li>reconstruct the bootstrap {@link MethodHandle} from its encoded
 *       {@code Handle} (kind/owner/name/desc);</li>
 *   <li>rebuild the static bootstrap arguments (Strings, boxed primitives,
 *       {@link MethodType}s, nested {@code MethodHandle}s, {@link Class}s);</li>
 *   <li>invoke the bootstrap with {@code (Lookup, name, methodType, static...
 *       )} to obtain the {@link CallSite};</li>
 *   <li>invoke the call site target via {@link MethodHandle#invokeWithArguments}.</li>
 * </ol>
 * The resolved target is cached keyed by the site's canonical spec so repeated
 * calls skip re-bootstrapping. This covers LambdaMetafactory,
 * StringConcatFactory and any user bootstrap that follows the 3-arg convention.
 */
public final class JnicIndy {

    private static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();
    private static final ConcurrentHashMap<String, MethodHandle> CACHE = new ConcurrentHashMap<>();
    private static final char SEP = 0x1f;   // top-level metadata field separator
    private static final char PARTS = 0x1e; // static-argument payload separator
    private static final Class<?> SELF = JnicIndy.class;
    private static final boolean DEBUG = Boolean.getBoolean("kbox.jnic.indydbg");

    private JnicIndy() {
    }

    /**
     * Entry point called from the native interpreter for one invokedynamic site.
     *
     * @param meta packed site metadata, fields joined by {@code \u001f}:
     *             [0] bsmOwner [1] bsmName [2] bsmDesc [3] bsmKind
     *             [4] bsmItf(0/1) [5] siteName [6] siteDesc [7] tags
     *             [8] static-arg payloads joined by {@code \u001e}
     * @param args boxed call-site arguments (order as in the call-site descriptor)
     * @return the boxed return value, or {@code null} for a void call site
     * @throws Throwable if bootstrap resolution or target invocation fails
     */
    public static Object invoke(String meta, Object[] args) throws Throwable {
        if (DEBUG) System.err.println("[JNIC-INDY] ENTER args=" + (args == null ? "?" : Arrays.toString(args)));
        String[] f = meta.split(String.valueOf(SEP), -1);
        MethodHandle target;
        try {
            target = CACHE.computeIfAbsent(meta, m -> {
                try {
                    return resolveTarget(f[9], f[0], f[1], f[2], Integer.parseInt(f[3]),
                            "1".equals(f[4]), f[5], f[6], f[7], f[8]);
                } catch (Throwable t) {
                    if (DEBUG) t.printStackTrace();
                    throw new RuntimeException("indy bootstrap failed", t);
                }
            });
        } catch (RuntimeException wrapped) {
            throw wrapped.getCause() != null ? wrapped.getCause() : wrapped;
        }
        if (DEBUG) System.err.println("[JNIC-INDY] target=" + target.type() + " impl=" + f[0] + "." + f[1] + f[2]);
        Object res = target.invokeWithArguments(args);
        if (DEBUG) System.err.println("[JNIC-INDY] RESULT=" + res);
        return res;
    }

    private static MethodHandle resolveTarget(String caller, String bsmOwner, String bsmName,
                                              String bsmDesc, int bsmKind, boolean bsmItf,
                                              String siteName, String siteDesc,
                                              String tags, String partsPacked) throws Throwable {
        MethodHandles.Lookup lk = callerLookup(caller);
        MethodType siteType = MethodType.fromMethodDescriptorString(siteDesc, SELF.getClassLoader());
        Object[] staticArgs = rebuild(lk, tags,
                partsPacked.isEmpty() ? new String[0] : partsPacked.split(String.valueOf(PARTS), -1));
        Object[] bootArgs = new Object[3 + staticArgs.length];
        bootArgs[0] = lk;
        bootArgs[1] = siteName;
        bootArgs[2] = siteType;
        for (int i = 0; i < staticArgs.length; i++) {
            bootArgs[3 + i] = staticArgs[i];
        }
        MethodHandle bsm = resolveHandle(lk, bsmOwner, bsmName, bsmDesc, bsmKind, bsmItf);
        CallSite cs = (CallSite) bsm.invokeWithArguments(bootArgs);
        return cs.getTarget();
    }

    /** A lookup with access to the caller class's own (including private) members. */
    private static MethodHandles.Lookup callerLookup(String internal) throws Throwable {
        Class<?> c = Class.forName(internal.replace('/', '.'), false, SELF.getClassLoader());
        return MethodHandles.privateLookupIn(c, LOOKUP);
    }

    private static Object[] rebuild(MethodHandles.Lookup lk, String tags, String[] parts) throws Throwable {
        Object[] out = new Object[parts.length];
        for (int i = 0; i < parts.length; i++) {
            char tag = (tags != null && i < tags.length()) ? tags.charAt(i) : 's';
            String p = parts[i];
            switch (tag) {
                case 'i': out[i] = Integer.valueOf(Integer.parseInt(p)); break;
                case 'l': out[i] = Long.valueOf(Long.parseLong(p)); break;
                case 'f': out[i] = Float.valueOf(Float.parseFloat(p)); break;
                case 'd': out[i] = Double.valueOf(Double.parseDouble(p)); break;
                case 'c': out[i] = Class.forName(p.replace('/', '.')); break;
                case 't': case 'm':
                    out[i] = MethodType.fromMethodDescriptorString(p, SELF.getClassLoader()); break;
                case 'h': {
                    String[] f = p.split("\\|", -1);
                    out[i] = resolveHandle(lk, f[0], f[1], f[2], Integer.parseInt(f[3]),
                            f.length > 4 && "1".equals(f[4]));
                    break;
                }
                case 'n': out[i] = null; break;
                default:  out[i] = p; break; // 's' and anything else: string payload
            }
        }
        return out;
    }

    /** Reconstructs a MethodHandle from an ASM-style Handle tuple, using the
     *  caller lookup so private/synthetic members (e.g. lambda impl methods)
     *  are resolved and lambda metafactories can "crack" them. On access
     *  failure we still fall back to reflection + setAccessible(true) + unreflect. */
    private static MethodHandle resolveHandle(MethodHandles.Lookup lk, String owner, String name,
                                              String desc, int kind, boolean itf) throws Throwable {
        Class<?> cls = Class.forName(owner.replace('/', '.'), false,
                Thread.currentThread().getContextClassLoader());
        MethodType mt = MethodType.fromMethodDescriptorString(desc, SELF.getClassLoader());
        boolean instance = (kind == 5 || kind == 7 || kind == 9);
        try {
            switch (kind) {
                case 5: case 9: return lk.findVirtual(cls, name, mt);
                case 6: return lk.findStatic(cls, name, mt);
                case 7: return lk.findSpecial(cls, name, mt, cls);
                case 8: return lk.findConstructor(cls, mt.changeReturnType(void.class));
                case 1: return lk.findGetter(cls, name, mt.returnType());
                case 2: return lk.findStaticGetter(cls, name, mt.returnType());
                case 3: return lk.findSetter(cls, name, mt.parameterType(0));
                case 4: return lk.findStaticSetter(cls, name, mt.parameterType(0));
                default: return lk.findStatic(cls, name, mt);
            }
        } catch (IllegalAccessException iae) {
            // Private / synthetic member not reachable via the lookup: open it.
            if (kind == 8) {
                java.lang.reflect.Constructor<?> cc = cls.getDeclaredConstructor(mt.parameterArray());
                cc.setAccessible(true);
                return lk.unreflectConstructor(cc);
            }
            java.lang.reflect.Method m = findMethodRaw(cls, name, mt, instance);
            if (m == null) throw iae;
            m.setAccessible(true);
            return lk.unreflect(m);
        }
    }

    /** Finds a declared method by name, declared parameter types and return type.
     *  For instance invocation the raw method drops the leading receiver slot. */
    private static java.lang.reflect.Method findMethodRaw(Class<?> c, String name,
                                                          MethodType callType, boolean instance) {
        java.lang.Class<?>[] wantParams;
        if (instance && callType.parameterCount() > 0) {
            wantParams = java.util.Arrays.copyOfRange(callType.parameterArray(), 1, callType.parameterCount());
        } else {
            wantParams = callType.parameterArray();
        }
        for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
            if (!m.getName().equals(name)) continue;
            if (m.getReturnType() != callType.returnType()) continue;
            if (!java.util.Arrays.equals(m.getParameterTypes(), wantParams)) continue;
            return m;
        }
        return null;
    }
}