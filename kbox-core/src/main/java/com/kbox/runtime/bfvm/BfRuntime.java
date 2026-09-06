package com.kbox.runtime.bfvm;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Public runtime entry point referenced by BFVM-transformed method bodies. Each
 * transformed method becomes a call to {@link #call(String, Class, Object, Object[])}
 * passing its BF program source, its owner class, its {@code this} (or null for static
 * methods) and its boxed arguments.
 */
public final class BfRuntime {
    private static final Map<String, byte[]> STREAM_CACHE = new ConcurrentHashMap<>();

    private BfRuntime() {
    }

    /** Invoked by transformed method bodies. Returns the method result (boxed, or null for void). */
    public static Object call(String source, Class<?> owner, Object self, Object[] args) {
        byte[] stream = decode(source);
        Object[] a = args == null ? new Object[0] : args;
        ClassLoader loader = pickLoader(owner, self, a);
        return VmCore.execute(stream, owner, self, a, loader);
    }

    /** Run the BF program once (per process, cached) to recover the underlying instruction stream. */
    public static byte[] decode(String source) {
        byte[] cached = STREAM_CACHE.get(source);
        if (cached != null) {
            return cached;
        }
        byte[] stream = BfInterpreter.executeToData(source);
        byte[] prev = STREAM_CACHE.putIfAbsent(source, stream);
        return prev != null ? prev : stream;
    }

    private static ClassLoader pickLoader(Class<?> owner, Object self, Object[] args) {
        if (owner != null && owner.getClassLoader() != null) {
            return owner.getClassLoader();
        }
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl != null) {
            return cl;
        }
        if (self != null && self.getClass().getClassLoader() != null) {
            return self.getClass().getClassLoader();
        }
        for (Object a : args) {
            if (a != null && a.getClass().getClassLoader() != null) {
                return a.getClass().getClassLoader();
            }
        }
        ClassLoader own = BfRuntime.class.getClassLoader();
        return own != null ? own : ClassLoader.getSystemClassLoader();
    }
}
