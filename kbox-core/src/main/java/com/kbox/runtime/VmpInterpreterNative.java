package com.kbox.runtime;

/**
 * Native execution seam for the VMP interpreter (Layer 4 "VM原生化").
 *
 * <p>When the optional native VMP library is present ({@code META-INF/kbox/vmp.bin}
 * shipped by the pipeline and loaded via {@link NativeLoader#loadVmp()}), the hot
 * path — per-position ChaCha20 keystream, two-state XOR dispatch, and the pure
 * arithmetic / stack / branch micro-ops — runs in C ({@code kbox_vmp_core.c}),
 * moving the interpreter body out of Java bytecode so it is not readable by
 * decompilers, JVMTI introspection or a method-body hook.
 *
 * <p><b>Guaranteed safe fallback.</b> If the native library is not compiled/loaded
 * (no blob, wrong platform, or a future linking failure), {@link #tryExecute}
 * returns the {@link #NOT_NATIVE} sentinel and {@code VmpInterpreter.execute} falls
 * through to the pure-Java interpreter. The two paths are byte-identical in
 * observable semantics (boxed-object operand stack), so enabling "VM原生化" never
 * changes a protected program's results — it only changes <em>where</em> the
 * interpreter runs. This keeps ${jar}-run output identical whether or not the
 * native library is available.
 *
 * <p>The native symbol resolved on first call is
 * {@code Java_com_kbox_runtime_VmpInterpreterNative_execute(JNIEnv*, jclass,
 * jobject m, jobject instance, jobjectArray args)} — exactly what
 * {@code kbox_vmp_core.c} exports. C reads the per-run state it needs
 * ({@code resident}, {@code ephKey}, {@code composite}, {@code twin},
 * {@code cipherLen}, {@code maxStack}, {@code maxLocals}) via jfieldID on
 * {@link com.kbox.runtime.VmpInterpreter.VmpMethod}.
 */
public final class VmpInterpreterNative {

    private VmpInterpreterNative() {}

    /** Sentinel: never a legitimate VMP method result. Package-visible for the
     *  {@code VmpInterpreter.execute} fall-through and for the "not native" test. */
    static final Object NOT_NATIVE = new Object();

    /** Exactly one native-availability probe per JVM. */
    private static volatile int state;        // 0 = unprobed, 1 = available, 2 = unavailable

    /** The native entry point (implemented in kbox_vmp_core.c). The JNI symbol
     *  resolved is {@code Java_com_kbox_runtime_VmpInterpreterNative_execute}. */
    private static native Object execute(
            com.kbox.runtime.VmpInterpreter.VmpMethod m, Object instance, Object[] args);

    /**
     * Attempts native execution. Returns {@link #NOT_NATIVE} (not a result) when the
     * native library is absent or unavailable, so the caller must fall back to the
     * Java interpreter. Never throws for the "not available" case.
     *
     * @return the VMP result, or {@link #NOT_NATIVE} to signal "use the Java path".
     */
    public static Object tryExecute(com.kbox.runtime.VmpInterpreter.VmpMethod m,
                                    Object instance, Object[] args) {
        if (state == 2) return NOT_NATIVE;             // already proven unavailable
        if (state == 0) {
            // Lazily attempt to load the packed native VMP library exactly once.
            try {
                boolean ok = NativeLoader.loadVmp();
                if (ok) {
                    // This class is defined by BfSecureLoader (a child ClassLoader);
                    // bind execute() explicitly so it resolves across the loader boundary.
                    NativeLoader.registerVmpNatives0(VmpInterpreterNative.class);
                }
                state = ok ? 1 : 2;
            } catch (Throwable t) {
                state = 2;                              // silent; fall back to Java
            }
            if (state == 2) return NOT_NATIVE;
        }
        try {
            return execute(m, instance, args);
        } catch (Throwable t) {
            // A Throwable thrown by the native interpreter is the semantics-faithful
            // outcome of the interpreted method itself (kbox_vmp_core.c mirrors the
            // Java interpreter by ThrowNew-ing the exact same exceptions, e.g. a
            // protected method's own IllegalArgumentException). It is NOT a native
            // infrastructure fault, so we propagate it as-is and keep native engaged.
            // Genuine availability failures (no blob / linking drift / unsupported
            // platform) are all handled above at load time and degrade cleanly via
            // NOT_NATIVE before this point, so this catch is never that case.
            throw t;
        }
    }

    /** Test-only visibility of the availability decision. */
    static boolean available() { return state == 1; }
}