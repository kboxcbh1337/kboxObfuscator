package com.kbox.runtime;

/**
 * Runtime tamper gate: the single union read by every *silent* poison sink
 * (string decryptors, VMP dispatch, class/resource guards).
 *
 * <p>There are three independent tamper signals in the runtime:
 * <ul>
 *   <li>{@link AntiDebug} — a debugger / agent / JDWP / timing canary fired;</li>
 *   <li>{@link IntegrityChecker} — the boot-time SHA-256 over the jar changed
 *       (a class or a stored hash was touched, even without a debugger);</li>
 *   <li>{@link VmpInterpreter} — the per-method instruction-stream FNV-1a check
 *       or the interpreter self-hash fired (an in-memory patch).</li>
 * </ul>
 * Historically the string decryptor consulted <em>only</em> {@link AntiDebug},
 * so repackaging a jar or patching a method in memory — without ever attaching a
 * debugger — left every string fully readable. This wrapper unions all three, so
 * a <em>misplaced / repacked / patched</em> artifact now degrades the same way a
 * debugged one does: decryption yields garbage (or misses the intern-table
 * {@code ==} optimization) instead of clean plaintext.
 *
 * <p><b>Dependency safety.</b> {@link AntiDebug} is the only hard dependency and
 * is always injected when string encryption is on. {@link IntegrityChecker} and
 * {@link VmpInterpreter} are consulted <em>defensively</em> (try/catch): when the
 * corresponding feature is disabled those classes are not injected into the
 * artifact, and the absent-class {@link NoClassDefFoundError} is swallowed into a
 * {@code false}, so this class loads and runs under every feature combination.
 */
public final class TamperShield {

    private TamperShield() {}

    /** True if any of the three tamper signals has fired. */
    public static boolean isTampered() {
        if (AntiDebug.isTampered()) return true;
        if (integrityTampered()) return true;
        return vmTampered();
    }

    /** IntegrityCheck is a hard reference only guarded at runtime (may not be injected). */
    private static boolean integrityTampered() {
        try {
            return IntegrityChecker.isTampered();
        } catch (Throwable t) {
            // Class not injected (integrityCheck off) — no integrity signal.
            return false;
        }
    }

    /** VmpInterpreter may not be injected (VMP off); resolve lazily + defensively. */
    private static boolean vmTampered() {
        try {
            return VmpInterpreter.isTampered();
        } catch (Throwable t) {
            return false;
        }
    }
}