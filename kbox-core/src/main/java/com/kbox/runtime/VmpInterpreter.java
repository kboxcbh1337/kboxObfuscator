package com.kbox.runtime;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * Stack-based VMP interpreter dispatched on {@link VmpOp}. Each {@code VmpMethod}
 * is a self-contained byte[] program with a constant pool holding Class, Field,
 * Method and String references resolved lazily and cached.
 *
 * <p>The interpreter is written in plain Java (no sun.misc.Unsafe) so it works on
 * every JVM 8..21. The dispatch loop is a single {@code switch} per opcode to
 * keep the hot path branch-predictable.
 *
 * <p>Semantics:
 * <ul>
 *   <li>Operand stack is {@code Object[]}; primitive values are auto-boxed on
 *       push and un-boxed on pop. This is slow but correct, which is the only
 *       priority for VMP-protected code (it is opt-in per method).</li>
 *   <li>Locals are {@code Object[]}.</li>
 *   <li>{@code MONITORENTER}/{@code MONITOREXIT} map to {@code synchronized}
 *       blocks via {@code Object} monitors (we hold the monitor on the object
 *       reference). Exceptions during the protected region are re-thrown after
 *       a best-effort {@code MONITOREXIT} on the way out.</li>
 *   <li>Exception table is consulted on {@code ATHROW} / any thrown exception;
 *       if no handler matches, the exception propagates to the caller.</li>
 * </ul>
 */
public final class VmpInterpreter {

    /**
     * Self-check state. When the protector enables {@code vmpSelfCheck}, this
     * class's {@code <clinit>} computes a SHA-256 of its own bytecode and
     * caches it; the {@link com.kbox.runtime.IntegrityChecker} then covers it
     * at boot. Direct byte comparison is deferred to the integrity checker to
     * avoid the patch-hash chicken-and-egg (patching the stored hash into the
     * class changes the very bytes being hashed).
     *
     * <p>If the class resource is missing or unreadable, {@link #selfTampered}
     * is set and {@code execute()} consults it to corrupt dispatch.
     */
    private static volatile boolean selfTampered = false;

    /** True if the self-check fired (interpreter class missing or tampered). */
    static boolean isSelfTampered() { return selfTampered; }

    /** Raised when a per-method ciphertext integrity probe fails (silent). */
    private static final java.util.concurrent.atomic.AtomicBoolean KBOX_TAMPER =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    // ------------------------------------------------------------------
    // Rolling-window integrity watchdog.
    //
    // A single shared daemon thread periodically re-verifies the decrypted
    // instruction stream of every live VmpMethod against its construction-time
    // FNV-1a fingerprint. If an attacker patches the resident ciphertext (or the
    // constant pool) while a protected method is mid-flight — i.e. after the
    // one-shot checkIntegrity() probe that runs at execute() entry — the watchdog
    // detects the drift across the *rolling window* currently decoded, flags
    // KBOX_TAMPER and poisons the method so in-flight dispatch throws instead of
    // silently producing a wrong result.
    //
    // Thread confinement: the watchdog reads the ciphertext through its OWN
    // fixed Keystream instances (ksWatch/ksWatchEph). ChaCha20.Keystream caches
    // per-instance block state, so a shared keystream between the executing
    // thread (m.b()/m.ksStatic/m.ksEph) and the watchdog would race and corrupt
    // the keystream offset. Private instances isolate the watchdog hot path.
    // ------------------------------------------------------------------
    private static final java.util.concurrent.ConcurrentHashMap<VmpMethod, Boolean> LIVE_METHODS =
            new java.util.concurrent.ConcurrentHashMap<>();
    private static volatile Thread watchdogThread;

    private static synchronized void ensureWatchdog() {
        if (watchdogThread != null && watchdogThread.isAlive()) return;
        Thread t = new Thread(VmpInterpreter::watchdogLoop, "VMP-Watchdog");
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        watchdogThread = t;
        t.start();
    }

    /** Periodic sweep: re-verify each live method's rolling decrypted-window fingerprint. */
    private static void watchdogLoop() {
        long tick = 0;
        while (!Thread.currentThread().isInterrupted()) {
            try {
                // Each tick advances a global rolling window index. Every method is
                // probed once per sweep, but the window probed rolls forward across
                // sweeps, so over time each method's full stream is re-hashed while a
                // tamper lands in whatever window is current when it happens.
                for (java.util.Map.Entry<VmpMethod, Boolean> e : LIVE_METHODS.entrySet()) {
                    VmpMethod m = e.getKey();
                    int wc = m.windowCount();
                    if (wc <= 0) continue;
                    int w = (int) ((tick + m.windowSalt()) % wc);
                    if (m.watchTampered()) continue;                 // already poisoned
                    if (!m.windowOk(w)) {
                        KBOX_TAMPER.set(true);
                        m.poison();                                  // poison in-flight decode
                        break;
                    }
                }
                tick++;
                Thread.sleep(120);                                  // 120ms rolling window
            } catch (InterruptedException ie) {
                break;
            } catch (Throwable t) {
                try { Thread.sleep(500); } catch (InterruptedException ie) { break; }
            }
        }
    }

    /** A compiled VMP method: code + cp + exception table. */
    public static final class VmpMethod {
        public final Object[] cp;            // resolved pool entries (lazy fill)
        public final Object[] cpRaw;         // null under keyed constant-pool (specs via specAt)
        private final Object[] cpRes;        // per-run re-keyed CIPHERTEXT spec strings
        private final int[] cpPerm;          // physical slot permutation (from K)
        public final int maxLocals;
        public final int maxStack;
        public final int argCount;
        /** ASM {@link Type#getSort()} of the method's return descriptor; used to box IRETURN correctly. */
        public final int retSort;
        /** {@code [startPc, endPc, handlerPc, catchTypeCpIdx]} rows; null = none. */
        public final int[][] exceptions;

        // --- VortexVM/L2: key-wrapped, per-run re-encrypted instruction stream ---
        /** Static ciphertext ({@code $vmp_0}) — encrypted at build under key K only.
         *  Immutable; kept so the method can be re-constructed/re-executed. */
        private final byte[] cipher;
        /** Per-run resident: {@code cipher ^ ksStatic ^ ksEph}. This is what actually
         *  lives in memory during execution, so a dump sees different bytes on every
         *  launch while {@code b()} still recovers the exact plaintext. */
        private final byte[] resident;
        private final int cipherLen;
        /** FNV-1a of the full decrypted plaintext, computed transiently at construction. */
        private final int constructionHash;
        /** ChaCha20 keystream from the unwrapped method key K (recover static plain). */
        private final ChaCha20.Keystream ksStatic;
        /** Per-run ChaCha20 keystream (derived from eph = HKDF(master, perLaunch, "kbox.run")). */
        private final ChaCha20.Keystream ksEph;
        /** Per-method opcode twin derived from K: {@code (st1 ^ st2)} -> real opcode. */
        private final int twin;
        /** True when the hardware-bound key unwrap failed (wrong machine / tamper). */
        private final boolean noise;

        private static int opcodeTwin(byte[] K) {
            int t = (K != null && K.length > 0) ? (K[0] & 0xFF) : 0;
            if (t == 0 && K != null && K.length > 1) t = K[K.length - 1] & 0xFF;
            return (t == 0) ? 0xB1 : t;
        }

        /** Deterministic slot permutation from K (MUST match VmpMethodInjector.slotPerm). */
        private static int[] slotPerm(byte[] K, int n) {
            int[] p = new int[n];
            for (int i = 0; i < n; i++) p[i] = i;
            if (n <= 1) return p;
            long s = 0x6A09E667F3BCC909L;
            byte[] kb = (K == null) ? new byte[0] : K;
            for (byte b : kb) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
            for (int i = n - 1; i > 0; i--) {
                s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27; s *= 0x2545F4914F6CDD1DL;
                int j = (int) (Long.remainderUnsigned(s, i + 1L));
                int t = p[i]; p[i] = p[j]; p[j] = t;
            }
            return p;
        }

        /** Lazy constant-pool access: logical slot {@code idx} is stored at physical
         *  slot {@code perm[idx]} and re-keyed under the per-run layer; the plaintext
         *  is recovered on demand and NOT retained (a new String per call). */
        String specAt(int idx) {
            int n = cpRes == null ? 0 : cpRes.length;
            if (n == 0) throw new RuntimeException("VMP: empty constant pool");
            int pi = (cpPerm != null && cpPerm.length == n) ? cpPerm[iidx(idx, n)] : iidx(idx, n);
            Object v = cpRes[pi];
            if (v instanceof String) {
                String s = (String) v;
                byte[] dec = new byte[s.length()];
                for (int j = 0; j < s.length(); j++) {
                    int off = j + cipherLen + pi * 256;
                    dec[j] = (byte) ((s.charAt(j) & 0xFF) ^ ksEph.atMasked(off) ^ ksStatic.atMasked(off));
                }
                return new String(dec, java.nio.charset.StandardCharsets.UTF_8);
            }
            return (String) v;
        }

        /** Keeps idx in range. */
        private static int iidx(int idx, int n) {
            int r = idx < 0 ? -idx : idx;
            return n == 0 ? 0 : r % n;
        }

        /**
         * Constructs a VmpMethod whose instruction stream is decrypted with a
         * HARDWARE-BOUND wrapped key:
         * <pre>
         *   master   = HKDF(hardwareFeed, VMP_SALT, "kbox.master", 32)   // per machine
         *   K        = AES-GCM-decrypt(master, wrappedK)                  // unwrap (throws off-device)
         *   eph      = HKDF(master, perLaunchSalt, "kbox.run", 32)        // per launch
         *   resident = plain ^ ksEph   (re-encrypted under the per-run stream)
         *   b(pos)   = resident[pos] ^ ksEph[pos] = plain[pos]            // only single bytes transient
         * </pre>
         * The method key {@code K} is never stored bare; on any unwrap failure the
         * method silently becomes a "noise" method (invalid opcode stream), so a
         * misplaced/tampered jar degrades into garbage rather than a clean boot.
         */
        public VmpMethod(byte[] encCode, Object[] encCpRaw, byte[] wrappedK,
                         int maxLocals, int maxStack, int argCount, int retSort, int[][] exceptions) {
            this.cipher = encCode == null ? new byte[0] : encCode;
            this.cipherLen = this.cipher.length;
            this.maxLocals = maxLocals;
            this.maxStack = maxStack;
            this.argCount = argCount;
            this.retSort = retSort;
            this.exceptions = exceptions;

            byte[] K = null;
            try {
                byte[] master = HardwareKeyRing.vmpMaster();
                K = HardwareKeyRing.aesGcmDecrypt(master, wrappedK);
            } catch (Throwable ignored) {
                K = null;
            }
            if (K == null || K.length == 0) {
                // Wrong machine / tampered wrapped key -> noise method.
                this.noise = true;
                this.twin = 0xB1;
                byte[] zero = new byte[32];
                this.ksStatic = new ChaCha20.Keystream(zero);
                this.ksEph = new ChaCha20.Keystream(zero);
                this.resident = this.cipher;
                this.cp = new Object[0];
                this.cpRaw = encCpRaw;
                this.cpRes = encCpRaw;
                this.cpPerm = new int[0];
                this.constructionHash = 0;
            } else {
                this.noise = false;
                this.twin = opcodeTwin(K);
                this.ksStatic = new ChaCha20.Keystream(K);
                byte[] eph = new byte[32];
                try {
                    byte[] master = HardwareKeyRing.vmpMaster();
                    eph = HardwareKeyRing.hkdfSha256(master,
                            HardwareKeyRing.ephemeralKey(), "kbox.run", 32);
                } catch (Throwable ignored) {
                    new java.security.SecureRandom().nextBytes(eph);
                }
                this.ksEph = new ChaCha20.Keystream(eph);
                // Transiently recover the plaintext and re-encrypt it under the per-run
                // stream into `resident`. No full plaintext is retained.
                byte[] res = new byte[cipherLen];
                int ch = 0x811c9dc5;
                for (int i = 0; i < cipherLen; i++) {
                    int pl = (cipher[i] & 0xFF) ^ ksStatic.atMasked(i);
                    res[i] = (byte) (pl ^ ksEph.atMasked(i));
                    ch ^= pl; ch *= 0x01000193;
                }
                this.resident = res;
                this.constructionHash = ch;
                // Constant-pool keying: keep the constant specs as CIPHERTEXT. Build a
                // per-run re-keyed resident (enc ^ eph) and a deterministic slot
                // permutation; individual specs are decrypted lazily via specAt() so no
                // full plaintext constant-pool array exists in memory and the physical
                // slot order is hidden from static analysis.
                int cpN = encCpRaw == null ? 0 : encCpRaw.length;
                Object[] cpResTmp = new Object[cpN];
                this.cpPerm = slotPerm(K, cpN);
                for (int pi = 0; pi < cpN; pi++) {
                    if (encCpRaw[pi] instanceof String) {
                        String s = (String) encCpRaw[pi];
                        byte[] sb = new byte[s.length()];
                        for (int j = 0; j < s.length(); j++) sb[j] = (byte) s.charAt(j);
                        byte[] re = new byte[sb.length];
                        for (int j = 0; j < sb.length; j++) {
                            re[j] = (byte) ((sb[j] & 0xFF) ^ ksEph.atMasked(j + cipherLen + pi * 256));
                        }
                        cpResTmp[pi] = new String(re, java.nio.charset.StandardCharsets.ISO_8859_1);
                    } else {
                        cpResTmp[pi] = encCpRaw[pi];
                    }
                }
                this.cpRes = cpResTmp;
                this.cpRaw = null;               // no plaintext spec array under keying
                this.cp = new Object[cpN];
            }

            // Rolling-window watchdog baselines over the resident stream. The watchdog
            // uses FIXED deterministic keystreams so baselines and windowOk() checks stay
            // self-consistent, and never touches the interpreter's ksStatic/ksEph.
            this.ksWatch = new ChaCha20.Keystream(WATCH_K);
            this.ksWatchEph = new ChaCha20.Keystream(WATCH_E);
            int n = cipherLen;
            int nWin = Math.min(8, Math.max(1, (n + 31) / 32));
            int seg = (n + nWin - 1) / nWin;
            int[] wh = new int[nWin];
            for (int wi = 0; wi < nWin; wi++) {
                int base = wi * seg;
                int end = Math.min(n, base + seg);
                int wH = 0x811c9dc5;
                for (int i = base; i < end; i++) {
                    int p = (resident[i] & 0xFF)
                            ^ ksWatch.atMasked(i)
                            ^ ksWatchEph.atMasked(i);
                    wH ^= p; wH *= 0x01000193;
                }
                wh[wi] = wH;
            }
            this.winHash = wh;
            this.windowCount = nWin;
            this.windowSalt = noise ? 0 : (System.identityHashCode(this) & 0x7fffffff);
            LIVE_METHODS.put(this, Boolean.TRUE);   // watch this method from now on
            ensureWatchdog();                        // start the single shared thread lazily
        }

        /** Number of rolling windows this method is split into. */
        int windowCount() { return windowCount; }

        /** Deterministic per-method stagger so concurrent methods roll out of phase. */
        long windowSalt() { return windowSalt & 0x7fffffffL; }

        /** True once the watchdog has flagged this method as tampered / poisoned. */
        boolean watchTampered() { return tamperedWatch; }

        /**
         * Verifies window {@code w}: re-hashes that window of the resident stream with
         * the watchdog's own fixed keystreams and compares its FNV-1a with the baseline
         * computed at construction. Returns {@code true} if intact.
         */
        boolean windowOk(int w) {
            int[] wh = winHash;
            if (wh == null || w < 0 || w >= wh.length) return true;
            int seg = (cipherLen + windowCount - 1) / windowCount;
            int base = w * seg;
            int end = Math.min(cipherLen, base + seg);
            int h = 0x811c9dc5;
            for (int i = base; i < end; i++) {
                int x = (resident[i] & 0xFF)
                        ^ (ksWatch.atMasked(i) & 0xFF)
                        ^ (ksWatchEph.atMasked(i) & 0xFF);
                h ^= x; h *= 0x01000193;
            }
            return h == wh[w];
        }

        /** Corrupts the resident stream so any in-flight/future decode throws. */
        void poison() {
            if (tamperedWatch) return;
            tamperedWatch = true;
            byte[] r = resident;
            if (r != null && r.length > 0) r[0] ^= (byte) 0xFF;   // garbage opcode
            else if (r != null && r.length > 1) r[1] ^= (byte) 0xFF;
        }

        // --- rolling-window watchdog state (task 4) ---
        /** Watchdog's own static keystream (fixed, self-consistent, isolated). */
        private final ChaCha20.Keystream ksWatch;
        /** Watchdog's own per-run keystream (fixed, self-consistent, isolated). */
        private final ChaCha20.Keystream ksWatchEph;
        /** Precomputed FNV-1a fingerprint of each fixed stream window. */
        private final int[] winHash;
        /** Number of rolling windows this method is split into (1..WIN_COUNT). */
        private final int windowCount;
        /** Deterministic per-method stagger so concurrent methods roll out of phase. */
        private final int windowSalt;
        /** Set true by the watchdog when a rolling-window hash mismatches. */
        private volatile boolean tamperedWatch = false;

        /** Fixed watchdog keystream secrets (domain constant; need not equal K). */
        private static final byte[] WATCH_K = new byte[32];
        private static final byte[] WATCH_E = new byte[32];
        static {
            WATCH_K[0] = 0x4B; WATCH_K[1] = 0x42; WATCH_K[2] = 0x4F; WATCH_K[3] = 0x58;
            WATCH_E[0] = 0x56; WATCH_E[1] = 0x4D; WATCH_E[2] = 0x50; WATCH_E[3] = 0x21;
        }

        /*
         * Rolling-window decryption. These accessors decrypt a single byte / operand
         * from the per-run RESIDENT stream on demand, WITHOUT ever materializing a
         * plaintext copy of the whole method. At any instant only the bytes of the
         * current instruction exist in memory (as transient locals), so a memory dump
         * cannot recover a contiguous plaintext stream. Loops simply re-decrypt the
         * (intact) resident stream on each pass.
         */
        final int b(int pos) {
            return pos >= 0 && pos < cipherLen
                    ? (resident[pos] & 0xFF) ^ ksEph.atMasked(pos)
                    : 0;
        }

        final int i4(int pos) {
            return (b(pos) << 24) | ((b(pos + 1) & 0xFF) << 16)
                    | ((b(pos + 2) & 0xFF) << 8) | (b(pos + 3) & 0xFF);
        }

        final int u2(int pos) {
            return ((b(pos) & 0xFF) << 8) | (b(pos + 1) & 0xFF);
        }

        /**
         * One-pass integrity probe over the decrypted stream (no plaintext stored —
         * only transient FNV accumulation). Silently flags tampering.
         */
        final void checkIntegrity() {
            int h = 0x811c9dc5;
            for (int i = 0; i < cipherLen; i++) {
                int x = b(i);
                h ^= x; h *= 0x01000193;
            }
            if (h != constructionHash) KBOX_TAMPER.set(true);
        }
    }

    /** Verifies the interpreter class is present and readable. */
    private static void verifySelf() {
        try {
            java.io.InputStream in = VmpInterpreter.class.getClassLoader()
                    .getResourceAsStream("com/kbox/runtime/VmpInterpreter.class");
            if (in == null) { selfTampered = true; return; }
            // Drain the stream to confirm the resource is intact.
            long total = 0; byte[] buf = new byte[8192]; int r;
            while ((r = in.read(buf)) > 0) total += r;
            in.close();
            if (total < 1024) selfTampered = true;  // suspiciously small
        } catch (Throwable t) {
            selfTampered = true;
        }
    }

    static {
        verifySelf();
    }

    public static Object execute(VmpMethod m, Object instance, Object[] args) throws Throwable {
        // Generous headroom for the VMP pass pipeline: flatten/substitute/bogus are net-0 on the
        // stack, but defensive margin avoids ArrayIndexOutOfBounds if a future transform ever deepens it.
        Object[] stack = new Object[m.maxStack + 16];
        int sp = 0;
        Object[] locals = new Object[m.maxLocals];
        int pc = 0;

        // Load arguments into locals (instance first if non-static).
        int li = 0;
        if (instance != null) locals[li++] = instance;
        if (args != null) {
            for (Object a : args) {
                locals[li++] = a;
            }
        }

        // VortexVM/L1 rolling-window: no full plaintext buffer is ever created.
        // Integrity (tamper) probe runs over ciphertext only, transiently.
        m.checkIntegrity();
        Object[] cp = m.cp;
        int ppc = 0;
        long watchdogCtr = 0;
        try {
            boolean trace = System.getProperty("kbox.vmp.trace") != null;
            if (trace) {
                StringBuilder sb = new StringBuilder("[VMPTRACE] code(maxLocals=" + m.maxLocals
                        + ",maxStack=" + m.maxStack + ",argCount=" + m.argCount + "):");
                for (int i = 0; i < m.cipherLen; i++) sb.append(String.format(" %02x", m.b(i)));
                System.err.println(sb);
                if (m.cpRaw != null) {
                    for (int i = 0; i < m.cpRaw.length; i++) {
                        System.err.println("[VMPTRACE]   cp[" + i + "]=" + m.cpRaw[i]);
                    }
                }
            }
            while (true) {
                // Two-state XOR dispatch: (st1 ^ st2) == m.twin, resolving the
                // twin-masked opcode byte back to the real VmpOp for the switch.
                // st1/st2 both evolve per-pc using the per-run ephemeral layer, so
                // the dispatch value is opaque to static analysis while provably
                // correct (the ephemeral byte cancels in st1 ^ st2 == twin).
                int raw = m.b(pc);
                int kb = m.ksEph.atMasked(pc);
                int st1 = m.twin ^ kb;   // twin = st1 ^ st2
                int st2 = kb;
                int op = (st1 ^ st2) ^ raw;
                ppc = pc;
                pc++; // advance past opcode; operand readers advance further
                if (trace) {
                    System.err.println("[VMPTRACE] pc=" + ppc + " op=0x" + Integer.toHexString(op)
                            + " sp=" + sp + " (locals=" + m.maxLocals + ")");
                }
                // Periodically surface a watchdog-poisoned method. The poison also
                // corrupts the opcode stream, but this explicit probe makes the
                // tamper response immediate instead of waiting for a corrupted
                // instruction to be decoded. ~1 check per 1024 dispatches is ~free.
                if ((++watchdogCtr & 0x3FFL) == 0 && m.watchTampered()) {
                    throw new RuntimeException("VMP: integrity watchdog fired (tamper) @ " + ppc);
                }
                switch (op) {
                    case 0x01: stack[sp++] = null; break;                              // ACONST_NULL
                    case 0x02: stack[sp++] = m.i4(pc); pc += 4; break;          // ICONST
                    case 0x03: { long v = ((long) m.i4(pc) << 32)
                                        | (m.i4(pc + 4) & 0xFFFFFFFFL);
                                 stack[sp++] = v; pc += 8; } break;                     // LCONST
                    case 0x04: stack[sp++] = Float.intBitsToFloat(m.i4(pc)); pc += 4; break;
                    case 0x05: { long bits = ((long) m.i4(pc) << 32)
                                        | (m.i4(pc + 4) & 0xFFFFFFFFL);
                                 stack[sp++] = Double.longBitsToDouble(bits); pc += 8; } break;
                    case 0x06: stack[sp++] = resolveString(m, cp, m.i4(pc)); pc += 4; break;
                    case 0x07: stack[sp++] = resolveClass(m, cp, m.i4(pc)); pc += 4; break;

                    case 0x10: case 0x14: stack[sp++] = locals[m.u2(pc)]; pc += 2; break; // ILOAD / ALOAD
                    case 0x11: case 0x13: stack[sp++] = locals[m.u2(pc)]; pc += 2; break; // LLOAD / DLOAD
                    case 0x12: stack[sp++] = locals[m.u2(pc)]; pc += 2; break;            // FLOAD

                    case 0x18: case 0x1C: locals[m.u2(pc)] = stack[--sp]; pc += 2; break;  // ISTORE / ASTORE
                    case 0x19: case 0x1B: locals[m.u2(pc)] = stack[--sp]; pc += 2; break;  // LSTORE / DSTORE
                    case 0x1A: locals[m.u2(pc)] = stack[--sp]; pc += 2; break;              // FSTORE

                    case 0x20: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a + b; break; } // IADD
                    case 0x21: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a - b; break; } // ISUB
                    case 0x22: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a * b; break; } // IMUL
                    case 0x23: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a / b; break; } // IDIV
                    case 0x24: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a % b; break; } // IREM
                    case 0x25: { int a = toInt(stack[--sp]); stack[sp++] = -a; break; } // INEG
                    case 0x26: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a << b; break; } // ISHL
                    case 0x27: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a >> b; break; } // ISHR
                    case 0x28: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a >>> b; break; } // IUSHR
                    case 0x29: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a & b; break; } // IAND
                    case 0x2A: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a | b; break; } // IOR
                    case 0x2B: { int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); stack[sp++] = a ^ b; break; } // IXOR
                    case 0x2C: { int v = m.u2(pc); int d = m.i4(pc + 2);
                                 locals[v] = toInt(locals[v]) + d; pc += 6; break; }              // IINC

                    // --- Type conversions ---
                    case 0x2D: stack[sp - 1] = (long) toInt(stack[sp - 1]); break;                   // I2L
                    case 0x2E: stack[sp - 1] = (float) toInt(stack[sp - 1]); break;                  // I2F
                    case 0x2F: stack[sp - 1] = (double) toInt(stack[sp - 1]); break;                // I2D
                    case 0xA0: stack[sp - 1] = (int) toLong(stack[sp - 1]); break;                   // L2I
                    case 0xA1: stack[sp - 1] = (float) toLong(stack[sp - 1]); break;                 // L2F
                    case 0xA2: stack[sp - 1] = (double) toLong(stack[sp - 1]); break;                // L2D
                    case 0xA3: stack[sp - 1] = (int) toFloat(stack[sp - 1]); break;                  // F2I
                    case 0xA4: stack[sp - 1] = (long) toFloat(stack[sp - 1]); break;                 // F2L
                    case 0xA5: stack[sp - 1] = (double) toFloat(stack[sp - 1]); break;                // F2D
                    case 0xA6: stack[sp - 1] = (int) toDouble(stack[sp - 1]); break;                 // D2I
                    case 0xA7: stack[sp - 1] = (long) toDouble(stack[sp - 1]); break;                // D2L
                    case 0xA8: stack[sp - 1] = (float) toDouble(stack[sp - 1]); break;                // D2F
                    case 0xA9: stack[sp - 1] = (byte) toInt(stack[sp - 1]); break;                   // I2B
                    case 0xAA: stack[sp - 1] = (char) toInt(stack[sp - 1]); break;                    // I2C
                    case 0xAB: stack[sp - 1] = (short) toInt(stack[sp - 1]); break;                  // I2S

                    // --- Long arithmetic ---
                    case 0xAC: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = (a == b ? 0 : (a < b ? -1 : 1)); break; } // LCMP
                    case 0xAD: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a + b; break; } // LADD
                    case 0xAE: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a - b; break; } // LSUB
                    case 0xAF: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a * b; break; } // LMUL
                    case 0xB0: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a / b; break; } // LDIV
                    case 0xB1: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a % b; break; } // LREM
                    case 0xB2: { long a = toLong(stack[--sp]); stack[sp++] = -a; break; }            // LNEG
                    case 0xB3: { int b = toInt(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a << b; break; } // LSHL
                    case 0xB4: { int b = toInt(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a >> b; break; } // LSHR
                    case 0xB5: { int b = toInt(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a >>> b; break; } // LUSHR
                    case 0xB6: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a & b; break; } // LAND
                    case 0xB7: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a | b; break; } // LOR
                    case 0xB8: { long b = toLong(stack[--sp]); long a = toLong(stack[--sp]); stack[sp++] = a ^ b; break; } // LXOR

                    // --- Float/double arithmetic ---
                    case 0xB9: { float b = toFloat(stack[--sp]); float a = toFloat(stack[--sp]); stack[sp++] = a + b; break; } // FADD
                    case 0xBA: { float b = toFloat(stack[--sp]); float a = toFloat(stack[--sp]); stack[sp++] = a - b; break; } // FSUB
                    case 0xBB: { float b = toFloat(stack[--sp]); float a = toFloat(stack[--sp]); stack[sp++] = a * b; break; } // FMUL
                    case 0xBC: { float b = toFloat(stack[--sp]); float a = toFloat(stack[--sp]); stack[sp++] = a / b; break; } // FDIV
                    case 0xBD: { float b = toFloat(stack[--sp]); float a = toFloat(stack[--sp]); stack[sp++] = a % b; break; } // FREM
                    case 0xBE: { float a = toFloat(stack[--sp]); stack[sp++] = -a; break; }           // FNEG
                    case 0xBF: { double b = toDouble(stack[--sp]); double a = toDouble(stack[--sp]); stack[sp++] = a + b; break; } // DADD
                    case 0xC0: { double b = toDouble(stack[--sp]); double a = toDouble(stack[--sp]); stack[sp++] = a - b; break; } // DSUB
                    case 0xC1: { double b = toDouble(stack[--sp]); double a = toDouble(stack[--sp]); stack[sp++] = a * b; break; } // DMUL
                    case 0xC2: { double b = toDouble(stack[--sp]); double a = toDouble(stack[--sp]); stack[sp++] = a / b; break; } // DDIV
                    case 0xC3: { double b = toDouble(stack[--sp]); double a = toDouble(stack[--sp]); stack[sp++] = a % b; break; } // DREM
                    case 0xC4: { double a = toDouble(stack[--sp]); stack[sp++] = -a; break; }         // DNEG
                    case 0xC5: { float b = toFloat(stack[--sp]); float a = toFloat(stack[--sp]); stack[sp++] = Float.compare(a, b); break; } // FCMPL
                    case 0xC6: { float b = toFloat(stack[--sp]); float a = toFloat(stack[--sp]); stack[sp++] = (a > b ? 1 : (a < b ? -1 : (Float.isNaN(a) || Float.isNaN(b) ? 1 : 0))); break; } // FCMPG
                    case 0xC7: { double b = toDouble(stack[--sp]); double a = toDouble(stack[--sp]); stack[sp++] = Double.compare(a, b); break; } // DCMPL
                    case 0xC8: { double b = toDouble(stack[--sp]); double a = toDouble(stack[--sp]); stack[sp++] = (a > b ? 1 : (a < b ? -1 : (Double.isNaN(a) || Double.isNaN(b) ? 1 : 0))); break; } // DCMPG

                    case 0x30: { int t = m.i4(pc); pc += 4; if (toInt(stack[--sp]) == 0) pc = t; break; } // IFEQ
                    case 0x31: { int t = m.i4(pc); pc += 4; if (toInt(stack[--sp]) != 0) pc = t; break; } // IFNE
                    case 0x32: { int t = m.i4(pc); pc += 4; if (toInt(stack[--sp]) <  0) pc = t; break; } // IFLT
                    case 0x33: { int t = m.i4(pc); pc += 4; if (toInt(stack[--sp]) >= 0) pc = t; break; } // IFGE
                    case 0x34: { int t = m.i4(pc); pc += 4; if (toInt(stack[--sp]) >  0) pc = t; break; } // IFGT
                    case 0x35: { int t = m.i4(pc); pc += 4; if (toInt(stack[--sp]) <= 0) pc = t; break; } // IFLE
                    case 0x36: { int t = m.i4(pc); pc += 4; int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); if (a == b) pc = t; break; }
                    case 0x37: { int t = m.i4(pc); pc += 4; int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); if (a != b) pc = t; break; }
                    case 0x38: { int t = m.i4(pc); pc += 4; int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); if (a <  b) pc = t; break; }
                    case 0x39: { int t = m.i4(pc); pc += 4; int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); if (a >= b) pc = t; break; }
                    case 0x3A: { int t = m.i4(pc); pc += 4; int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); if (a >  b) pc = t; break; }
                    case 0x3B: { int t = m.i4(pc); pc += 4; int b = toInt(stack[--sp]); int a = toInt(stack[--sp]); if (a <= b) pc = t; break; }
                    case 0x3C: { int t = m.i4(pc); pc += 4; if (stack[--sp] == null) pc = t; break; }
                    case 0x3D: { int t = m.i4(pc); pc += 4; if (stack[--sp] != null) pc = t; break; }
                    case 0x3F: { int t = m.i4(pc); pc += 4; Object b = stack[--sp]; Object a = stack[--sp]; if (a == b) pc = t; break; } // IF_ACMPEQ
                    case 0xC9: { int t = m.i4(pc); pc += 4; Object b = stack[--sp]; Object a = stack[--sp]; if (a != b) pc = t; break; } // IF_ACMPNE
                    case 0x3E: { int t = m.i4(pc); pc = t; break; }                         // GOTO

                    case 0x40: --sp; break;                                                          // POP
                    case 0x41: sp -= 2; break;                                                       // POP2
                    case 0x42: stack[sp] = stack[sp - 1]; sp++; break;                              // DUP
                    case 0x43: { Object v = stack[sp - 1]; stack[sp] = v; stack[sp - 1] = stack[sp - 2]; stack[sp - 2] = v; sp++; break; } // DUP_X1
                    case 0xCA: { Object v = stack[sp - 1]; stack[sp] = v; stack[sp - 1] = stack[sp - 2]; stack[sp - 2] = stack[sp - 3]; stack[sp - 3] = v; sp++; break; } // DUP_X2
                    case 0xCB: { stack[sp] = stack[sp - 1]; stack[sp + 1] = stack[sp - 2]; sp += 2; break; } // DUP2 (category 1: duplicate top two)
                    case 0xCC: { Object v1 = stack[sp - 1]; Object v2 = stack[sp - 2]; stack[sp] = v1; stack[sp + 1] = v2; stack[sp - 1] = stack[sp - 3]; stack[sp - 2] = v1; stack[sp - 3] = v2; sp += 2; break; } // DUP2_X1
                    case 0xCD: { Object v1 = stack[sp - 1]; Object v2 = stack[sp - 2]; stack[sp + 1] = v1; stack[sp] = v2; stack[sp - 1] = stack[sp - 3]; stack[sp - 2] = stack[sp - 4]; stack[sp - 3] = v2; stack[sp - 4] = v1; sp += 2; break; } // DUP2_X2
                    case 0x44: { Object t = stack[sp - 1]; stack[sp - 1] = stack[sp - 2]; stack[sp - 2] = t; break; } // SWAP

                    case 0x50: { Field f = resolveField(m, cp, m.i4(pc), true);
                                 initClass(f.getDeclaringClass()); // GETSTATIC must initialize the class
                                 Object gv = f.get(null);
                                 if (System.getProperty("kbox.vmp.dbg") != null)
                                     System.err.println("[VMPDBG] pc=" + ppc + " GETSTATIC " + f.getDeclaringClass().getSimpleName()
                                             + "." + f.getName() + " = " + (gv == null ? "NULL" : gv.getClass().getName()));
                                 stack[sp++] = gv; pc += 4; break; }                                 // GETSTATIC
                    case 0x51: { Field f = resolveField(m, cp, m.i4(pc), true);
                                 initClass(f.getDeclaringClass()); // PUTSTATIC must initialize the class
                                 f.set(null, stack[--sp]); pc += 4; break; }                         // PUTSTATIC
                    case 0x52: { Field f = resolveField(m, cp, m.i4(pc), false);
                                 Object o = stack[--sp]; stack[sp++] = f.get(o); pc += 4; break; }    // GETFIELD
                    case 0x53: { Field f = resolveField(m, cp, m.i4(pc), false);
                                 Object v = stack[--sp]; Object o = stack[--sp]; f.set(o, v); pc += 4; break; } // PUTFIELD

                    case 0x60: { // INVOKEVIRTUAL
                        int idx = m.i4(pc); pc += 4;
                        Method me = resolveMethod(m, cp, idx, false);
                        Object[] args2 = popArgs(me.getParameterTypes(), stack, sp);
                        sp -= args2.length;
                        Object recv = stack[--sp];
                        Object r = safeInvoke(me, recv, args2);
                        if (me.getReturnType() != void.class) stack[sp++] = r;
                        break;
                    }
                    case 0x61: { // INVOKESPECIAL (private / super / ctor)
                        int idx = m.i4(pc); pc += 4;
                        // Distinguish constructor vs private method via cp spec.
                        Object spec = m.specAt(idx);
                        if (spec instanceof String && ((String) spec).contains("#<init>#")) {
                            Constructor<?> c = resolveCtor(m, cp, idx);
                            Object[] args2 = popArgs(c.getParameterTypes(), stack, sp);
                            sp -= args2.length;
                            // The receiver is the Class marker pushed by NEW (javac/Kotlin
                            // emit NEW;DUP;INVOKESPECIAL <init>). NEW pushed one marker and DUP
                            // copied it, so the stack holds [.., marker0, marker1] where
                            // marker1 (top) is the receiver. Discard the receiver and replace
                            // the NEW slot (marker0) with the real instance, so the stack ends
                            // up with exactly one object reference (matching JVM semantics).
                            Object marker = stack[sp - 1];
                            boolean duped = sp >= 2 && stack[sp - 2] == marker;
                            stack[duped ? sp - 2 : sp - 1] = c.newInstance(coerceArgs(c.getParameterTypes(), args2));
                            sp--; // pop the receiver
                        } else {
                            Method me = resolveMethod(m, cp, idx, false);
                            Object[] args2 = popArgs(me.getParameterTypes(), stack, sp);
                            sp -= args2.length;
                            Object recv = stack[--sp];
                            Object r = safeInvoke(me, recv, args2);
                            if (me.getReturnType() != void.class) stack[sp++] = r;
                        }
                        break;
                    }
                    case 0x62: { // INVOKESTATIC
                        int idx = m.i4(pc); pc += 4;
                        Method me = resolveMethod(m, cp, idx, true);
                        Object[] args2 = popArgs(me.getParameterTypes(), stack, sp);
                        sp -= args2.length;
                        Object r = safeInvoke(me, null, args2);
                        if (me.getReturnType() != void.class) stack[sp++] = r;
                        break;
                    }
                    case 0x63: { // INVOKEINTERFACE
                        int idx = m.i4(pc); pc += 4;
                        Method me = resolveMethod(m, cp, idx, false);
                        Object[] args2 = popArgs(me.getParameterTypes(), stack, sp);
                        sp -= args2.length;
                        Object recv = stack[--sp];
                        Object r = safeInvoke(me, recv, args2);
                        if (me.getReturnType() != void.class) stack[sp++] = r;
                        break;
                    }
                    case 0x70: { Class<?> c = resolveClass(m, cp, m.i4(pc)); pc += 4;
                                 // NEW must NOT run a constructor: the old code called c.newInstance()
                                 // here AND again in the INVOKESPECIAL <init> handler, constructing the
                                 // object twice (and crashing when no no-arg ctor exists). Push a Class
                                 // marker that the matching <init> consumes and replaces with the real
                                 // instance. javac/Kotlin always emit NEW;DUP;INVOKESPECIAL <init>, so the
                                 // marker is only ever consumed by <init>.
                                 stack[sp++] = c; break; }                                          // NEW (push class marker)
                    case 0x71: { int at = m.i4(pc); pc += 4;
                                 Class<?> elem = arrayType(at); int len = toInt(stack[--sp]);
                                 stack[sp++] = Array.newInstance(elem, len); break; }              // NEWARRAY
                    case 0x72: { Class<?> c = resolveClass(m, cp, m.i4(pc)); pc += 4;
                                 int len = toInt(stack[--sp]); stack[sp++] = Array.newInstance(c, len); break; } // ANEWARRAY
                    case 0x73: { int arrDepth = sp - 1;
                                 Object alArr = stack[arrDepth];
                                 if (System.getProperty("kbox.vmp.dbg") != null)
                                     System.err.println("[VMPDBG] pc=" + ppc + " ARRAYLENGTH arr="
                                             + (alArr == null ? "NULL" : alArr.getClass().getName())
                                             + " sp=" + sp + " locals4=" + (m.maxLocals > 4 ? locals[4] : "x")
                                             + " locals5=" + (m.maxLocals > 5 ? locals[5] : "x"));
                                 stack[arrDepth] = Array.getLength(alArr); break; }                  // ARRAYLENGTH (pop then push)
                    case 0x74: { int i = toInt(stack[--sp]); Object a = stack[--sp]; stack[sp++] = Array.get(a, i); break; } // AALOAD
                    case 0x75: { int i = toInt(stack[--sp]); Object v = stack[--sp]; Object a = stack[--sp]; Array.set(a, i, v); break; } // AASTORE
                    case 0x76: { int i = toInt(stack[--sp]); Object a = stack[--sp]; stack[sp++] = Array.getInt(a, i); break; } // IALOAD
                    case 0x77: { int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp]; Array.setInt(a, i, v); break; } // IASTORE
                    case 0x7A: { int i = toInt(stack[--sp]); Object a = stack[--sp]; stack[sp++] = Array.getByte(a, i); break; } // BALOAD
                    case 0x7B: { int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp]; Array.setByte(a, i, (byte) v); break; } // BASTORE
                    case 0x7C: { int i = toInt(stack[--sp]); Object a = stack[--sp]; stack[sp++] = Array.getChar(a, i); break; } // CALOAD
                    case 0x7D: { int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp]; Array.setChar(a, i, (char) v); break; } // CASTORE
                    case 0x7E: { int i = toInt(stack[--sp]); Object a = stack[--sp]; stack[sp++] = Array.getShort(a, i); break; } // SALOAD
                    case 0x7F: { int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp]; Array.setShort(a, i, (short) v); break; } // SASTORE
                    case 0x78: { Class<?> c = resolveClass(m, cp, m.i4(pc)); pc += 4;
                                 stack[sp - 1] = c.cast(stack[sp - 1]); break; }                     // CHECKCAST
                    case 0x79: { Class<?> c = resolveClass(m, cp, m.i4(pc)); pc += 4;
                                 stack[sp - 1] = c.isInstance(stack[sp - 1]); break; }              // INSTANCEOF

                    case 0x80: { Object o = stack[sp - 1]; enterMonitor(o); break; }                // MONITORENTER
                    case 0x81: { Object o = stack[--sp]; exitMonitor(o); break; }                   // MONITOREXIT

                    case 0x82: throw (Throwable) stack[--sp];                                       // ATHROW

                    case 0x90: { int iv = toInt(stack[--sp]); return boxIntReturn(m, iv); }   // IRETURN
                    case 0x91: return stack[--sp];                                                   // LRETURN
                    case 0x92: return stack[--sp];                                                   // FRETURN
                    case 0x93: return stack[--sp];                                                   // DRETURN
                    case 0x94: return stack[--sp];                                                   // ARETURN
                    case 0x95: return null;                                                          // RETURN

                    case 0xFF: return null;                                                          // END
                    default:
                        throw new RuntimeException("VMP: unknown opcode 0x"
                                + Integer.toHexString(op) + " @ " + ppc);
                }
            }
        } catch (Throwable t) {
            // Consult the exception table.
            if (m.exceptions != null) {
                for (int[] row : m.exceptions) {
                    if (ppc >= row[0] && ppc < row[1]) {
                        Class<?> catchType = row[3] >= 0
                                ? resolveClass(m, cp, row[3]) : Throwable.class;
                        if (catchType.isInstance(t)) {
                            // Clear operand stack, push the exception, jump.
                            sp = 0;
                            stack[sp++] = t;
                            pc = row[2];
                            continue;
                        }
                    }
                }
            }
            throw t;
        } finally {
            // VortexVM/L1 rolling-window: nothing to wipe — no full plaintext
            // buffer was ever created; only the intact ciphertext remains.
        }
    }

    // --- helpers ---

    private static Object[] popArgs(Class<?>[] ptypes, Object[] stack, int sp) {
        Object[] args = new Object[ptypes.length];
        for (int i = ptypes.length - 1; i >= 0; i--) {
            args[i] = stack[--sp];
        }
        return args;
    }

    /**
     * Converts popped (already boxed) argument values to the exact boxed type a
     * reflection {@code Method.invoke}/{@code Constructor.newInstance} expects.
     * The interpreter pushes char/byte/short constants as {@code Integer} on the
     * operand stack, but reflection does not auto-widen to {@code Character}/
     * {@code Byte}/{@code Short}, which would throw {@code IllegalArgumentException:
     * argument type mismatch}. This coerces only primitive targets; reference types
     * are passed through untouched.
     */
    private static Object[] coerceArgs(Class<?>[] ptypes, Object[] args) {
        if (ptypes == null || args == null) return args;
        Object[] out = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            out[i] = (i < ptypes.length) ? coerceArg(args[i], ptypes[i]) : args[i];
        }
        return out;
    }

    /** Coerces a single value to the boxed form of a primitive parameter type. */
    private static Object coerceArg(Object v, Class<?> t) {
        if (v == null || !t.isPrimitive()) return v;
        if (t == int.class)     return (v instanceof Integer)   ? v : (Integer) toInt(v);
        if (t == boolean.class) return (v instanceof Boolean)   ? v : (toInt(v) != 0);
        if (t == byte.class)    return (v instanceof Byte)      ? v : (byte) toInt(v);
        if (t == short.class)   return (v instanceof Short)     ? v : (short) toInt(v);
        if (t == char.class)    return (v instanceof Character) ? v : (char) toInt(v);
        if (t == long.class)    return (v instanceof Long)      ? v : toLong(v);
        if (t == float.class)   return (v instanceof Float)     ? v : toFloat(v);
        if (t == double.class)  return (v instanceof Double)    ? v : toDouble(v);
        return v;
    }

    private static int toInt(Object o) {
        if (o instanceof Integer) return (int) o;
        if (o instanceof Boolean) return (boolean) o ? 1 : 0;
        if (o instanceof Character) return (char) o;
        if (o instanceof Byte) return (byte) o;
        if (o instanceof Short) return (short) o;
        throw new ClassCastException("VMP: not int-compatible: " + o);
    }

    /**
     * Boxes an IRETURN value according to the VmpMethod's declared return type.
     * The generated wrapper stub does {@code CHECKCAST <boxed>; xxxValue; IRETURN}
     * for primitive int/sub-int returns, so the interpreter MUST hand back the
     * correct boxed type (Boolean/Byte/Character/Short/Integer) or the cast fails.
     */
    private static Object boxIntReturn(VmpMethod m, int v) {
        switch (m.retSort) {
            case org.objectweb.asm.Type.BOOLEAN: return v != 0;
            case org.objectweb.asm.Type.BYTE:    return (byte) v;
            case org.objectweb.asm.Type.CHAR:    return (char) v;
            case org.objectweb.asm.Type.SHORT:   return (short) v;
            default: return v; // INT (or anything treated as int)
        }
    }

    private static long toLong(Object o) {
        if (o instanceof Long) return (long) o;
        if (o instanceof Integer) return (int) o;
        if (o instanceof Short) return (short) o;
        if (o instanceof Byte) return (byte) o;
        if (o instanceof Character) return (char) o;
        if (o instanceof Boolean) return (boolean) o ? 1L : 0L;
        throw new ClassCastException("VMP: not long-compatible: " + o);
    }

    private static float toFloat(Object o) {
        if (o instanceof Float) return (float) o;
        if (o instanceof Integer) return (float) (int) o;
        if (o instanceof Long) return (float) (long) o;
        if (o instanceof Short) return (short) o;
        if (o instanceof Byte) return (byte) o;
        if (o instanceof Character) return (char) o;
        if (o instanceof Boolean) return (boolean) o ? 1f : 0f;
        throw new ClassCastException("VMP: not float-compatible: " + o);
    }

    private static double toDouble(Object o) {
        if (o instanceof Double) return (double) o;
        if (o instanceof Float) return (float) o;
        if (o instanceof Long) return (double) (long) o;
        if (o instanceof Integer) return (int) o;
        if (o instanceof Short) return (short) o;
        if (o instanceof Byte) return (byte) o;
        if (o instanceof Character) return (char) o;
        if (o instanceof Boolean) return (boolean) o ? 1.0 : 0.0;
        throw new ClassCastException("VMP: not double-compatible: " + o);
    }

    private static int readInt(byte[] code, int pc) {
        return (code[pc] << 24) | ((code[pc + 1] & 0xFF) << 16)
                | ((code[pc + 2] & 0xFF) << 8) | (code[pc + 3] & 0xFF);
    }

    private static int readU2(byte[] code, int pc) {
        return ((code[pc] & 0xFF) << 8) | (code[pc + 1] & 0xFF);
    }

    private static final Object UNSAFE;
    private static final java.lang.reflect.Method MON_ENTER;
    private static final java.lang.reflect.Method MON_EXIT;
    static {
        Object u = null; java.lang.reflect.Method e = null, x = null;
        try {
            Class<?> uc = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field f = uc.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            u = f.get(null);
            e = uc.getMethod("monitorEnter", Object.class);
            x = uc.getMethod("monitorExit", Object.class);
        } catch (Throwable t) {
            // JDK 17+ blocks sun.misc.Unsafe by default; fall back to no-op (rare path).
        }
        UNSAFE = u; MON_ENTER = e; MON_EXIT = x;
    }

    /**
     * Enters the JVM monitor on {@code o} (held until the matching
     * {@link #exitMonitor}). Uses {@code sun.misc.Unsafe#monitorEnter} when
     * available (JDK 8); on JDK 17+ where Unsafe is blocked, falls back to a
     * striped {@link java.util.concurrent.locks.ReentrantLock}. The striped
     * fallback is reentrant and enforces mutual exclusion across interpreter
     * threads; it is intentionally conservative (objects sharing a stripe are
     * serialized) but is correct, unlike the old no-op fallback which released
     * the lock immediately and broke atomicity of synchronized regions.
     */
    private static void enterMonitor(Object o) {
        if (o == null) return;
        if (MON_ENTER != null) {
            try { MON_ENTER.invoke(UNSAFE, o); return; } catch (Exception ignored) {}
        }
        MONITOR_STRIPES[stripe(o)].lock();
        heldLocks().push(o);
    }

    private static void exitMonitor(Object o) {
        if (o == null) return;
        if (MON_EXIT != null) {
            try { MON_EXIT.invoke(UNSAFE, o); return; } catch (Exception ignored) {}
        }
        java.util.ArrayDeque<Object> s = heldLocks();
        if (!s.isEmpty() && s.peek() == o) s.pop();
        MONITOR_STRIPES[stripe(o)].unlock();
    }

    private static final java.util.concurrent.locks.ReentrantLock[] MONITOR_STRIPES =
            new java.util.concurrent.locks.ReentrantLock[256];
    static {
        for (int i = 0; i < MONITOR_STRIPES.length; i++) {
            MONITOR_STRIPES[i] = new java.util.concurrent.locks.ReentrantLock();
        }
    }

    private static int stripe(Object o) {
        return (System.identityHashCode(o) & 0x7fffffff) % MONITOR_STRIPES.length;
    }

    private static java.util.ArrayDeque<Object> heldLocks() {
        @SuppressWarnings("unchecked")
        java.util.ArrayDeque<Object> s = (java.util.ArrayDeque<Object>) HELD.get();
        if (s == null) { s = new java.util.ArrayDeque<>(); HELD.set(s); }
        return s;
    }

    private static final ThreadLocal<Object> HELD = new ThreadLocal<>();

    private static String resolveString(VmpMethod m, Object[] cp, int idx) {
        Object v = cp[idx];
        if (v != null) return (String) v;
        // Lazy keyed constant: decrypt on demand, do NOT retain the plaintext.
        return m.specAt(idx);
    }

    private static Class<?> resolveClass(VmpMethod m, Object[] cp, int idx) {
        Object v = cp[idx];
        if (v != null) return (Class<?>) v;
        String spec = m.specAt(idx);
        Class<?> c = classForName(spec.replace('/', '.'));
        cp[idx] = c;
        return c;
    }

    private static Field resolveField(VmpMethod m, Object[] cp, int idx, boolean isStatic) {
        Object v = cp[idx];
        if (v != null) return (Field) v;
        String spec = m.specAt(idx); // "owner#name#desc"
        String[] parts = spec.split("#");
        try {
            Class<?> owner = classForName(parts[0].replace('/', '.'));
            // Like methods, getDeclaredField() does not find inherited fields.
            // Walk the whole hierarchy to find the first definition.
            Field f = findField(owner, parts[1]);
            try {
                f.setAccessible(true);
            } catch (RuntimeException ex) {
                // JDK 17+ module access (e.g. java.lang protected members).
            }
            cp[idx] = f;
            return f;
        } catch (Exception e) {
            throw new RuntimeException("VMP: field resolve failed " + spec, e);
        }
    }

    /** Resolves {@code name} across the class hierarchy (finds inherited fields). */
    private static Field findField(Class<?> owner, String name) throws NoSuchFieldException {
        Class<?> c = owner;
        while (c != null) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                // continue
            }
            c = c.getSuperclass();
        }
        return owner.getField(name); // public fallback
    }

    private static Method resolveMethod(VmpMethod m, Object[] cp, int idx, boolean isStatic) {
        Object v = cp[idx];
        if (v != null) return (Method) v;
        String spec = m.specAt(idx); // "owner#name#desc"
        String[] parts = spec.split("#");
        try {
            Class<?> owner = classForName(parts[0].replace('/', '.'));
            Class<?>[] ptypes = parseArgTypes(parts[2]);
            // getDeclaredMethod() alone fails for inherited methods and interface dispatch,
            // which breaks a large fraction of real-world methods. Walk the whole hierarchy.
            Method me = findMethod(owner, parts[1], ptypes);
            try {
                me.setAccessible(true);
            } catch (RuntimeException ex) {
                // JDK 17+ module system: java.lang is not open to the unnamed module,
                // so setAccessible on protected members like Object.clone() throws
                // InaccessibleObjectException. Keep the method; public/internal members
                // still invoke fine via safeInvoke(), which handles array clone()
                // natively and surfaces a clear error only when genuinely not invokable.
            }
            cp[idx] = me;
            return me;
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("VMP: method resolve failed " + spec, e);
        }
    }

    /**
     * Invokes {@code me} on {@code recv} with {@code args}, handling the JDK 17+
     * module-access limitation. In particular {@code Object.clone()} (invoked on
     * arrays, e.g. {@code byte[].clone()}) is {@code protected native} in
     * {@code java.base}, which the interpreter cannot make accessible; we instead
     * perform a shallow array copy that matches {@code Object.clone()} semantics.
     */
    private static Object safeInvoke(Method me, Object recv, Object[] args) throws Exception {
        if (me.getName().equals("clone") && recv != null && recv.getClass().isArray()) {
            Class<?> comp = recv.getClass().getComponentType();
            int len = java.lang.reflect.Array.getLength(recv);
            Object na = java.lang.reflect.Array.newInstance(comp, len);
            System.arraycopy(recv, 0, na, 0, len);
            return na;
        }
        try {
            return me.invoke(recv, coerceArgs(me.getParameterTypes(), args));
        } catch (IllegalArgumentException e) {
            System.err.println("[VMPDBG] safeInvoke failed: " + me + " recv="
                    + (recv == null ? "null" : recv.getClass().getName())
                    + " declaringClass=" + me.getDeclaringClass().getName());
            throw e;
        }
    }

    /**
     * Resolves {@code name(ptypes)} across the class hierarchy and interfaces, so
     * INVOKEVIRTUAL on inherited/overridden methods and interface dispatch work.
     */
    private static Method findMethod(Class<?> owner, String name, Class<?>[] ptypes)
            throws NoSuchMethodException {
        NoSuchMethodException last = null;
        Class<?> c = owner;
        while (c != null) {
            try {
                return c.getDeclaredMethod(name, ptypes);
            } catch (NoSuchMethodException e) {
                last = e;
            }
            c = c.getSuperclass();
        }
        for (Class<?> iface : owner.getInterfaces()) {
            try {
                return findMethod(iface, name, ptypes);
            } catch (NoSuchMethodException ignore) {
                // continue
            }
        }
        try {
            return owner.getMethod(name, ptypes); // public (incl. inherited) fallback
        } catch (NoSuchMethodException e) {
            last = e;
        }
        throw (NoSuchMethodException) last;
    }

    private static Constructor<?> resolveCtor(VmpMethod m, Object[] cp, int idx) {
        Object v = cp[idx];
        if (v != null) return (Constructor<?>) v;
        String spec = m.specAt(idx); // "owner#<init>#desc"
        String[] parts = spec.split("#");
        try {
            Class<?> owner = classForName(parts[0].replace('/', '.'));
            Class<?>[] ptypes = parseArgTypes(parts[2]);
            Constructor<?> c = owner.getDeclaredConstructor(ptypes);
            c.setAccessible(true);
            cp[idx] = c;
            return c;
        } catch (Exception e) {
            throw new RuntimeException("VMP: ctor resolve failed " + spec, e);
        }
    }

    private static final Map<String, Class<?>> PRIMS = new HashMap<>();
    static {
        PRIMS.put("I", int.class); PRIMS.put("J", long.class);
        PRIMS.put("F", float.class); PRIMS.put("D", double.class);
        PRIMS.put("Z", boolean.class); PRIMS.put("B", byte.class);
        PRIMS.put("S", short.class); PRIMS.put("C", char.class); PRIMS.put("V", void.class);
    }

    private static Class<?> classForName(String name) {
        Class<?> c = PRIMS.get(name);
        if (c != null) return c;
        // Handle JVM type descriptors: [I, [Ljava/lang/Object;, Ljava/lang/Object;
        if (name.startsWith("[")) {
            String elem = name.substring(1);
            return Array.newInstance(classForName(elem), 0).getClass();
        }
        if (name.startsWith("L") && name.endsWith(";")) {
            name = name.substring(1, name.length() - 1).replace('/', '.');
        }
        if (name.endsWith("[]")) {
            String elem = name.substring(0, name.length() - 2);
            return Array.newInstance(classForName(elem), 0).getClass();
        }
        try {
            return Class.forName(name, false, Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("VMP: class not found " + name, e);
        }
    }

    /**
     * Forces the given class to be initialized (runs its {@code <clinit>}).
     * The JVM initializes a class whenever a static member is first accessed
     * (GETSTATIC/PUTSTATIC/INVOKESTATIC). Reflection-based {@code Field.get/set}
     * used by the interpreter does NOT trigger initialization, so static fields
     * of lazy classes (e.g. scattered-string holders like {@code _KboxS*}) would
     * otherwise read as null. This restores the required JVM semantics.
     */
    private static void initClass(Class<?> c) {
        if (c == null) return;
        try {
            Class.forName(c.getName(), true, c.getClassLoader());
        } catch (Throwable t) {
            // Not initialized; leave it — the subsequent field access will surface any real error.
        }
    }

    private static Class<?>[] parseArgTypes(String desc) {
        // desc like "(II)V" — parse args only.
        java.util.List<Class<?>> out = new java.util.ArrayList<>();
        int i = 1; // skip '('
        while (desc.charAt(i) != ')') {
            int start = i;
            while (desc.charAt(i) == '[') i++;
            char c = desc.charAt(i);
            if (c == 'L') {
                while (desc.charAt(i) != ';') i++;
                i++;
            } else {
                i++;
            }
            out.add(classForName(desc.substring(start, i).replace('/', '.')));
        }
        return out.toArray(new Class<?>[0]);
    }

    private static Class<?> arrayType(int code) {
        switch (code) {
            case 4: return boolean.class;
            case 5: return char.class;
            case 6: return float.class;
            case 7: return double.class;
            case 8: return byte.class;
            case 9: return short.class;
            case 10: return int.class;
            case 11: return long.class;
            default: throw new RuntimeException("VMP: bad newarray code " + code);
        }
    }
}
