package com.kbox.runtime;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
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

    /** Raised when a per-method ciphertext integrity probe fails (silent).
     *  Field name intentionally generic — a recognizable Utf8 entry would
     *  re-leak the format tag into the JVM's metaspace. */
    private static final java.util.concurrent.atomic.AtomicBoolean _T1 =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /**
     * Union accessor so string decryption and other sinks can also poison when
     * the VM self-check / watchdog fires, not just when the debugger canary does.
     * Deliberately a public static so {@link TamperShield} can consult it without
     * depending on the interpreter's internal state shape.
     */
    public static boolean isTampered() { return _T1.get() || selfTampered; }

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
                        _T1.set(true);
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
         *  launch while {@code b()} still recovers the exact plaintext.
         *  <p>Held in an OFF-HEAP {@link java.nio.ByteBuffer} (never a Java heap
         *  {@code byte[]}) so the per-run wave never materialises as a heap array:
         *  heap scanners / dumps cannot anchor onto a contiguous ciphertext wave. */
        private final java.nio.ByteBuffer resident;
        private final int cipherLen;
        /** FNV-1a of the full decrypted plaintext, computed transiently at construction. */
        private final int constructionHash;
        /** ChaCha20 keystream from the unwrapped method key K (recover static plain). */
        private final ChaCha20.Keystream ksStatic;
        /** Per-run ChaCha20 keystream (derived from eph = HKDF(master, perLaunch, "kbox.run")). */
        private final ChaCha20.Keystream ksEph;
        /**
         * The 32-byte per-run ephemeral key that seeded {@link #ksEph}. Exposed so the
         * optional native interpreter ({@link VmpInterpreterNative}) can re-derive the
         * per-position keystream byte-identically and execute the same resident stream
         * without ever holding a full plaintext window. All zeros under noise mode.
         */
        private final byte[] ephKey;
        /** Per-method opcode twin derived from K: {@code (st1 ^ st2)} -> real opcode. */
        private final int twin;
        /**
         * Per-method inverse opcode permutation derived from K. The stored stream
         * holds {@code perm[real] ^ twin}; dispatch recovers the real VmpOp via
         * {@code invPerm[(st1 ^ st2) ^ raw]}. Identity under noise mode.
         */
        private final int[] invPerm;
        /**
         * Per-method micro-operation permutation derived from K (independent domain
         * from {@link #invPerm}). The data-driven dispatch maps the stored opcode to
         * its handler SLOT via {@code composite[twin ^ raw]} — the real VmpOp is never
         * materialized in a register, so the instruction set is re-laid-out per method
         * per build and static analysis of the dispatch loop cannot recover semantics.
         */
        private final int[] microPerm;
        /**
         * Composite dispatch permutation {@code microPerm[invPerm[t]]}. Slot for the
         * stored byte value {@code (st1 ^ st2) ^ raw} == returned handler slot, all in
         * opaque data (nothing in the code). Built at construction.
         */
        private final int[] composite;
        /**
         * Per-method data-driven handler table keyed by micro-SLOT:
         * {@code handlers[micro[op]] = OP_HANDLER[op]}. The dispatch loop looks up
         * {@code handlers[composite[twin ^ raw]]} and runs it — the real opcode and
         * the interpreter's instruction set are nowhere recoverable statically.
         */
        private final Handler[] handlers;
        /** True when the hardware-bound key unwrap failed (wrong machine / tamper). */
        private final boolean noise;
        /**
         * VortexVM/L2 runtime handler re-permutation: a monotonic per-method sequence
         * that, folded into a fresh per-run {@code R} permutation, re-lays the handler
         * table on every {@literal execute()}. Subsequent executions of the same method
         * (and, via the per-launch {@link #ephKey}, every launch) observe a moving
         * slot{@literal ->}handler mapping, so a static or runtime dump of the handler
         * table is useless — the dispatch value and the table both shift each run.
         */
        private final java.util.concurrent.atomic.AtomicLong runSeq =
                new java.util.concurrent.atomic.AtomicLong(0L);

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

        /** Deterministic 256-entry opcode permutation from K (MUST match VmpMethodInjector.opcodePerm). */
        private static int[] opcodePerm(byte[] K) {
            int[] p = new int[256];
            for (int i = 0; i < 256; i++) p[i] = i;
            long s = 0x243F6A8885A308D3L;   // distinct domain constant from slotPerm
            byte[] kb = (K == null) ? new byte[0] : K;
            for (byte b : kb) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
            for (int i = 255; i > 0; i--) {
                s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27; s *= 0x2545F4914F6CDD1DL;
                int j = (int) (Long.remainderUnsigned(s, i + 1L));
                int t = p[i]; p[i] = p[j]; p[j] = t;
            }
            return p;
        }

        /** Inverse of {@link #opcodePerm} — maps the stored (twin-masked) opcode back to the real VmpOp. */
        private static int[] inversePerm(int[] perm) {
            int[] inv = new int[perm.length];
            for (int i = 0; i < perm.length; i++) inv[perm[i]] = i;
            return inv;
        }

        /** Deterministic 256-entry micro-operation permutation from K (MUST match VmpMethodInjector.microPerm). */
        private static int[] microPerm(byte[] K) {
            int[] p = new int[256];
            for (int i = 0; i < 256; i++) p[i] = i;
            long s = 0xA4093822299F31D0L;   // distinct domain constant from slotPerm/opcodePerm
            byte[] kb = (K == null) ? new byte[0] : K;
            for (byte b : kb) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
            for (int i = 255; i > 0; i--) {
                s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27; s *= 0x2545F4914F6CDD1DL;
                int j = (int) (Long.remainderUnsigned(s, i + 1L));
                int t = p[i]; p[i] = p[j]; p[j] = t;
            }
            return p;
        }

        /**
         * VortexVM/L2 per-run handler permutation {@code R}. Seeded by the per-launch
         * ephemeral key ({@link #ephKey}) AND a fresh per-execution sequence value, so
         * the permutation changes both across launches and across consecutive executions
         * of the same method. {@code R} is applied purely on the dispatch INDIRECTION
         * (slot{@literal ->}handler table re-lay), never to the instruction stream, so it
         * is fully runtime-self-consistent and needs no build-side counterpart.
         */
        int[] runPerm() {
            long s = 0x13198A2E03707344L;          // distinct domain constant for R
            byte[] kb = ephKey;
            for (byte b : kb) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
            long seq = runSeq.incrementAndGet();
            s ^= seq * 0x9E3779B97F4A7C15L;
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27; s *= 0x2545F4914F6CDD1DL;
            int[] p = new int[256];
            for (int i = 0; i < 256; i++) p[i] = i;
            for (int i = 255; i > 0; i--) {
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
            // BrainfuckShield 二次虚拟化：静态字段存的是「磁带程序」（KBFT）而非直存密文。
            // 在密钥 unwrap 之后统一由 BfInterpreter 回放解码回 encVmp（见下方分支）。
            byte[] tape = encCode == null ? new byte[0] : encCode;
            this.maxLocals = maxLocals;
            this.maxStack = maxStack;
            this.argCount = argCount;
            this.retSort = retSort;
            this.exceptions = exceptions;

            byte[] K = null;
            try {
                K = HardwareKeyRing.aesGcmDecrypt(HardwareKeyRing.vmpMaster(), wrappedK);
            } catch (Throwable decErr) {
                K = null;
            }
            if (K == null || K.length == 0) {
                // Wrong machine / tampered wrapped key -> noise method.
                this.noise = true;
                this.twin = 0xB1;
                this.invPerm = new int[256];
                for (int i = 0; i < 256; i++) this.invPerm[i] = i;   // identity under noise
                this.microPerm = new int[256];
                for (int i = 0; i < 256; i++) this.microPerm[i] = i; // identity under noise
                this.composite = new int[256];
                for (int i = 0; i < 256; i++) this.composite[i] = i; // identity under noise
                this.handlers = identityHandlers();                  // identity under noise
                byte[] zero = new byte[32];
                this.ksStatic = new ChaCha20.Keystream(zero);
                this.ksEph = new ChaCha20.Keystream(zero);
                this.ephKey = zero;
                this.cipher = tape;
                this.cipherLen = tape.length;
                this.resident = toOffHeap(this.cipher);
                this.cp = new Object[0];
                this.cpRaw = encCpRaw;
                this.cpRes = encCpRaw;
                this.cpPerm = new int[0];
                this.constructionHash = 0;
            } else {
                this.noise = false;
                this.twin = opcodeTwin(K);
                // BrainfuckShield（二次虚拟化）: 静态字段存的是「磁带程序」（KBFT）而非直存密文。
                // 用 K 逐格回放解码回 VMP 密文流 encVmp。解码失败（trailer 校验不过 =
                // 磁带被静态补丁 / 插桩改动）时回退到原始磁带字节作为噪声流 fail-closed，
                // 不给出任何检测信号（见 BfInterpreter 设计）。
                byte[] decryptedCode = BfInterpreter.decodeIfTape(tape, K);
                this.cipher = decryptedCode == null ? tape : decryptedCode;
                this.cipherLen = this.cipher.length;
                int[] opPerm = opcodePerm(K);
                int[] inv = inversePerm(opPerm);
                this.invPerm = inv;
                // Data-driven L2 dispatch: the interpreter maps the stored opcode byte
                // through composite[twin ^ raw] to its handler SLOT; the real VmpOp is
                // never materialized. Per-method, per-build re-keying makes every build's
                // handler layout different.
                int[] micro = microPerm(K);
                this.microPerm = micro;
                int[] comp = new int[256];
                for (int t = 0; t < 256; t++) comp[t] = micro[inv[t]];
                this.composite = comp;
                // Lay the handler table out in this method's micro-slot order: slot
                // micro[op] holds the handler for the real opcode `op`. Every method &
                // build permutes these 256 pointers differently.
                Handler[] hs = new Handler[256];
                for (int op = 0; op < 256; op++) {
                    Handler h = OP_HANDLER[op];
                    if (h != null) hs[micro[op]] = h;
                }
                this.handlers = hs;
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
                this.ephKey = eph;
                // Transiently recover the plaintext and re-encrypt it under the per-run
                // stream into `resident`. No full plaintext is retained.
                byte[] res = new byte[cipherLen];
                int ch = 0x811c9dc5;
                for (int i = 0; i < cipherLen; i++) {
                    int pl = (cipher[i] & 0xFF) ^ ksStatic.atMasked(i);
                    res[i] = (byte) (pl ^ ksEph.atMasked(i));
                    ch ^= pl; ch *= 0x01000193;
                }
                this.resident = toOffHeap(res);
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
                    int p = (resident.get(i) & 0xFF)
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
                int x = (resident.get(i) & 0xFF)
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
            java.nio.ByteBuffer r = resident;
            if (r != null && r.hasRemaining()) {
                r.put(0, (byte) (r.get(0) ^ 0xFF));   // garbage opcode
            }
        }

        /** Copies a transient build-time array into an OFF-HEAP direct buffer so the
         *  per-run resident wave never lives in the Java heap. The source is a short-lived
         *  construction local and is collectible immediately after return. */
        private static java.nio.ByteBuffer toOffHeap(byte[] src) {
            if (src == null) return null;
            java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocateDirect(src.length);
            bb.put(src);
            bb.rewind();
            return bb;
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
                    ? (resident.get(pos) & 0xFF) ^ ksEph.atMasked(pos)
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
            if (h != constructionHash) _T1.set(true);
        }
    }

    /**
     * A single VMP micro-operation handler. The data-driven dispatch loop runs the
     * handler whose index equals {@code composite[twin ^ raw]} for the current
     * program counter — the real opcode that decided WHICH handler to run is never
     * materialized as a value, so the instruction set and its mapping to semantics
     * are only recoverable from per-method opaque permutation data.
     *
     * @return {@code true} if the method should unwind (a *RETURN / END was executed);
     *         the result is in {@link Ctx#retValue}.
     */
    @FunctionalInterface
    private interface Handler {
        /** Executes one micro-operation. {@code true} unwinds (a *RETURN / END ran);
         *  the result is in {@link Ctx#retValue}. Throwables propagate to execute(). */
        boolean run(Ctx c) throws Throwable;
    }

    /** Mutable execution context shared by every micro-operation handler. */
    private static final class Ctx {
        VmpMethod m;
        Object[] cp;
        Object[] stack;
        Object[] locals;
        int sp;
        int pc;
        Object retValue;
    }

    /**
     * Static semantic table: index by the REAL VmpOp, value is the handler that
     * implements its semantics. Each {@link VmpMethod} folds this through its
     * per-method {@code microPerm} into a differently-ordered {@code handlers}
     * array, so no two methods/builds share a byte-identical dispatch layout.
     */
    private static final Handler[] OP_HANDLER = new Handler[256];
    static {
        OP_HANDLER[0x01] = c -> { c.stack[c.sp++] = null; return false; };                         // ACONST_NULL
        OP_HANDLER[0x02] = c -> { c.stack[c.sp++] = c.m.i4(c.pc); c.pc += 4; return false; };      // ICONST
        OP_HANDLER[0x03] = c -> {
            long v = ((long) c.m.i4(c.pc) << 32) | (c.m.i4(c.pc + 4) & 0xFFFFFFFFL);
            c.stack[c.sp++] = v; c.pc += 8; return false; };                                        // LCONST
        OP_HANDLER[0x04] = c -> { c.stack[c.sp++] = Float.intBitsToFloat(c.m.i4(c.pc)); c.pc += 4; return false; };
        OP_HANDLER[0x05] = c -> {
            long bits = ((long) c.m.i4(c.pc) << 32) | (c.m.i4(c.pc + 4) & 0xFFFFFFFFL);
            c.stack[c.sp++] = Double.longBitsToDouble(bits); c.pc += 8; return false; };
        OP_HANDLER[0x06] = c -> { c.stack[c.sp++] = resolveString(c.m, c.cp, c.m.i4(c.pc)); c.pc += 4; return false; };
        OP_HANDLER[0x07] = c -> { c.stack[c.sp++] = resolveClass(c.m, c.cp, c.m.i4(c.pc)); c.pc += 4; return false; };

        OP_HANDLER[0x10] = c -> { c.stack[c.sp++] = c.locals[c.m.u2(c.pc)]; c.pc += 2; return false; };  // ILOAD
        OP_HANDLER[0x11] = c -> { c.stack[c.sp++] = c.locals[c.m.u2(c.pc)]; c.pc += 2; return false; };  // LLOAD
        OP_HANDLER[0x12] = c -> { c.stack[c.sp++] = c.locals[c.m.u2(c.pc)]; c.pc += 2; return false; };  // FLOAD
        OP_HANDLER[0x13] = c -> { c.stack[c.sp++] = c.locals[c.m.u2(c.pc)]; c.pc += 2; return false; };  // DLOAD
        OP_HANDLER[0x14] = c -> { c.stack[c.sp++] = c.locals[c.m.u2(c.pc)]; c.pc += 2; return false; };  // ALOAD

        OP_HANDLER[0x18] = c -> { c.locals[c.m.u2(c.pc)] = c.stack[--c.sp]; c.pc += 2; return false; };  // ISTORE
        OP_HANDLER[0x19] = c -> { c.locals[c.m.u2(c.pc)] = c.stack[--c.sp]; c.pc += 2; return false; };  // LSTORE
        OP_HANDLER[0x1A] = c -> { c.locals[c.m.u2(c.pc)] = c.stack[--c.sp]; c.pc += 2; return false; };  // FSTORE
        OP_HANDLER[0x1B] = c -> { c.locals[c.m.u2(c.pc)] = c.stack[--c.sp]; c.pc += 2; return false; };  // DSTORE
        OP_HANDLER[0x1C] = c -> { c.locals[c.m.u2(c.pc)] = c.stack[--c.sp]; c.pc += 2; return false; };  // ASTORE

        OP_HANDLER[0x20] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a + b; return false; }; // IADD
        OP_HANDLER[0x21] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a - b; return false; }; // ISUB
        OP_HANDLER[0x22] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a * b; return false; }; // IMUL
        OP_HANDLER[0x23] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a / b; return false; }; // IDIV
        OP_HANDLER[0x24] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a % b; return false; }; // IREM
        OP_HANDLER[0x25] = c -> { int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = -a; return false; }; // INEG
        OP_HANDLER[0x26] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a << b; return false; }; // ISHL
        OP_HANDLER[0x27] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a >> b; return false; }; // ISHR
        OP_HANDLER[0x28] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a >>> b; return false; }; // IUSHR
        OP_HANDLER[0x29] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a & b; return false; }; // IAND
        OP_HANDLER[0x2A] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a | b; return false; }; // IOR
        OP_HANDLER[0x2B] = c -> { int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); c.stack[c.sp++] = a ^ b; return false; }; // IXOR
        OP_HANDLER[0x2C] = c -> {
            int v = c.m.u2(c.pc); int d = c.m.i4(c.pc + 2);
            c.locals[v] = toInt(c.locals[v]) + d; c.pc += 6; return false; };                        // IINC

        OP_HANDLER[0x2D] = c -> { c.stack[c.sp - 1] = (long) toInt(c.stack[c.sp - 1]); return false; }; // I2L
        OP_HANDLER[0x2E] = c -> { c.stack[c.sp - 1] = (float) toInt(c.stack[c.sp - 1]); return false; };// I2F
        OP_HANDLER[0x2F] = c -> { c.stack[c.sp - 1] = (double) toInt(c.stack[c.sp - 1]); return false; };// I2D
        OP_HANDLER[0xA0] = c -> { c.stack[c.sp - 1] = (int) toLong(c.stack[c.sp - 1]); return false; };  // L2I
        OP_HANDLER[0xA1] = c -> { c.stack[c.sp - 1] = (float) toLong(c.stack[c.sp - 1]); return false; };// L2F
        OP_HANDLER[0xA2] = c -> { c.stack[c.sp - 1] = (double) toLong(c.stack[c.sp - 1]); return false; };// L2D
        OP_HANDLER[0xA3] = c -> { c.stack[c.sp - 1] = (int) toFloat(c.stack[c.sp - 1]); return false; }; // F2I
        OP_HANDLER[0xA4] = c -> { c.stack[c.sp - 1] = (long) toFloat(c.stack[c.sp - 1]); return false; }; // F2L
        OP_HANDLER[0xA5] = c -> { c.stack[c.sp - 1] = (double) toFloat(c.stack[c.sp - 1]); return false; };// F2D
        OP_HANDLER[0xA6] = c -> { c.stack[c.sp - 1] = (int) toDouble(c.stack[c.sp - 1]); return false; }; // D2I
        OP_HANDLER[0xA7] = c -> { c.stack[c.sp - 1] = (long) toDouble(c.stack[c.sp - 1]); return false; };// D2L
        OP_HANDLER[0xA8] = c -> { c.stack[c.sp - 1] = (float) toDouble(c.stack[c.sp - 1]); return false; };// D2F
        OP_HANDLER[0xA9] = c -> { c.stack[c.sp - 1] = (byte) toInt(c.stack[c.sp - 1]); return false; }; // I2B
        OP_HANDLER[0xAA] = c -> { c.stack[c.sp - 1] = (char) toInt(c.stack[c.sp - 1]); return false; }; // I2C
        OP_HANDLER[0xAB] = c -> { c.stack[c.sp - 1] = (short) toInt(c.stack[c.sp - 1]); return false; };// I2S

        OP_HANDLER[0xAC] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = (a == b ? 0 : (a < b ? -1 : 1)); return false; }; // LCMP
        OP_HANDLER[0xAD] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a + b; return false; }; // LADD
        OP_HANDLER[0xAE] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a - b; return false; }; // LSUB
        OP_HANDLER[0xAF] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a * b; return false; }; // LMUL
        OP_HANDLER[0xB0] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a / b; return false; }; // LDIV
        OP_HANDLER[0xB1] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a % b; return false; }; // LREM
        OP_HANDLER[0xB2] = c -> { long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = -a; return false; };// LNEG
        OP_HANDLER[0xB3] = c -> { int b = toInt(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a << b; return false; }; // LSHL
        OP_HANDLER[0xB4] = c -> { int b = toInt(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a >> b; return false; }; // LSHR
        OP_HANDLER[0xB5] = c -> { int b = toInt(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a >>> b; return false; }; // LUSHR
        OP_HANDLER[0xB6] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a & b; return false; }; // LAND
        OP_HANDLER[0xB7] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a | b; return false; }; // LOR
        OP_HANDLER[0xB8] = c -> { long b = toLong(c.stack[--c.sp]); long a = toLong(c.stack[--c.sp]); c.stack[c.sp++] = a ^ b; return false; }; // LXOR

        OP_HANDLER[0xB9] = c -> { float b = toFloat(c.stack[--c.sp]); float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = a + b; return false; }; // FADD
        OP_HANDLER[0xBA] = c -> { float b = toFloat(c.stack[--c.sp]); float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = a - b; return false; }; // FSUB
        OP_HANDLER[0xBB] = c -> { float b = toFloat(c.stack[--c.sp]); float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = a * b; return false; }; // FMUL
        OP_HANDLER[0xBC] = c -> { float b = toFloat(c.stack[--c.sp]); float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = a / b; return false; }; // FDIV
        OP_HANDLER[0xBD] = c -> { float b = toFloat(c.stack[--c.sp]); float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = a % b; return false; }; // FREM
        OP_HANDLER[0xBE] = c -> { float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = -a; return false; }; // FNEG
        OP_HANDLER[0xBF] = c -> { double b = toDouble(c.stack[--c.sp]); double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = a + b; return false; }; // DADD
        OP_HANDLER[0xC0] = c -> { double b = toDouble(c.stack[--c.sp]); double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = a - b; return false; }; // DSUB
        OP_HANDLER[0xC1] = c -> { double b = toDouble(c.stack[--c.sp]); double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = a * b; return false; }; // DMUL
        OP_HANDLER[0xC2] = c -> { double b = toDouble(c.stack[--c.sp]); double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = a / b; return false; }; // DDIV
        OP_HANDLER[0xC3] = c -> { double b = toDouble(c.stack[--c.sp]); double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = a % b; return false; }; // DREM
        OP_HANDLER[0xC4] = c -> { double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = -a; return false; }; // DNEG
        OP_HANDLER[0xC5] = c -> { float b = toFloat(c.stack[--c.sp]); float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = (Float.isNaN(a) || Float.isNaN(b) ? -1 : (a > b ? 1 : (a < b ? -1 : 0))); return false; }; // FCMPL
        OP_HANDLER[0xC6] = c -> { float b = toFloat(c.stack[--c.sp]); float a = toFloat(c.stack[--c.sp]); c.stack[c.sp++] = (a > b ? 1 : (a < b ? -1 : (Float.isNaN(a) || Float.isNaN(b) ? 1 : 0))); return false; }; // FCMPG
        OP_HANDLER[0xC7] = c -> { double b = toDouble(c.stack[--c.sp]); double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = (Double.isNaN(a) || Double.isNaN(b) ? -1 : (a > b ? 1 : (a < b ? -1 : 0))); return false; }; // DCMPL
        OP_HANDLER[0xC8] = c -> { double b = toDouble(c.stack[--c.sp]); double a = toDouble(c.stack[--c.sp]); c.stack[c.sp++] = (a > b ? 1 : (a < b ? -1 : (Double.isNaN(a) || Double.isNaN(b) ? 1 : 0))); return false; }; // DCMPG

        OP_HANDLER[0x30] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (toInt(c.stack[--c.sp]) == 0) c.pc = t; return false; }; // IFEQ
        OP_HANDLER[0x31] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (toInt(c.stack[--c.sp]) != 0) c.pc = t; return false; }; // IFNE
        OP_HANDLER[0x32] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (toInt(c.stack[--c.sp]) <  0) c.pc = t; return false; }; // IFLT
        OP_HANDLER[0x33] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (toInt(c.stack[--c.sp]) >= 0) c.pc = t; return false; }; // IFGE
        OP_HANDLER[0x34] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (toInt(c.stack[--c.sp]) >  0) c.pc = t; return false; }; // IFGT
        OP_HANDLER[0x35] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (toInt(c.stack[--c.sp]) <= 0) c.pc = t; return false; }; // IFLE
        OP_HANDLER[0x36] = c -> { int t = c.m.i4(c.pc); c.pc += 4; int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); if (a == b) c.pc = t; return false; };
        OP_HANDLER[0x37] = c -> { int t = c.m.i4(c.pc); c.pc += 4; int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); if (a != b) c.pc = t; return false; };
        OP_HANDLER[0x38] = c -> { int t = c.m.i4(c.pc); c.pc += 4; int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); if (a <  b) c.pc = t; return false; };
        OP_HANDLER[0x39] = c -> { int t = c.m.i4(c.pc); c.pc += 4; int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); if (a >= b) c.pc = t; return false; };
        OP_HANDLER[0x3A] = c -> { int t = c.m.i4(c.pc); c.pc += 4; int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); if (a >  b) c.pc = t; return false; };
        OP_HANDLER[0x3B] = c -> { int t = c.m.i4(c.pc); c.pc += 4; int b = toInt(c.stack[--c.sp]); int a = toInt(c.stack[--c.sp]); if (a <= b) c.pc = t; return false; };
        OP_HANDLER[0x3C] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (c.stack[--c.sp] == null) c.pc = t; return false; }; // IFNULL
        OP_HANDLER[0x3D] = c -> { int t = c.m.i4(c.pc); c.pc += 4; if (c.stack[--c.sp] != null) c.pc = t; return false; }; // IFNONNULL
        OP_HANDLER[0x3E] = c -> { c.pc = c.m.i4(c.pc); return false; };                                    // GOTO
        OP_HANDLER[0x3F] = c -> { int t = c.m.i4(c.pc); c.pc += 4; Object b = c.stack[--c.sp]; Object a = c.stack[--c.sp]; if (a == b) c.pc = t; return false; }; // IF_ACMPEQ
        OP_HANDLER[0xC9] = c -> { int t = c.m.i4(c.pc); c.pc += 4; Object b = c.stack[--c.sp]; Object a = c.stack[--c.sp]; if (a != b) c.pc = t; return false; }; // IF_ACMPNE

        OP_HANDLER[0x45] = c -> { return false; };                                               // NOP (VortexVM/L2 interleave filler)
        OP_HANDLER[0x40] = c -> { --c.sp; return false; };                                              // POP
        OP_HANDLER[0x41] = c -> { c.sp -= 2; return false; };                                           // POP2
        OP_HANDLER[0x42] = c -> { c.stack[c.sp] = c.stack[c.sp - 1]; c.sp++; return false; };           // DUP
        OP_HANDLER[0x43] = c -> { Object v = c.stack[c.sp - 1]; c.stack[c.sp] = v; c.stack[c.sp - 1] = c.stack[c.sp - 2]; c.stack[c.sp - 2] = v; c.sp++; return false; }; // DUP_X1
        OP_HANDLER[0xCA] = c -> { Object v = c.stack[c.sp - 1]; c.stack[c.sp] = v; c.stack[c.sp - 1] = c.stack[c.sp - 2]; c.stack[c.sp - 2] = c.stack[c.sp - 3]; c.stack[c.sp - 3] = v; c.sp++; return false; }; // DUP_X2
        OP_HANDLER[0xCB] = c -> { c.stack[c.sp] = c.stack[c.sp - 1]; c.stack[c.sp + 1] = c.stack[c.sp - 2]; c.sp += 2; return false; }; // DUP2
        OP_HANDLER[0xCC] = c -> { Object v1 = c.stack[c.sp - 1]; Object v2 = c.stack[c.sp - 2]; c.stack[c.sp] = v1; c.stack[c.sp + 1] = v2; c.stack[c.sp - 1] = c.stack[c.sp - 3]; c.stack[c.sp - 2] = v1; c.stack[c.sp - 3] = v2; c.sp += 2; return false; }; // DUP2_X1
        /* DUP2_X2 (JVMS 6.5): ..., v4, v3, v2, v1 -> ..., v2, v1, v4, v3, v2, v1.
         * Single-slot model collapses all four forms to this 4-slot rotation. */
        OP_HANDLER[0xCD] = c -> { Object v1 = c.stack[c.sp - 1]; Object v2 = c.stack[c.sp - 2]; Object v3 = c.stack[c.sp - 3]; Object v4 = c.stack[c.sp - 4]; c.stack[c.sp - 4] = v2; c.stack[c.sp - 3] = v1; c.stack[c.sp - 2] = v4; c.stack[c.sp - 1] = v3; c.stack[c.sp] = v2; c.stack[c.sp + 1] = v1; c.sp += 2; return false; }; // DUP2_X2
        OP_HANDLER[0x44] = c -> { Object t = c.stack[c.sp - 1]; c.stack[c.sp - 1] = c.stack[c.sp - 2]; c.stack[c.sp - 2] = t; return false; }; // SWAP

        OP_HANDLER[0x50] = c -> {
            Field f = resolveField(c.m, c.cp, c.m.i4(c.pc), true);
            initClass(f.getDeclaringClass());
            Object gv = f.get(null);
            c.stack[c.sp++] = gv; c.pc += 4; return false; };                                            // GETSTATIC
        OP_HANDLER[0x51] = c -> {
            Field f = resolveField(c.m, c.cp, c.m.i4(c.pc), true);
            initClass(f.getDeclaringClass());
            f.set(null, c.stack[--c.sp]); c.pc += 4; return false; };                                    // PUTSTATIC
        OP_HANDLER[0x52] = c -> {
            Field f = resolveField(c.m, c.cp, c.m.i4(c.pc), false);
            Object o = c.stack[--c.sp]; c.stack[c.sp++] = f.get(o); c.pc += 4; return false; };          // GETFIELD
        OP_HANDLER[0x53] = c -> {
            Field f = resolveField(c.m, c.cp, c.m.i4(c.pc), false);
            Object v = c.stack[--c.sp]; Object o = c.stack[--c.sp]; f.set(o, v); c.pc += 4; return false; }; // PUTFIELD

        OP_HANDLER[0x60] = c -> {                                                                        // INVOKEVIRTUAL
            int idx = c.m.i4(c.pc); c.pc += 4;
            Method me = resolveMethod(c.m, c.cp, idx, false);
            Object[] args2 = popArgs(me.getParameterTypes(), c.stack, c.sp);
            c.sp -= args2.length;
            Object recv = c.stack[--c.sp];
            Object r = safeInvoke(me, recv, args2);
            if (me.getReturnType() != void.class) c.stack[c.sp++] = r;
            return false;
        };
        OP_HANDLER[0x61] = c -> {                                                                        // INVOKESPECIAL
            int idx = c.m.i4(c.pc); c.pc += 4;
            Object spec = c.m.specAt(idx);
            if (spec instanceof String && ((String) spec).contains("#<init>#")) {
                Constructor<?> ctor = resolveCtor(c.m, c.cp, idx);
                Object[] args2 = popArgs(ctor.getParameterTypes(), c.stack, c.sp);
                c.sp -= args2.length;
                Object marker = c.stack[c.sp - 1];
                boolean duped = c.sp >= 2 && c.stack[c.sp - 2] == marker;
                c.stack[duped ? c.sp - 2 : c.sp - 1] = ctor.newInstance(coerceArgs(ctor.getParameterTypes(), args2));
                c.sp--;
            } else {
                Method me = resolveMethod(c.m, c.cp, idx, false);
                Object[] args2 = popArgs(me.getParameterTypes(), c.stack, c.sp);
                c.sp -= args2.length;
                Object recv = c.stack[--c.sp];
                Object r = safeInvoke(me, recv, args2);
                if (me.getReturnType() != void.class) c.stack[c.sp++] = r;
            }
            return false;
        };
        OP_HANDLER[0x62] = c -> {                                                                        // INVOKESTATIC
            int idx = c.m.i4(c.pc); c.pc += 4;
            Method me = resolveMethod(c.m, c.cp, idx, true);
            Object[] args2 = popArgs(me.getParameterTypes(), c.stack, c.sp);
            c.sp -= args2.length;
            Object r = safeInvoke(me, null, args2);
            if (me.getReturnType() != void.class) c.stack[c.sp++] = r;
            return false;
        };
        OP_HANDLER[0x63] = c -> {                                                                        // INVOKEINTERFACE
            int idx = c.m.i4(c.pc); c.pc += 4;
            Method me = resolveMethod(c.m, c.cp, idx, false);
            Object[] args2 = popArgs(me.getParameterTypes(), c.stack, c.sp);
            c.sp -= args2.length;
            Object recv = c.stack[--c.sp];
            Object r = safeInvoke(me, recv, args2);
            if (me.getReturnType() != void.class) c.stack[c.sp++] = r;
            return false;
        };
        OP_HANDLER[0x70] = c -> { Class<?> cc = resolveClass(c.m, c.cp, c.m.i4(c.pc)); c.pc += 4;
            c.stack[c.sp++] = cc; return false; };                                                       // NEW (push class marker)
        OP_HANDLER[0x71] = c -> { int at = c.m.i4(c.pc); c.pc += 4; Class<?> elem = arrayType(at);
            int len = toInt(c.stack[--c.sp]); c.stack[c.sp++] = Array.newInstance(elem, len); return false; }; // NEWARRAY
        OP_HANDLER[0x72] = c -> { Class<?> cc = resolveClass(c.m, c.cp, c.m.i4(c.pc)); c.pc += 4;
            int len = toInt(c.stack[--c.sp]); c.stack[c.sp++] = Array.newInstance(cc, len); return false; }; // ANEWARRAY
        OP_HANDLER[0x73] = c -> { int arrDepth = c.sp - 1; Object alArr = c.stack[arrDepth];
            c.stack[arrDepth] = Array.getLength(alArr); return false; };                                 // ARRAYLENGTH
        OP_HANDLER[0x74] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.get(a, i); return false; }; // AALOAD
        OP_HANDLER[0x75] = c -> { Object v = c.stack[--c.sp]; int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.set(a, i, v); return false; }; // AASTORE
        OP_HANDLER[0x76] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.getInt(a, i); return false; }; // IALOAD
        OP_HANDLER[0x77] = c -> { int v = toInt(c.stack[--c.sp]); int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.setInt(a, i, v); return false; }; // IASTORE
        OP_HANDLER[0x7A] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.getByte(a, i); return false; }; // BALOAD
        OP_HANDLER[0x7B] = c -> { int v = toInt(c.stack[--c.sp]); int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.setByte(a, i, (byte) v); return false; }; // BASTORE
        OP_HANDLER[0x7C] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.getChar(a, i); return false; }; // CALOAD
        OP_HANDLER[0x7D] = c -> { int v = toInt(c.stack[--c.sp]); int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.setChar(a, i, (char) v); return false; }; // CASTORE
        OP_HANDLER[0x7E] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.getShort(a, i); return false; }; // SALOAD
        OP_HANDLER[0x7F] = c -> { int v = toInt(c.stack[--c.sp]); int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.setShort(a, i, (short) v); return false; }; // SASTORE
        OP_HANDLER[0x83] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.getLong(a, i); return false; }; // LALOAD
        OP_HANDLER[0x84] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.getFloat(a, i); return false; }; // FALOAD
        OP_HANDLER[0x85] = c -> { int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; c.stack[c.sp++] = Array.getDouble(a, i); return false; }; // DALOAD
        OP_HANDLER[0x86] = c -> { long v = toLong(c.stack[--c.sp]); int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.setLong(a, i, v); return false; }; // LASTORE
        OP_HANDLER[0x87] = c -> { float v = toFloat(c.stack[--c.sp]); int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.setFloat(a, i, v); return false; }; // FASTORE
        OP_HANDLER[0x88] = c -> { double v = toDouble(c.stack[--c.sp]); int i = toInt(c.stack[--c.sp]); Object a = c.stack[--c.sp]; Array.setDouble(a, i, v); return false; }; // DASTORE
        OP_HANDLER[0x78] = c -> { Class<?> cc = resolveClass(c.m, c.cp, c.m.i4(c.pc)); c.pc += 4;
            c.stack[c.sp - 1] = cc.cast(c.stack[c.sp - 1]); return false; };                             // CHECKCAST
        OP_HANDLER[0x79] = c -> { Class<?> cc = resolveClass(c.m, c.cp, c.m.i4(c.pc)); c.pc += 4;
            c.stack[c.sp - 1] = cc.isInstance(c.stack[c.sp - 1]); return false; };                      // INSTANCEOF

        OP_HANDLER[0x80] = c -> { Object o = c.stack[c.sp - 1]; enterMonitor(o); return false; };       // MONITORENTER
        OP_HANDLER[0x81] = c -> { Object o = c.stack[--c.sp]; exitMonitor(o); return false; };          // MONITOREXIT

        OP_HANDLER[0x82] = c -> { throw (Throwable) c.stack[--c.sp]; };                                  // ATHROW

        OP_HANDLER[0x90] = c -> { int iv = toInt(c.stack[--c.sp]); c.retValue = boxIntReturn(c.m, iv); return true; }; // IRETURN
        OP_HANDLER[0x91] = c -> { c.retValue = c.stack[--c.sp]; return true; };                          // LRETURN
        OP_HANDLER[0x92] = c -> { c.retValue = c.stack[--c.sp]; return true; };                          // FRETURN
        OP_HANDLER[0x93] = c -> { c.retValue = c.stack[--c.sp]; return true; };                          // DRETURN
        OP_HANDLER[0x94] = c -> { c.retValue = c.stack[--c.sp]; return true; };                          // ARETURN
        OP_HANDLER[0x95] = c -> { return true; };                                                       // RETURN
        OP_HANDLER[0xFF] = c -> { return true; };                                                       // END
    }

    /** Identity handler table (used when the wrapped key unwrap fails → noise). */
    private static Handler[] identityHandlers() {
        Handler[] h = new Handler[256];
        for (int i = 0; i < 256; i++) h[i] = OP_HANDLER[i];
        return h;
    }

    /** Verifies the interpreter class is present and readable. In Brainfuck mode
     *  the check runs inside native code (BfSecureLoader.probeClassFromBF), which
     *  decodes VmpInterpreter transiently in native secure memory and NEVER copies
     *  the plaintext class bytes into a Java byte[] — so a native memory scanner
     *  cannot find this class resting in the heap. Outside BF mode (the class file
     *  is on disk in the jar anyway) the classic resource read is used. */
    private static void verifySelf() {
        if (probeSelfViaNative()) return;
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

    /** BF-mode self-probe via reflection (keeps this class free of a hard link to
     *  BfSecureLoader, which is only present in Brainfuck-protected jars). Returns
     *  true when the probe ran; false when BfSecureLoader is absent (non-BF mode),
     *  in which case the caller falls back to the resource read. */
    private static boolean probeSelfViaNative() {
        try {
            Class<?> loader = Class.forName("com.kbox.runtime.BfSecureLoader",
                    false, VmpInterpreter.class.getClassLoader());
            java.lang.reflect.Method m = loader.getDeclaredMethod(
                    "probeClassFromBF", String.class);
            m.setAccessible(true);
            Object r = m.invoke(null, "com/kbox/runtime/VmpInterpreter.class");
            selfTampered = !Boolean.TRUE.equals(r);
            return true;
        } catch (Throwable t) {
            return false; // not BF mode (or probe unavailable) -> fall back
        }
    }

    static {
        verifySelf();
    }

    public static Object execute(VmpMethod m, Object instance, Object[] args) throws Throwable {
        // Optional VM原生化: run the interpreter body in native code when the packed
        // VMP library is present. On any unavailability the seam returns NOT_NATIVE and
        // we fall through to the identical Java interpreter below (no behavioral change).
        //
        // If the native interpreter THROWS, that is either (a) the semantics-faithful
        // outcome of the interpreted method itself, or (b) a native-interpreter fault
        // (e.g. an operand typed wrongly on the C stack for some randomized build's
        // translation). The two are indistinguishable from the seam, but the Java
        // interpreter below is byte-identical to the native one, so replaying the
        // method on the Java path is always safe: a genuine exception re-surfaces
        // identically (slightly slower), a native fault is silently corrected.
        try {
            Object nat = VmpInterpreterNative.tryExecute(m, instance, args);
            if (nat != VmpInterpreterNative.NOT_NATIVE) return nat;
        } catch (Throwable t) {
            if (t instanceof ThreadDeath || t instanceof VirtualMachineError) throw t;
            String s = String.valueOf(t);
            if (s.length() > 240) s = s.substring(0, 240);
            System.err.println("[KBOX-VMP] native interpreter fault, replaying on Java interpreter: " + s);
        }

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
        // VortexVM/L2 per-run handler re-layout: derive a fresh R permutation for THIS
        // execution and re-lay the handler table through it. R only moves the dispatch
        // INDIRECTION, so the stream semantics are untouched — but the in-memory handler
        // table differs on every execute and every launch, defeating handler-table dumps.
        int[] R = m.runPerm();
        Handler[] runHandlers = new Handler[256];
        {
            Handler[] base = m.handlers;
            for (int s = 0; s < 256; s++) runHandlers[R[s]] = base[s];
        }
        // Execution context shared by the data-driven micro-op handlers. The dispatch
        // loop only ever reads/writes ctx.* — the operand stack, locals and pc live here.
        Ctx ctx = new Ctx();
        ctx.m = m;
        ctx.cp = cp;
        ctx.stack = stack;
        ctx.locals = locals;
        ctx.sp = sp;
        ctx.pc = pc;
        // Exception handling: if an exception is raised and THIS method's exception
        // table has a matching handler, we re-enter the dispatch loop at the handler
        // pc (resumeDispatch). Otherwise it propagates out to the invoking context.
        boolean resumeDispatch = false;
        do {
            resumeDispatch = false;
            try {
            while (true) {
                // Two-state XOR dispatch: st1/st2 both evolve per-pc using the per-run
                // ephemeral layer, so the dispatch value is opaque to static analysis
                // while provably correct (the ephemeral byte cancels: st1 ^ st2 == twin).
                // Data-driven micro-op dispatch: the composite permutation maps the
                // stored ciphertext byte directly onto a handler SLOT. Neither the real
                // VmpOp nor any dispatch value is ever materialized:
                //   slot = composite[twin ^ raw] = micro[inv[perm[real] ^ twin ^ twin]] = micro[real]
                //   handlers[micro[real]] is the semantic handler for that build+method.
                int raw = m.b(ctx.pc);
                int kb = m.ksEph.atMasked(ctx.pc);
                int st1 = m.twin ^ kb;   // twin = st1 ^ st2
                int st2 = kb;
                int slot = m.composite[(st1 ^ st2) ^ raw];
                ppc = ctx.pc;
                ctx.pc++; // advance past opcode; operand readers advance further
                // Periodically surface a watchdog-poisoned method. The poison also
                // corrupts the opcode stream, but this explicit probe makes the
                // tamper response immediate instead of waiting for a corrupted
                // instruction to be decoded. ~1 check per 1024 dispatches is ~free.
                if ((++watchdogCtr & 0x3FFL) == 0 && m.watchTampered()) {
                    // Closed state machine: never surface a pc/state-hinting message.
                    throw new RuntimeException("KBox");
                }
                Handler h = runHandlers[R[slot]];
                if (h == null) {
                    // Slot is unassigned → the stored byte decodes to an unknown opcode.
                    // In a closed state machine this is identity-independent: we neither
                    // reconstruct nor display the real VmpOp.
                    throw new RuntimeException("KBox");
                }
                if (h.run(ctx)) {
                    return ctx.retValue;   // *RETURN / END
                }
                continue;
                // (The old static switch is superseded; semantics now live in OP_HANDLER.)
            }
            } catch (Throwable t) {
            // A method invoked via the interpreter (INVOKE*/safeInvoke reflection) surfaces
            // checked exceptions wrapped in InvocationTargetException. The caller's exception
            // table matches against the REAL thrown type (e.g. IllegalArgumentException), so
            // unwrap the reflection wrapper before matching — this is exactly the semantics a
            // direct, non-reflective call would have produced.
            Throwable unwrapped = t;
            while (unwrapped instanceof InvocationTargetException && unwrapped.getCause() != null) {
                unwrapped = unwrapped.getCause();
            }
            // Consult the exception table.
            boolean excHandled = false;
            if (m.exceptions != null) {
                for (int[] row : m.exceptions) {
                    if (ppc >= row[0] && ppc < row[1]) {
                        Class<?> catchType = row[3] >= 0
                                ? resolveClass(m, cp, row[3]) : Throwable.class;
                        if (catchType.isInstance(unwrapped)) {
                            // Clear operand stack, push the exception, jump to handler
                            // and re-enter the dispatch loop THERE.
                            ctx.sp = 0;
                            ctx.stack[ctx.sp++] = unwrapped;
                            ctx.pc = row[2];
                            excHandled = true;
                            break;
                        }
                    }
                }
            }
            if (excHandled) { resumeDispatch = true; }
            else throw unwrapped;
            } finally {
            // VortexVM/L1 rolling-window: nothing to wipe — no full plaintext
            // buffer was ever created; only the intact ciphertext remains.
            }
        } while (resumeDispatch);
        return null;          // unreachable: while (true) above always returns; satisfies definite-return
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
            // Diagnostic for native-interpreter faults: name the exact method and
            // the declared-vs-actual type of every argument so a "argument type
            // mismatch" can be pinned to one operand without a debugger.
            StringBuilder sb = new StringBuilder("VMP: invoke type mismatch on ")
                    .append(me.getDeclaringClass().getName()).append('#')
                    .append(me.getName()).append(me.toGenericString());
            sb.append(" recv=").append(recv == null ? "null" : recv.getClass().getName());
            Class<?>[] pts = me.getParameterTypes();
            for (int i = 0; i < args.length; i++) {
                sb.append(" arg").append(i).append("[decl=")
                        .append(i < pts.length ? pts[i].getName() : "?")
                        .append(",got=")
                        .append(args[i] == null ? "null" : args[i].getClass().getName())
                        .append(']');
            }
            RuntimeException diag = new RuntimeException(sb.toString(), e);
            diag.setStackTrace(e.getStackTrace());
            throw diag;
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

    /* =====================================================================
     * Native interpreter bridge (VM原生化 / Layer 4).
     *
     * These <code>nl*</code> helpers are invoked from the optional C-native
     * VMP interpreter (kbox_vmp_core.c) via ordinary JNI static calls. They
     * reproduce the EXACT bodies of the object-model micro-op handlers above,
     * so the native path observes byte-identical semantics to the Java
     * interpreter. Each helper:
     *   - reads pc/sp from the shared <code>long[] cpu</code> ({cpu[0],cpu[1]}),
     *   - reads operands from the resident stream via m.i4(pc)/m.u2(pc),
     *   - mutates the shared Object[] operand stack (and locals, where used),
     *   - writes back cpu[0]=pc, cpu[1]=sp, and sets cpu[2]=1 when the method
     *     must unwind (a *RETURN ran).
     * Exceptions propagate to the C side (ExceptionCheck after each
     * CallStatic*Method), which unwinds and lets the Java seam fall back to the
     * byte-identical Java interpreter. Return convention: 0 = continue, and any
     * thrown Throwable aborts the native frame (safe degradation).
     * ===================================================================== */

    /** GETSTATIC: resolve static field, init owning class, push value. */
    static int nlGetStatic(VmpMethod m, Object[] stack, Object[] locals, long[] cpu) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        Field f = resolveField(m, m.cp, m.i4(pc), true);
        initClass(f.getDeclaringClass());
        Object gv = f.get(null);
        stack[sp++] = gv; pc += 4;
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /** PUTSTATIC: resolve static field, init owning class, store popped value. */
    static int nlPutStatic(VmpMethod m, Object[] stack, Object[] locals, long[] cpu) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        Field f = resolveField(m, m.cp, m.i4(pc), true);
        initClass(f.getDeclaringClass());
        f.set(null, coerceFieldValue(f, stack[--sp])); pc += 4;
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /** GETFIELD: pop objectref, push f.get(objref). */
    static int nlGetField(VmpMethod m, Object[] stack, Object[] locals, long[] cpu) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        Field f = resolveField(m, m.cp, m.i4(pc), false);
        Object o = stack[--sp];
        stack[sp++] = f.get(o); pc += 4;
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /** PUTFIELD: pop objectref,value; f.set(objref,value). */
    static int nlPutField(VmpMethod m, Object[] stack, Object[] locals, long[] cpu) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        Field f = resolveField(m, m.cp, m.i4(pc), false);
        Object v = stack[--sp]; Object o = stack[--sp];
        f.set(o, coerceFieldValue(f, v)); pc += 4;
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /**
     * Coerces a boxed stack value to the field's declared type before
     * {@code Field.set}. The JVM executes boolean/byte/char/short field writes
     * with int-typed stack values (0/1, or the raw byte/char/short), which the
     * interpreter boxes as {@code Integer}; passing that Integer straight to
     * {@code Field.set} on a non-int field throws IllegalArgumentException
     * ("Can not set boolean field X to java.lang.Integer"). Boolean fields also
     * arrive as {@code Boolean} when the producer was itself a boolean-typed
     * read, so each primitive type accepts both its own box and the int/Number
     * form. Reference values pass through untouched.
     */
    private static Object coerceFieldValue(Field f, Object v) {
        Class<?> t = f.getType();
        if (v == null) return null;
        if (t == boolean.class) {
            return v instanceof Boolean ? v : Boolean.valueOf(((Number) v).intValue() != 0);
        }
        if (t == byte.class) {
            return v instanceof Byte ? v : (byte) ((Number) v).intValue();
        }
        if (t == char.class) {
            return v instanceof Character ? v : (char) ((Number) v).intValue();
        }
        if (t == short.class) {
            return v instanceof Short ? v : (short) ((Number) v).intValue();
        }
        if (t == int.class) {
            return v instanceof Integer ? v : ((Number) v).intValue();
        }
        if (t == long.class) {
            return v instanceof Long ? v : ((Number) v).longValue();
        }
        if (t == float.class) {
            return v instanceof Float ? v : ((Number) v).floatValue();
        }
        if (t == double.class) {
            return v instanceof Double ? v : ((Number) v).doubleValue();
        }
        return v;
    }

    /** INVOKE* kind: 0=virtual,1=special,2=static,3=interface. */
    static int nlInvoke(VmpMethod m, Object[] stack, Object[] locals, long[] cpu, int kind) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        int idx = m.i4(pc); pc += 4;
        if (kind == 1) {                                     // INVOKESPECIAL (ctor or super)
            Object spec = m.specAt(idx);
            if (spec instanceof String && ((String) spec).contains("#<init>#")) {
                Constructor<?> ctor = resolveCtor(m, m.cp, idx);
                Object[] args2 = popArgs(ctor.getParameterTypes(), stack, sp);
                sp -= args2.length;
                Object marker = stack[sp - 1];
                boolean duped = sp >= 2 && stack[sp - 2] == marker;
                stack[duped ? sp - 2 : sp - 1] =
                        ctor.newInstance(coerceArgs(ctor.getParameterTypes(), args2));
                sp--;
            } else {
                Method me = resolveMethod(m, m.cp, idx, false);
                Object[] args2 = popArgs(me.getParameterTypes(), stack, sp);
                sp -= args2.length;
                Object recv = stack[--sp];
                Object r = safeInvoke(me, recv, args2);
                if (me.getReturnType() != void.class) stack[sp++] = r;
            }
        } else {
            boolean isStatic = (kind == 2);
            Method me = resolveMethod(m, m.cp, idx, isStatic);
            int nArgs = me.getParameterTypes().length;
            int needed = nArgs + (isStatic ? 0 : 1);
            if (sp < needed) {
                throw new RuntimeException("VMP: nlInvoke operand stack underflow (kind="
                        + kind + " pc=" + pc + " sp=" + sp + " needed=" + needed + ")");
            }
            Object[] args2 = popArgs(me.getParameterTypes(), stack, sp);
            sp -= args2.length;
            Object recv = isStatic ? null : stack[--sp];
            Object r = safeInvoke(me, recv, args2);
            if (me.getReturnType() != void.class) stack[sp++] = r;
        }
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /** NEW: push class marker (allocation happens at the matching #<init># invoke). */
    static int nlNew(VmpMethod m, Object[] stack, Object[] locals, long[] cpu) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        stack[sp++] = resolveClass(m, m.cp, m.i4(pc)); pc += 4;
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /** NEWARRAY mode=1 (prim array-code), ANEWARRAY mode=0 (ref type cp idx). */
    static int nlNewArray(VmpMethod m, Object[] stack, Object[] locals, long[] cpu, int mode) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        Class<?> el = (mode == 1) ? arrayType(m.i4(pc)) : resolveClass(m, m.cp, m.i4(pc));
        pc += 4;
        int len = toInt(stack[--sp]);
        stack[sp++] = Array.newInstance(el, len);
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /** Array micro-ops. gs: 0=load,1=store. op: 0=arraylength,1=ref,2=int,3=byte,4=char,5=short. */
    static int nlArrayIndex(VmpMethod m, Object[] stack, long[] cpu, int gs, int op) throws Throwable {
        int sp = (int) cpu[1];
        if (op == 0) {                                       // ARRAYLENGTH
            stack[sp - 1] = Array.getLength(stack[sp - 1]);
            cpu[1] = sp; return 0;
        }
        if (gs == 0) {                                       // xALOAD
            int i = toInt(stack[--sp]); Object a = stack[--sp];
            Object r;
            if (op == 1) r = Array.get(a, i);
            else if (op == 2) r = Array.getInt(a, i);
            else if (op == 3) r = Array.getByte(a, i);
            else if (op == 4) r = Array.getChar(a, i);
            else r = Array.getShort(a, i);
            stack[sp++] = r;
        } else {                                             // xASTORE
            if (op == 1) {
                Object v = stack[--sp]; int i = toInt(stack[--sp]); Object a = stack[--sp];
                Array.set(a, i, v);
            } else if (op == 2) {
                int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp];
                Array.setInt(a, i, v);
            } else if (op == 3) {
                int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp];
                Array.setByte(a, i, (byte) v);
            } else if (op == 4) {
                int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp];
                Array.setChar(a, i, (char) v);
            } else {
                int v = toInt(stack[--sp]); int i = toInt(stack[--sp]); Object a = stack[--sp];
                Array.setShort(a, i, (short) v);
            }
        }
        cpu[1] = sp; return 0;
    }

    /** CHECKCAST: resolve class, cast top of stack (ClassCastException on failure). */
    static int nlCheckCast(VmpMethod m, Object[] stack, Object[] locals, long[] cpu) throws Throwable {
        int pc = (int) cpu[0];
        Class<?> cc = resolveClass(m, m.cp, m.i4(pc)); pc += 4;
        int sp = (int) cpu[1];
        stack[sp - 1] = cc.cast(stack[sp - 1]);
        cpu[0] = pc; return 0;
    }

    /** INSTANCEOF: resolve class, replace top with boolean. */
    static int nlInstanceOf(VmpMethod m, Object[] stack, Object[] locals, long[] cpu) throws Throwable {
        int pc = (int) cpu[0];
        Class<?> cc = resolveClass(m, m.cp, m.i4(pc)); pc += 4;
        int sp = (int) cpu[1];
        stack[sp - 1] = cc.isInstance(stack[sp - 1]);
        cpu[0] = pc; return 0;
    }

    /** LDC string (real op 0x06) / class (real op 0x07). Reconstructs the real
     *  opcode from twin ^ resident (same machinery as the Java dispatch error path). */
    static int nlResolve(VmpMethod m, Object[] stack, long[] cpu) throws Throwable {
        int pc = (int) cpu[0], sp = (int) cpu[1];
        int raw = m.b(pc - 1);
        int op = m.invPerm[(m.twin ^ raw) & 0xFF];
        if (op == 0x07) stack[sp++] = resolveClass(m, m.cp, m.i4(pc));
        else            stack[sp++] = resolveString(m, m.cp, m.i4(pc));
        pc += 4;
        cpu[0] = pc; cpu[1] = sp; return 0;
    }

    /** MONITOR: kind 0=enter,1=exit,2=ATHROW (throws). */
    static int nlMonitor(VmpMethod m, Object[] stack, Object[] locals, long[] cpu, int kind) throws Throwable {
        int sp = (int) cpu[1];
        if (kind == 2) throw (Throwable) stack[--sp];        // ATHROW
        if (kind == 1) exitMonitor(stack[--sp]);              // MONITOREXIT
        else           enterMonitor(stack[sp - 1]);           // MONITORENTER (no pop)
        cpu[1] = sp; return 0;
    }

    /** Native-interpreter exception dispatch. Called by kbox_vmp_core.c when a
     *  helper surfaces a pending JNI exception: consults THIS method's exception
     *  table for a handler covering {@code opcodePc}. On a hit it clears the
     *  operand stack, pushes the (unwrapped) exception and jumps to the handler,
     *  returning 1 so the C loop resumes dispatch there. On a miss it returns 0
     *  so the C loop re-raises the original exception for the invoking context.
     *  Mirrors the Java-fallback interpreter's post-dispatch catch (which unwraps
     *  InvocationTargetException) so native execution honors try/catch exactly. */
    static int nlTryCatch(VmpMethod m, Object[] stack, long[] cpu, Object exc, int opcodePc) {
        Throwable t = unwrapException(exc);
        if (m.exceptions != null) {
            for (int[] row : m.exceptions) {
                if (opcodePc >= row[0] && opcodePc < row[1]) {
                    Class<?> catchType = row[3] >= 0
                            ? resolveClass(m, m.cp, row[3]) : Throwable.class;
                    if (catchType.isInstance(t)) {
                        stack[0] = t;                       // push exception at sp=0
                        cpu[0] = row[2];                    // jump to handler pc
                        cpu[1] = 1;                         // clear operand stack
                        return 1;
                    }
                }
            }
        }
        return 0;
    }

    /** Strips reflection wrappers to reveal the exception the caller's table binds to. */
    private static Throwable unwrapException(Object exc) {
        Throwable t = (exc instanceof Throwable) ? (Throwable) exc : new RuntimeException("KBox");
        while (t instanceof InvocationTargetException && t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }

    /** *RETURN: kind 0=I,1=L,2=F,3=D,4=A,5=void. Leaves the (boxed) result at the
     *  top of the operand stack and sets cpu[2]=1 (unwind) so the C epilogue,
     *  which reads stack[cpu[1]-1], recovers it. IRETURN re-boxes per retSort. */
    static int nlReturn(VmpMethod m, Object[] stack, Object[] locals, long[] cpu, int kind) {
        int sp = (int) cpu[1];
        if (kind == 0) {                                     // IRETURN: re-box sub-int types
            stack[sp - 1] = boxIntReturn(m, toInt(stack[sp - 1]));
        }
        cpu[2] = 1;
        return 0;
    }
}
