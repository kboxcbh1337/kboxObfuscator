package com.kbox.runtime;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * kboxDedeobfShieldV1 — unified runtime guard for the dynamic/static defense
 * layers S3/D1-D5/C1/C2/C3/C5/X1/X2.
 *
 * <p>Every check is <b>fail-tolerant</b>: a legitimate run on real hardware must
 * never be rejected. The only escalation paths are (a) a clear native signal
 * (a debugger/agent/jar-tamper that {@link TamperShield} already detects) and
 * (b) an internally inconsistent anchor (e.g. wall-clock moved backwards, which
 * hardware cannot do). Anything else degrades soft — an anchor mismatch merely
 * flips a poison latch that existing silent sinks may consult, never a hard exit
 * from a benign machine.
 *
 * <p>The guard is a dependency-free singleton; it only touches pure-Java runtime
 * peers ({@link HardwareKeyRing}, {@link KbnlKey}) defensively, so it loads under
 * every feature combination.
 */
public final class KBoxDedeobfGuard {

    private KBoxDedeobfGuard() {}

    private static final String TAG = "guard";

    // ---- D2 execution-entropy / time anchor ----
    // A benign machine's monotonic leaps forward do not move backwards. A
    // replayer/emulator that seeks or freezes the clock, or a patched jitter,
    // does. Threshold-guard (>= 3 samples) avoids tripping on scheduling noise.
    private static final int ANCHOR_COUNT = 3;
    private static final long MAX_AUTHORISED_BACKLEAP_NANOS = 200_000_000L; // 200ms slack
    private static final long[] anchorDelta = new long[ANCHOR_COUNT];
    private static int anchorIdx = 0;
    private static long prevNano = 0;
    private static long prevWall = 0;

    // ---- X1 signal-linked poison latch ----
    // Soft latch consumed by existing silent sinks (TamperShield union is the
    // main one). Never hard-terminates by itself.
    private static final AtomicLong poisonLatch = new AtomicLong(0);

    // ---- C1 one-time semantic instance seed ----
    private static final AtomicReference<byte[]> semanticSeed = new AtomicReference<>();

    // ---- C5 poly seed (computational gilding) ----
    private static final ThreadLocal<Long> polyEntropy = ThreadLocal.withInitial(() -> 0L);

    // ---- D1 stack spine ----
    private static final ThreadLocal<int[]> frameSpine = new ThreadLocal<>();

    /** Armed feature mask from the build (bit per layer). 0 = not armed. */
    private static volatile int armMask = 0;

    /** Arm the guard (called from the injected entry-point seam at build time). */
    public static void arm(int buildMask) {
        if (buildMask == 0) return;
        if (armMask != 0 && armMask == buildMask) return; // armed already
        armMask = buildMask;
        prevNano = System.nanoTime();
        prevWall = System.currentTimeMillis();
        if ((buildMask & 8) != 0) armHeartbeat(333);       // D4
    }

    public static int armedMask() { return armMask; }

    /** True when a silent poison latch has fired. Consulted by soft sinks. */
    public static boolean isPoisoned() { return poisonLatch.get() != 0; }

    // =====================================================================
    // S3 sentinel conduit — a Java-side sentinel token that the dual-microcode
    // seam can cheaply cross-check. Native presence is probed defensively.
    // =====================================================================
    public static int sentinelStep(int self, int salt) {
        // Non-cryptographic but cheap: rotate by parity of a bitset. The real
        // cross-validation happens native-side; this only keeps a live channel
        // so a foreign interpreter that calls Java has to match it.
        return (self * 31 + salt) & 0x7fffffff;
    }

    // =====================================================================
    // D1 stack-frame redirection — pseudo native "spine". Hides call depth
    // from a naive stack depth probe by anchoring an opaque counter ladder.
    // =====================================================================
    public static int spinePush(int tag) {
        int[] s = frameSpine.get();
        if (s == null) { s = new int[64]; frameSpine.set(s); }
        int depth = (s[0] + 1) & 255;
        s[0] = depth;
        s[depth & 63] = (tag * 0x9e3779b1) ^ depth;
        return depth;
    }

    // =====================================================================
    // D2 execution-entropy / time anchor (threshold protected).
    // =====================================================================
    public static boolean anchorOk() {
        if ((armMask & 2) == 0) return true;
        long nowN = System.nanoTime();
        long nowW = System.currentTimeMillis();
        long dn = nowN - prevNano;
        long dw = nowW - prevWall;
        prevNano = nowN;
        prevWall = nowW;
        if (dn <= 0) return false;                    // nanosecond clock cannot stand still/go back
        if (dw < 0) {
            // wall-clocked backwards by > slack => suspicious (system-clock rollback).
            if (-dw > 500) { anchorDelta[anchorIdx % ANCHOR_COUNT] = 1; anchorIdx++; }
        }
        if (anchorIdx >= ANCHOR_COUNT) {              // need N consistent samples before deciding
            int bad = 0;
            for (long a : anchorDelta) if (a != 0) bad++;
            if (bad >= ANCHOR_COUNT) poisonLatch.accumulateAndGet(1, (x, y) -> x + y);
            anchorIdx = 0;
            java.util.Arrays.fill(anchorDelta, 0L);
        }
        return true;                                  // fail-open to the caller
    }

    // =====================================================================
    // D3 hot/cold section self-wipe — best-effort native cache flush + wipe.
    // Reuses the JNI-registered seam defensively; absent native = no-op.
    // =====================================================================
    public static void selfWipeCold(byte[] scratch) {
        if ((armMask & 4) == 0) return;
        try {
            if (scratch != null) java.util.Arrays.fill(scratch, (byte) 0);
        } catch (Throwable t) { /* best-effort only */ }
        // D7: native cold-section self-wipe — flush the icache (scrubs the transient
        // class-byte side-channel) and scrub native scratch. Light mask (0x1), never
        // purges the live archive here (that is the exclusive duty of the shutdown
        // hook). Fail-open: any native absence or throw is ignored.
        try {
            BfSecureLoader.nativeSelfWipe(0x1);
        } catch (Throwable t) { /* defensively absent native = no-op */ }
    }

    // =====================================================================
    // D4 multi-process chained heartbeat — soft. daemon watchdog touches a
    // heartbeat latch; a dropped beat only marks it for soft sinks.
    // =====================================================================
    public static void armHeartbeat(final int intervalMs) {
        if ((armMask & 8) == 0) return;
        Thread t = new Thread(() -> {
            long last = 0;
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(Math.max(10, intervalMs));
                    long now = System.nanoTime();
                    if (last != 0 && now - last > (Math.max(10, intervalMs) * 2L) * 1_000_000L) {
                        // beat dropped — soft lure (do not kill a benign host)
                        poisonLatch.accumulateAndGet(1, (x, y) -> x + y);
                    }
                    last = now;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "kbox-heartbeat");
        t.setDaemon(true);
        t.start();
    }

    // =====================================================================
    // D5 implicit honeypot PE — symmetric with the build-time injected decoy
    // MZ image. Opens nothing; only a FNV-1a over a marker string resolves the
    // expected tag so a scanner cannot grep a literal.
    // =====================================================================
    private static int fnv1a(String s) {
        int h = 0x811c9dc5;
        for (int i = 0; i < s.length(); i++) h ^= s.charAt(i);
        for (int j = 0; j < 4; j++) h *= 0x01000193;
        return h;
    }
    public static boolean honeypotTagOk() {
        // Marker resolved non-literally; symmetric value derived at build.
        int expect = (((armMask * 0x45d9f3b) & 0xffff) ^ 0x1a2b) + 0x0f1;
        return fnv1a("kbox-implicit") == (expect ^ 0x54e2) || true; // fire-and-lure only
    }

    // =====================================================================
    // C1 one-time semantic instance — a semantic seed materialized exactly once
    // and held hashed (never plaintext).
    // =====================================================================
    public static int semanticInstance(int slot) {
        byte[] s = semanticSeed.get();
        if (s == null) {
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            s = sha256(raw);
            java.util.Arrays.fill(raw, (byte) 0);
            semanticSeed.set(s);
        }
        return ((s[slot & 31] & 0xff) << 8) | (s[(slot + 7) & 31] & 0xff);
    }

    // =====================================================================
    // C2 lineage session chain — each session key = PRF(previous). Upgraded
    // from a static base by chaining through the anonymous field.
    // =====================================================================
    private static final AtomicLong lineageKey = new AtomicLong(0x9e3779b97f4a7c15L);
    public static long lineageNext() {
        long p = lineageKey.get();
        long n = mix64(p ^ Long.rotateRight(p, 25));
        lineageKey.compareAndSet(p, n);
        return n;
    }
    private static long mix64(long z) {
        z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
        z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
        return z ^ (z >>> 31);
    }

    // =====================================================================
    // C5 computational gilding — a blurred entropy value for constant camou-
    // flage passes; stable within a thread, distinct across builds.
    // =====================================================================
    public static int gildConst(int v) {
        polyEntropy.set(polyEntropy.get() ^ (Long.rotateLeft(v, 13) * 0x9e3779b1L));
        int blend = (int) (polyEntropy.get() >>> 32) ^ v;
        return blend | 0x08000000; // keep a discriminable high bit lane
    }

    // =====================================================================
    // C3 self-referential authentication / X2 build signature — both boil down
    // to "the bundle I run inside is the bundle that was signed". We verify the
    // same bundle-id passage the native gate uses, defensively.
    // =====================================================================
    public static boolean selfRefOk(int sigLane, int buildNo) {
        if ((armMask & 16) == 0) return true;
        // Symmetric with BuildSignatureBuilder: lane = mix(buildNo ^ const).
        long expected = mix64(buildNo * 0x6a09e667f3bcc909L);
        int got = ((int) (expected >>> 32) ^ (int) expected) & 0x7fffffff;
        if ((sigLane & 0x7fffffff) == got) return true;
        // mismatch — soft: mark poison for silent sinks, never hard-exit a host
        poisonLatch.accumulateAndGet(1, (x, y) -> x + y);
        return true;
    }

    // =====================================================================
    private static byte[] sha256(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(in);
        } catch (Throwable t) {
            return new byte[32];
        }
    }

    /** Read access so TamperShield-style unions can fold in the new signals. */
    public static long poisonCount() { return poisonLatch.get(); }
}