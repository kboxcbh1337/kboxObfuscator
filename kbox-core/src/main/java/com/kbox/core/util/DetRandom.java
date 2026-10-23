package com.kbox.core.util;

import java.util.Random;

/**
 * KBX-CF-18 fix: deterministic, build-scoped PRNG for every obfuscation pass.
 *
 * <p>Historically every pass drew randomness from
 * {@code ThreadLocalRandom.current()} — an unseeded, thread-local,
 * wall-clock-derived source. Consequence: the same input jar with the same
 * config produced a DIFFERENT artifact depending on thread count and thread
 * scheduling, which made regression work (differential builds, VerifyError
 * bisection, watermark verification) impossible.
 *
 * <p>Now each pass derives a private {@link Random} stream from
 * {@code SHA-256(buildSeed || passId || classKey)}. Within one build the
 * stream is a pure function of the class being transformed, so:
 * <ul>
 *   <li>the artifact is byte-stable across runs and thread counts,</li>
 *   <li>two builds differ exactly as much as their per-build seeds differ —
 *       the deterministic stream doubles as a build watermark,</li>
 *   <li>a build can be reproduced bit-exactly by replaying the same seed.</li>
 * </ul>
 *
 * <p>The build seed is installed once per pipeline run from the same 32-byte
 * CSPRNG material that feeds the key ring (see ProtectionPipeline stage 0),
 * so determinism never weakens key derivation: the PRNG stream is used only
 * for transform-shape decisions (block ordering, mix constants, predicate
 * selection), never for cryptographic keys.
 */
public final class DetRandom extends Random {

    private static final long serialVersionUID = 1L;

    /** Per-build seed material (32 bytes from the pipeline's CSPRNG). */
    private static volatile byte[] buildSeed;

    private DetRandom(long seed) {
        super(seed);
    }

    /** Installs this build's seed material. Called once per pipeline run. */
    public static void installBuildSeed(byte[] seed) {
        buildSeed = (seed == null || seed.length == 0) ? null : seed.clone();
    }

    /**
     * {@code ThreadLocalRandom}-style bounded draw on a plain {@link Random}
     * (the JDK only ships this on ThreadLocalRandom, but every pass now uses a
     * deterministic stream instead).
     */
    public int nextInt(int origin, int bound) {
        if (bound <= origin) return origin;
        return origin + nextInt(bound - origin);
    }

    /**
     * Derives the deterministic stream for {@code passId} / {@code classKey}.
     * Both components participate so that (a) passes never share a stream and
     * (b) every class in a pass gets an independent, scheduling-independent
     * stream — the property that makes parallel processing deterministic.
     */
    public static DetRandom of(String passId, String classKey) {
        return new DetRandom(derive(passId, classKey));
    }

    /** SHA-256(buildSeed || 0 || passId || 0 || classKey) → first 8 bytes. */
    public static long derive(String passId, String classKey) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] bs = buildSeed;
            if (bs != null) md.update(bs);
            md.update((byte) 0);
            md.update(passId.getBytes("UTF-8"));
            md.update((byte) 0);
            md.update(classKey.getBytes("UTF-8"));
            byte[] d = md.digest();
            long s = 0;
            for (int i = 0; i < 8; i++) s = (s << 8) | (d[i] & 0xFFL);
            return s;
        } catch (Throwable t) {
            // No SHA-256 provider (never happens on a JVM, but stay total):
            // fall back to a 64-bit FNV-1a over the strings. Still deterministic.
            long h = 0x9E3779B97F4A7C15L;
            byte[] bs = buildSeed;
            if (bs != null) for (byte b : bs) { h ^= (b & 0xFFL); h *= 0x100000001B3L; }
            String all = passId + "\u0000" + classKey;
            for (int i = 0; i < all.length(); i++) {
                h ^= (all.charAt(i) & 0xFFL);
                h *= 0x100000001B3L;
            }
            return h;
        }
    }
}
