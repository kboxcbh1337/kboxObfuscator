package com.kbox.runtime;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Runtime derivation of the per-blob ChaCha20 key for native-library containers
 * ({@code native.bin} / {@code jnic.bin} / {@code vmp.bin} / {@code native-crypto.bin}).
 *
 * <p><b>KEY 出域 / hardware-rooted seed:</b> the old design baked a fixed, obscured
 * per-domain {@code DOMAIN_BASE} constant into the class constant pool, so every
 * domain seed was statically recoverable by reverse-engineering a single jar (the
 * evaluation's "密钥全部静态可派生 — 无保密因子" finding). This class removes that
 * static base entirely. Each domain seed is now computed at <em>first use</em> as
 *
 * <pre>
 *   domainSeed = SHA-256( fingerprint() || externalToken() || "kbnl-v3/domain/"+domain )
 * </pre>
 *
 * where {@code fingerprint()} is {@link HardwareKeyRing#fingerprint()} — a hardware
 * factor digest that is <em>deterministic on the current host</em> (subprocess-free:
 * OS/arch/CPUs/MAC/boot-disk). There is no base constant left in the constant pool:
 * an attacker holding the jar still cannot derive the key without first producing the
 * host's hardware factor (or solving the environment token).</p>
 *
 * <p><b>外部 token (opt-in):</b> an operator can additionally inject a secret token at
 * <em>both</em> pack time and run time via system property {@code kbox.keystoken} or
 * env {@code KBOX_KEYS_TOKEN}. It is mixed into every domain seed as a second factor.
 * When absent the derivation reduces to hardware fingerprint + domain tag, so the
 * existing pack→run workflow still works unchanged on the build machine. Because the
 * hardware factor and any token are inputs to the same SHA-256, build-time
 * {@link com.kbox.core.jnic.NativePacker} and the run-time decryptor agree on the
 * identical key on a given host.</p>
 *
 * <p><b>单点分体 (interpreter/dispersion):</b> every blob family still derives a
 * <em>distinct</em> seed (distinct domain tag + per-domain cache), so no single
 * derivation unlocks all four containers. The salt in the blob header is still mixed
 * at {@link #derive} so each artifact additionally carries per-blob randomness.</p>
 *
 * <p>Honest ceiling: because each jar is self-contained and the target host's factors
 * are observable at run time, a determined attacker with that exact hardware present
 * can re-derive the domain seeds. This removes the <em>free</em> static extraction and
 * the "base constant in the constant pool" trunk-key, adds a hardware-binding second
 * factor, and preserves cross-domain dispersion. The remaining static root (hardware
 * factor) is what the "壳层 / PE shell" track further hardens at the native layer.</p>
 */
public final class KbnlKey {

    private KbnlKey() {}

    /**
     * Build a per-build random domain tag used to seed a single blob family.
     * The tag is <b>not</b> a static enumerable constant (the old 0/1/2/3
     * DOMAIN_* values): it is drawn fresh from a CSPRNG on every {@code pack()},
     * written into the KBNL header, and read back by the run-time decryptor so
     * build↔run always agree. Because the tag is random in a 32-bit space and
     * differs on every build, static domain enumeration (probe 0..3, recover all
     * four seeds) no longer transfers across builds. Returns a value whose low
     * 4 bytes are nonzero so a corrupted/zeroed header cannot silently derive.
     */
    public static int newDomainTag() {
        while (true) {
            int t = new java.security.SecureRandom().nextInt();
            if (t == 0) continue;               // reject the degenerate all-zero tag
            return t;
        }
    }

    /**
     * External secret factor, injected at pack AND run time. Read from system
     * property {@code kbox.keystoken} else env {@code KBOX_KEYS_TOKEN}. Absent
     * (null) → derivation reduces to hardware fingerprint + domain tag only, so the
     * existing no-token pack→run workflow keeps working. There is deliberately NO
     * static fallback literal here.
     *
     * <p><b>强门控 (反「随手改」, 下策止血):</b> when {@code -Dkbox.requiretoken=true}
     * or env {@code KBOX_REQUIRE_TOKEN=1} is set, an absent/empty token is a hard
     * failure ({@link IllegalStateException}) instead of silently degrading to the
     * hardware-factor-only derivation. This closes the "external token defaults to
     * empty string → attacker pays zero cost" gap. Honest limit: the operator token
     * must also be derivable from the jar itself to keep build↔run agreement, so it
     * only defeats casual tampering, not a determined re-derivation (the real fix for
     * that is the TPM/hardware track; see docs/SECURITY-HARDENING.md). Off by default
     * so the pre-existing no-token workflow keeps working unchanged.
     */
    private static volatile byte[] _etc;

    private static byte[] externalToken() {
        byte[] c = _etc;
        if (c != null) return c.length == 0 ? null : c;
        boolean required;
        try {
            String rq = System.getProperty("kbox.requiretoken");
            if (rq == null || rq.isEmpty()) rq = System.getenv("KBOX_REQUIRE_TOKEN");
            required = "true".equalsIgnoreCase(rq) || "1".equals(rq);
        } catch (Throwable ignored) { required = false; }
        String v = System.getProperty("kbox.keystoken");
        if (v == null || v.isEmpty()) v = System.getenv("KBOX_KEYS_TOKEN");
        byte[] t = (v == null || v.isEmpty()) ? null : v.getBytes(StandardCharsets.UTF_8);
        if (t == null && required) {
            throw new IllegalStateException(
                    "KBox: missing required key token (set -Dkbox.keystoken or KBOX_KEYS_TOKEN)");
        }
        _etc = t == null ? new byte[0] : t;
        return t;
    }

    /** Per-run session salt, cached for the lifetime of this one JVM. Unlike
     *  {@link #domainSeed(int)} it is <b>deliberately volatile across processes</b>
     *  and must <b>never</b> be folded into a {@code domainSeed} — the blob keys that
     *  {@code derive()} produces are baked at pack time by NativePacker and must be
     *  re-derived identically at run time, so any per-run entropy there would make
     *  native.bin / jnic.bin / vmp.bin / native-crypto.bin permanently undecryptable
     *  (the ONE hard constraint in docs/SECURITY-HARDENING.md). Scope this to the
     *  session/ephemeral layer only (resident re-key, rolling window, noise seed). */
    private static volatile byte[] _pre;

    /**
     * Attach a native-sourced per-run entropy root (32 bytes produced by the
     * Brainfuck native loader {@code kbox_bf_sessionEpoch}). Fed by
     * {@link BfSecureLoader} at startup. If present, it is mixed into the
     * session epoch header so the per-run factor is no longer pure-Java
     * {@code System.nanoTime()} but carries the loader's load-time time base.
     * Still per-run and session-layer only — NEVER folded into a domain seed.
     */
    public static void attachEpochRoot(byte[] root) {
        if (root == null || root.length == 0) return;
        synchronized (KbnlKey.class) {
            _pre = sha256(concat(root, root.length,
                    sessionEpochInternal()));
        }
    }

    public static byte[] sessionEpoch() {
        byte[] e = _pre;
        if (e != null) return e;
        byte[] root = HardwareKeyRing.fingerprint();
        long t = System.nanoTime();
        long st = 0L;
        try { st = java.lang.management.ManagementFactory.getRuntimeMXBean().getStartTime(); } catch (Throwable ignored) {}
        String mix = Long.toHexString(t) + "|" + Long.toHexString(st ^ t)
                + "|" + System.identityHashCode(new Object());
        byte[] mid = mix.getBytes(StandardCharsets.UTF_8);
        byte[] tag = "kbnl-v3/session-epoch".getBytes(StandardCharsets.UTF_8);
        byte[] m = new byte[root.length + mid.length + tag.length];
        int o = 0;
        System.arraycopy(root, 0, m, o, root.length);                          o += root.length;
        System.arraycopy(mid, 0, m, o, mid.length);                             o += mid.length;
        System.arraycopy(tag, 0, m, o, tag.length);
        _pre = sha256(m);
        return _pre;
    }

    private static byte[] sessionEpochInternal() {
        byte[] root = HardwareKeyRing.fingerprint();
        long t = System.nanoTime();
        long st = 0L;
        try { st = java.lang.management.ManagementFactory.getRuntimeMXBean().getStartTime(); } catch (Throwable ignored) {}
        String mix = Long.toHexString(t) + "|" + Long.toHexString(st ^ t)
                + "|" + System.identityHashCode(new Object());
        byte[] mid = mix.getBytes(StandardCharsets.UTF_8);
        byte[] tag = "kbnl-v3/session-epoch".getBytes(StandardCharsets.UTF_8);
        byte[] m = new byte[root.length + mid.length + tag.length];
        int o = 0;
        System.arraycopy(root, 0, m, o, root.length);                          o += root.length;
        System.arraycopy(mid, 0, m, o, mid.length);                             o += mid.length;
        System.arraycopy(tag, 0, m, o, tag.length);
        return sha256(m);
    }

    private static byte[] concat(byte[] a, int alen, byte[] b) {
        byte[] out = new byte[alen + b.length];
        System.arraycopy(a, 0, out, 0, alen);
        System.arraycopy(b, 0, out, alen, b.length);
        return out;
    }

    /**
     * One derived 32-byte seed per domain tag, assembled lazily on first use and
     * cached in a small bounded map. No base constant exists — the seed is
     * hardware-rooted (+ optional external token) + the per-build random tag, so
     * the same tag always yields the same seed on a given host (build↔run
     * agreement), while a fresh random tag on each build de-staticizes the domain.
     * The cache is capped to avoid unbounded growth from an enumeration flood.
     */
    private static final int _MCT = 64;
    private static final java.util.HashMap<Integer, byte[]> _cs = new java.util.HashMap<>();

    private static byte[] domainSeed(int domainTag) {
        synchronized (_cs) {
            byte[] s = _cs.get(domainTag);
            if (s != null) return s;
            byte[] root = HardwareKeyRing.fingerprint();   // deterministic, subprocess-free, per-host
            byte[] tok  = externalToken();                 // opt-in second factor (may be null)
            // The tag is the per-build random value found in the KBNL header; the
            // tag domain avoids clashing with the legacy v3 "domain/<0..3>" layout.
            byte[] tag  = ("kbnl-v4/domain/" + Integer.toHexString(domainTag)).getBytes(StandardCharsets.UTF_8);
            int n = root.length + tag.length + (tok == null ? 0 : tok.length);
            byte[] m = new byte[n];
            int o = 0;
            System.arraycopy(root, 0, m, o, root.length);              o += root.length;
            if (tok != null) { System.arraycopy(tok, 0, m, o, tok.length); o += tok.length; }
            System.arraycopy(tag, 0, m, o, tag.length);
            s = sha256(m);
            if (_cs.size() >= _MCT) _cs.clear();
            _cs.put(domainTag, s);
            return s;
        }
    }

    /**
     * A2 域枚举熔断 (domain-enumeration circuit breaker). A healthy process only
     * ever decrypts the handful of valid blobs (< a dozen derive+decrypt calls), so
     * any large burst of <em>failed</em> decryptions is the signature of brute-force
     * domain-tag enumeration or a tampered/corrupted header. Each failed decrypt
     * (length mismatch / inflate error surfaced from the unpack layer) reports via
     * {@link #noteBadDecrypt()}; after {@link #BAD_DERIVE_LIMIT} failures the process
     * is poisoned and {@link #derive} becomes fail-closed, so an automated enumerator
     * trips the fuse before it can exhaust the tag space. Counter is per-JVM and reset
     * on restart; scoped to the session layer, never a stable key.
     */
    private static final int _BDL = 32;
    private static volatile int _bdc = 0;
    private static volatile boolean _po = false;

    /** Report one failed blob decryption (wrong key / inflate failure). Rapidly
     *  reaching the limit (a burst, i.e. enumeration) poisons the process. */
    public static void noteBadDecrypt() {
        int n = _bdc + 1;
        _bdc = n;
        if (n >= _BDL) _po = true;
    }

    /** True once the process has been poisoned by a decrypt-failure burst. */
    public static boolean poisoned() {
        return _po;
    }

    // ---------------------------------------------------------------------------
    // Native-blob container magic — XOR-masked so the 4 stored header bytes
    // are NOT a static ASCII fingerprint. A grep over the jar/PE cannot
    // fingerprint the native-container format (the mirror of the masking in
    // the BF container). Writer (NativePacker) and both readers (NativeLoader /
    // NativeCrypto) agree on this single definition, so build↔run stay in sync.
    // The field name is intentionally generic — a recognizable constant-pool
    // Utf8 entry would re-leak the format tag into the running JVM's metaspace
    // (memscan picked up "KBNL" via the field name even though the bytes were
    // already masked).
    // ---------------------------------------------------------------------------
    private static final byte[] _M1 = {
            (byte) ('K' ^ 0x3D), (byte) ('B' ^ 0xE9), (byte) ('N' ^ 0x18), (byte) ('L' ^ 0x6F) };

    /** Masked magic byte i (0..3): exactly what the packer writes into the blob. */
    public static byte kbnlMagicByte(int i) {
        return _M1[i];
    }

    /** True iff {@code blob[off..off+3]} equals the masked container magic. */
    public static boolean isKbnl(byte[] blob, int off) {
        return blob.length >= off + 4
                && (blob[off] & 0xFF) == (_M1[0] & 0xFF)
                && (blob[off + 1] & 0xFF) == (_M1[1] & 0xFF)
                && (blob[off + 2] & 0xFF) == (_M1[2] & 0xFF)
                && (blob[off + 3] & 0xFF) == (_M1[3] & 0xFF);
    }

    // ---------------------------------------------------------------------------
    // A8 密钥使用计数 (per-key usage cap → noise beyond cap).
    //
    // Growth protection against unlimited replay / rederivation of a captured
    // domain tag within a single JVM. A healthy process derives each valid blob
    // key essentially once (the seed cache absorbs repeats), so per-tag derive
    // counts stay ≤ 1-2. An attacker who recovered a single tag and keeps
    // calling derive() on it (replaying/decrypting repeatedly, or probing the
    // same tag against many artifacts) is capped: on the (cap+1)-th re-derive of
    // the SAME tag the process returns nondeterministic NOISE instead of the real
    // key, so the reused tag silently stops working instead of yielding a stable,
    // replayable key. Unlike the A2 burst fuse this does not hard-die; it quietly
    // degrades the single over-used domain to noise, preserving the rest of the
    // process. LEGIT use never crosses the cap, so the running program is
    // unaffected.
    // ---------------------------------------------------------------------------
    public static final int K_USE_CAP = 16;
    private static final java.util.concurrent.ConcurrentHashMap<Integer, Integer> _uc =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** Count one usage of {@code derive(domainTag, ...)}. Returns true once the
     *  per-tag cap has been exceeded (caller should feed noise / throw). */
    private static boolean overUse(int domainTag) {
        int n = _uc.merge(domainTag, 1, Integer::sum);
        return n > K_USE_CAP;
    }

    private static final java.lang.ThreadLocal<java.security.SecureRandom> _NR =
            java.lang.ThreadLocal.withInitial(java.security.SecureRandom::new);

    /** True if a given tag has already tripped the A8 usage cap this session. */
    public static boolean tagExhausted(int domainTag) {
        Integer n = _uc.get(domainTag);
        return n != null && n > K_USE_CAP;
    }

    /** Derive the per-blob ChaCha20 key: SHA-256(domainSeed(domainTag) || blobSalt).
     *  {@code domainTag} is the per-build random tag read from the KBNL header
     *  (see {@link #newDomainTag()}), never a static enumerable constant. On a
     *  poisoned process (A2 fuse tripped by enumeration) this fails-closed. On a
     *  single tag reused past the A8 cap it silently degrades to noise (anti-replay). */
    public static byte[] derive(int domainTag, byte[] blobSalt) {
        if (_po) {
            throw new IllegalStateException("KBox");   // enumeration fuse tripped
        }
        if (overUse(domainTag)) {
            // A8: over-used tag → nondeterministic noise, no stable replayable key.
            byte[] noise = new byte[32];
            _NR.get().nextBytes(noise);
            return noise;
        }
        byte[] seed = domainSeed(domainTag);
        byte[] m = new byte[seed.length + (blobSalt == null ? 0 : blobSalt.length)];
        System.arraycopy(seed, 0, m, 0, seed.length);
        if (blobSalt != null) System.arraycopy(blobSalt, 0, m, seed.length, blobSalt.length);
        return sha256(m);
    }

    // ---------------------------------------------------------------------------
    // A3 会话一次性密钥根 (per-session ephemeral root, extended to all blobs).
    //
    // Hard constraint (docs/SECURITY-HARDENING.md): the KBNL blob key — derived by
    // derive(domainTag, blobSalt) from the hardware factor + stable tag — is baked at
    // pack time and MUST re-derive identically at run time, so per-run entropy can
    // never enter THAT key. A3 therefore adds a SEPARATE session layer on top of the
    // stable region, never mixed into a domain seed:
    //   * sessionBoundKey(domainTag, blobSalt) — a per-run wrapper key obtained by
    //     folding sessionEpoch() over the STABLE derived key. It is deterministic
    //     within one JVM/session and differs across sessions, so a blob-material
    //     wrapper captured in session A is undecryptable in session B (anti-replay).
    //     Consumed by the session-layer re-key (VMP resident / rolling window)
    //     which already absorbs a session epoch; it is NOT the KBNL decryption key.
    //   * noteBlobOpened / sessionOpenedBlobs() — a session register of every blob
    //     family successfully opened in this run, bound to sessionEpoch(), so every
    //     blob access carries the once-session root (no stable cross-session trace).
    // ---------------------------------------------------------------------------

    /** Per-run wrapper key for transient/blob-material re-keying. Differs across
     *  sessions (sessionEpoch is volatile per process); stable within a session. */
    public static byte[] sessionBoundKey(int domainTag, byte[] blobSalt) {
        byte[] stable = derive(domainTag, blobSalt);   // fail-closed if poisoned
        byte[] ses = sessionEpoch();
        byte[] m = new byte[ses.length + stable.length];
        System.arraycopy(ses, 0, m, 0, ses.length);
        System.arraycopy(stable, 0, m, ses.length, stable.length);
        return sha256(m);
    }

    /** Session register of blob families opened so far (keyed by domain tag). */
    private static final java.util.Set<Integer> _ob = java.util.Collections.newSetFromMap(
            new java.util.concurrent.ConcurrentHashMap<Integer, Boolean>());

    /** Record a successful blob open (extended session root to all blob accesses). */
    public static void noteBlobOpened(int domainTag) {
        _ob.add(domainTag);
    }

    /** Tags of every blob successfully opened in this session. */
    public static java.util.Set<Integer> sessionOpenedBlobs() {
        return java.util.Collections.unmodifiableSet(new java.util.HashSet<>(_ob));
    }

    /** Number of distinct blobs opened this session (≤ number of families). */
    public static int sessionBlobCount() {
        return _ob.size();
    }

    private static byte[] sha256(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(in);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}