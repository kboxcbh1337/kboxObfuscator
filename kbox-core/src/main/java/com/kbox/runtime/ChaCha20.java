package com.kbox.runtime;

/**
 * Pure-Java ChaCha20 stream cipher (RFC 8439). Used by the JNIC pipeline to
 * encrypt the compressed native library blob so the jar contains no plaintext
 * native code. The keystream is XORed against the ciphertext; the same routine
 * encrypts and decrypts.
 *
 * <p>This implementation is intentionally allocation-light: a single 64-byte
 * block is generated at a time and streamed out via {@link #process}. A 12-byte
 * nonce is used (the IETF variant); the 32-byte key is provided by the caller.
 *
 * <p>Self-contained, dependency-free, JDK 8 compatible.
 */
public final class ChaCha20 {

    private ChaCha20() {}

    private static final int ROUNDS = 20;

    /** State indices for the ChaCha20 constant "expand 32-byte k". */
    private static final int[] SIGMA = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    /** Processes (encrypts/decrypts) {@code len} bytes of {@code in} into {@code out}. */
    public static void process(byte[] key, byte[] nonce, long counter,
                                byte[] in, int inOff, byte[] out, int outOff, int len) {
        int[] state = new int[16];
        int[] block = new int[16];
        byte[] ks = new byte[64];
        init(state, key, nonce, counter);
        int pos = 0;
        while (len > 0) {
            System.arraycopy(state, 0, block, 0, 16);
            for (int i = 0; i < ROUNDS; i += 2) {
                quarterRound(block, 0, 4, 8, 12);
                quarterRound(block, 1, 5, 9, 13);
                quarterRound(block, 2, 6, 10, 14);
                quarterRound(block, 3, 7, 11, 15);
                quarterRound(block, 0, 5, 10, 15);
                quarterRound(block, 1, 6, 11, 12);
                quarterRound(block, 2, 7, 8, 13);
                quarterRound(block, 3, 4, 9, 14);
            }
            for (int i = 0; i < 16; i++) block[i] += state[i];
            for (int i = 0; i < 16; i++) {
                ks[i * 4]     = (byte) (block[i]);
                ks[i * 4 + 1] = (byte) (block[i] >>> 8);
                ks[i * 4 + 2] = (byte) (block[i] >>> 16);
                ks[i * 4 + 3] = (byte) (block[i] >>> 24);
            }
            int n = Math.min(64, len);
            for (int i = 0; i < n; i++) {
                out[outOff + pos + i] = (byte) (in[inOff + pos + i] ^ ks[i]);
            }
            pos += n;
            len -= n;
            // Increment counter (state[12]).
            if (++state[12] == 0) state[13]++;
        }
    }

    /** One-shot convenience: returns the XOR of {@code data} with the keystream. */
    public static byte[] process(byte[] key, byte[] nonce, long counter, byte[] data) {
        byte[] out = new byte[data.length];
        process(key, nonce, counter, data, 0, out, 0, data.length);
        return out;
    }

    /**
     * Initializes the 16-word state per the IETF ChaCha20 layout:
     * <pre>
     *   state[0..3]   = "expand 32-byte k" constant
     *   state[4..11]  = 256-bit key
     *   state[12]     = 32-bit block counter (low word of {@code counter})
     *   state[13..15] = 96-bit nonce (nonce[0..3], nonce[4..7], nonce[8..11])
     * </pre>
     */
    private static void init(int[] state, byte[] key, byte[] nonce, long counter) {
        state[0]  = SIGMA[0];
        state[1]  = SIGMA[1];
        state[2]  = SIGMA[2];
        state[3]  = SIGMA[3];
        state[4]  = leInt(key, 0);
        state[5]  = leInt(key, 4);
        state[6]  = leInt(key, 8);
        state[7]  = leInt(key, 12);
        state[8]  = leInt(key, 16);
        state[9]  = leInt(key, 20);
        state[10] = leInt(key, 24);
        state[11] = leInt(key, 28);
        state[12] = (int) counter;          // 32-bit block counter
        state[13] = leInt(nonce, 0);
        state[14] = leInt(nonce, 4);
        state[15] = leInt(nonce, 8);
    }

    private static void quarterRound(int[] v, int a, int b, int c, int d) {
        v[a] += v[b]; v[d] = rotl(v[d] ^ v[a], 16);
        v[c] += v[d]; v[b] = rotl(v[b] ^ v[c], 12);
        v[a] += v[b]; v[d] = rotl(v[d] ^ v[a], 8);
        v[c] += v[d]; v[b] = rotl(v[b] ^ v[c], 7);
    }

    private static int rotl(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    private static int leInt(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    // ------------------------------------------------------------------
    //  Seed-derived keystream access (used by the VMP instruction stream,
    //  replacing the old weak 64-bit XOR vmpKeyByte cipher)
    // ------------------------------------------------------------------

    /**
     * Deterministically expands a 64-bit seed into a 256-bit ChaCha20 key and a
     * 96-bit nonce via SHA-256. Build-time encryptor and run-time decryptor must
     * both derive from the SAME seed, so the derived key/nonce are stable across
     * the packager and the interpreter JVM on a given host.
     */
    public static void deriveKeyNonce(long seed, byte[] keyOut32, byte[] nonceOut12) {
        byte[] s = new byte[9];
        for (int i = 0; i < 8; i++) s[i] = (byte) (seed >>> (8 * i));
        byte[] h = sha256(s);
        System.arraycopy(h, 0, keyOut32, 0, 32);
        s[8] = 1; // salt so key and nonce domains are distinct
        byte[] h2 = sha256(s);
        System.arraycopy(h2, 0, nonceOut12, 0, 12);
    }

    /** Derives a 32-byte key + 12-byte nonce from an arbitrary-length secret. */
    public static void deriveKeyNonce(byte[] secret, byte[] keyOut32, byte[] nonceOut12) {
        byte[] h = sha256(secret);
        System.arraycopy(h, 0, keyOut32, 0, 32);
        byte[] sep = new byte[secret.length + 1];
        System.arraycopy(secret, 0, sep, 0, secret.length);
        sep[secret.length] = 0x01;
        byte[] hn = sha256(sep);
        System.arraycopy(hn, 0, nonceOut12, 0, 12);
    }

    /** SHA-256 (JDK), never throws — falls back to a deterministic fill. */
    private static byte[] sha256(byte[] in) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return md.digest(in);
        } catch (Throwable t) {
            byte[] r = new byte[32];
            for (int i = 0; i < r.length; i++) r[i] = (byte) ((in.length + i) * 31 + 7);
            return r;
        }
    }

    /** Returns the 64-byte ChaCha20 keystream block for a given block counter. */
    public static byte[] blockKeystream(byte[] key, byte[] nonce, long counter) {
        byte[] zero = new byte[64];
        byte[] ks = new byte[64];
        process(key, nonce, counter, zero, 0, ks, 0, 64);
        return ks;
    }

    /**
     * Random-access keystream byte at an absolute stream {@code pos}, with a
     * one-block cache so sequential access is amortized O(1) (one block
     * generation per 64 bytes). Keystream block = {@code pos >> 6}; same stream
     * identity (derived from {@code seed}) for both encrypt and decrypt.
     */
    public static final class Keystream {
        private final byte[] key = new byte[32];
        private final byte[] nonce = new byte[12];
        private final byte[] block = new byte[64];
        private long blockCtr = Long.MIN_VALUE;

        public Keystream(long seed) {
            deriveKeyNonce(seed, key, nonce);
        }

        /** Keystream over an arbitrary-length secret (e.g. a 32-byte method key or
         *  per-run ephemeral key). Key = SHA-256(secret); nonce = SHA-256(secret||0x01)
         *  truncated to 12 bytes so the key and nonce domains are distinct. Both the
         *  build-time encryptor and the run-time interpreter derive from the SAME
         *  secret, so streams agree on a given host. */
        public Keystream(byte[] secret) {
            deriveKeyNonce(secret, key, nonce);
        }

        public byte at(int pos) {
            if (pos < 0) return 0;
            long bc = pos >>> 6;
            if (bc != blockCtr) {
                blockCtr = bc;
                System.arraycopy(blockKeystream(key, nonce, bc), 0, block, 0, 64);
            }
            return block[pos & 63];
        }

        /** 32-bit masked view (for the two-state dispatch seed). */
        public int atMasked(int pos) { return at(pos) & 0xFF; }
    }
}
