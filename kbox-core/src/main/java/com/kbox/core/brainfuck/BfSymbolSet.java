package com.kbox.core.brainfuck;

import java.security.SecureRandom;

/**
 * Per-build random permutation of the <b>eight</b> Brainfuck ops used by the
 * KBox-BF loader. The build-time packer ({@link BrainfuckPacker}) encodes the
 * payload with these symbols and the native decoder ({@code kbox_bf_loader.c},
 * compiled per build) is baked with the <em>same</em> mapping — so no two builds
 * ship a byte-identical Brainfuck program / decoder pair (build-to-build
 * polymorphism, analogous to VMP's per-build virtual instruction set).
 *
 * <p>The full standard Brainfuck command set is mapped here, so the emitted
 * program genuinely exercises all 8 commands ({@code + - &gt; &lt; [ ] . ,}) —
 * not the old 3-op ({@code + - .}) subset.</p>
 *
 * <p>Constraints on the drawn symbols:</p>
 * <ul>
 *   <li>distinct — the eight ops must not collide;</li>
 *   <li>non-digit — digits are the RLE run-length prefix in the payload;</li>
 *   <li>printable ASCII {@code '!'..'~'} — never whitespace, never NUL (the RLE
 *       terminator).</li>
 * </ul>
 */
public final class BfSymbolSet {

    /** {@code +} — increment current cell. */
    public final char plus;
    /** {@code -} — decrement current cell. */
    public final char minus;
    /** {@code >} — advance tape pointer right. */
    public final char right;
    /** {@code <} — move tape pointer left. */
    public final char left;
    /** {@code [} — loop if current cell non-zero. */
    public final char open;
    /** {@code ]} — loop back. */
    public final char close;
    /** {@code .} — emit current cell as one byte. */
    public final char dot;
    /** {@code ,} — read one byte into current cell (from the native pad). */
    public final char comma;

    /**
     * Per-build 32-bit seed. Combined with each chunk's absolute RLE offset, it
     * deterministically derives that chunk's own 8-op permutation (same hash on
     * the Java packer and the native decoder). Guarantees the payload's operator
     * table is re-shuffled per chunk AND per build.
     */
    public final int seed;

    /**
     * Per-build permutation of the semantic handler slot (0..7). Injected into the
     * native decoder as KBOX_BF_DISP_0..7 and applied at runtime, so the
     * opcode→handler mapping is opaque / re-dealt on every build (the native-side
     * counterpart of VMP's per-build virtual instruction dispatch).
     */
    public final int[] dispatch;

    public BfSymbolSet(char plus, char minus, char right, char left,
                       char open, char close, char dot, char comma,
                       int seed, int[] dispatch) {
        this.plus = plus;
        this.minus = minus;
        this.right = right;
        this.left = left;
        this.open = open;
        this.close = close;
        this.dot = dot;
        this.comma = comma;
        this.seed = seed;
        this.dispatch = dispatch;
    }

    /** Draws a fresh random 8-op symbol set for this build. */
    public static BfSymbolSet random() {
        // '!'..'~' is 94 printable ASCII chars; removing the 10 digits leaves 84.
        char[] alphabet = new char[84];
        int n = 0;
        for (char c = '!'; c <= '~'; c++) {
            if (c >= '0' && c <= '9') continue;
            alphabet[n++] = c;
        }
        SecureRandom rnd = new SecureRandom();
        boolean[] used = new boolean[n];
        char[] picks = new char[8];
        for (int i = 0; i < 8; i++) {
            int idx;
            do { idx = rnd.nextInt(n); } while (used[idx]);
            used[idx] = true;
            picks[i] = alphabet[idx];
        }
        // Per-build seed for the per-chunk operator permutation.
        int seed = rnd.nextInt();
        // Fresh per-build 0..7 permutation for the native handler dispatch.
        int[] dispatch = new int[8];
        boolean[] taken = new boolean[8];
        for (int i = 0; i < 8; i++) {
            int v;
            do { v = rnd.nextInt(8); } while (taken[v]);
            taken[v] = true;
            dispatch[i] = v;
        }
        return new BfSymbolSet(picks[0], picks[1], picks[2], picks[3],
                picks[4], picks[5], picks[6], picks[7],
                seed, dispatch);
    }
}