package com.kbox.core.sedvx;

import java.util.Random;

/**
 * SED-VX part C: the Equivalent Realization Pool.
 *
 * <p>Instead of one fixed transform per constant, the pool exposes several
 * <em>verified-equivalent</em> realizations of the same semantic value and the
 * planner picks among them per build. Each entry documents its scope and its
 * known recognisable feature so the attack report can say which realization is
 * cheap to normalise — the SED-VX design requires that no candidate be kept
 * merely because it looks complex.
 *
 * <p>Every realization here is exact by construction (see
 * {@link com.kbox.core.obfu.ExpressionSynthesizer}); none of them relies on
 * floating-point, NaN, or evaluation-order assumptions.
 */
public final class RealizationPool {

    /** The shapes the restricted implementation actually provides. */
    public enum Realization {
        /**
         * Constant-only intertwined tree over IADD/ISUB/IMUL/IXOR.
         * Recognisable feature: all leaves are constants → one linear fold
         * recovers the value. Cheap for automated simplifiers, so it is used
         * only where no run-time slot is available.
         */
        CONST_TREE("const-tree", Kind.INT),
        /**
         * Variable-bound MBA: {@code v == ((v^k) + 2*(v&k)) - k} with {@code k}
         * read from a run-time-bound static slot. A fold must first learn
         * {@code k}; the identity is exact in Z/2^32 (int overflow safe).
         */
        VAR_MBA("var-mba", Kind.INT),
        /**
         * Long-constant intertwined tree over LADD/LSUB/LMUL/LXOR. Covers the
         * gap where only {@code int} literals were rewritten before.
         */
        LONG_TREE("long-tree", Kind.LONG);

        public final String id;
        public final Kind kind;

        Realization(String id, Kind kind) {
            this.id = id;
            this.kind = kind;
        }
    }

    /** Value categories a candidate can realize. */
    public enum Kind { INT, LONG }

    private RealizationPool() {}

    /**
     * Picks a realization for one site. Deterministic given {@code rng}, whose
     * stream is already derived from (buildSeed, pass, class#method), so the
     * choice is reproducible per build but differs between builds.
     *
     * @param runtimeSlotAvailable whether the class exposes a run-time int slot
     */
    public static Realization pick(Kind kind, boolean runtimeSlotAvailable, Random rng) {
        if (kind == Kind.LONG) return Realization.LONG_TREE;
        if (runtimeSlotAvailable) {
            return rng.nextBoolean() ? Realization.VAR_MBA : Realization.CONST_TREE;
        }
        return Realization.CONST_TREE;
    }
}
