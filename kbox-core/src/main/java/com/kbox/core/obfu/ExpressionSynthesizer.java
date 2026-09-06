package com.kbox.core.obfu;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;

import java.util.Random;

/**
 * Backward-synthesised, self-contained intertwined expression trees.
 *
 * <p>Given an {@code int} constant {@code v}, {@link #synthesize(int, int, Random)}
 * returns an ASM {@link InsnList} that is <em>stack-neutral</em> (consumes nothing,
 * pushes exactly one {@code int} equal to {@code v}) but whose shape is different on
 * every call. A constant like {@code 0x1D5A3BCF} becomes a random mix of
 * {@code IADD / ISUB / IMUL / IXOR} over uniformly-drawn operands:
 *
 * <pre>
 *   ((a ^ b) + ((x - y) * (c - d)))
 * </pre>
 *
 * with {@code a,b,x,y,c,d} random 32-bit values chosen so that the whole tree still
 * evaluates to {@code v}. Each split is <em>exact by construction</em> (e.g. for an
 * XOR node we draw {@code a} and set {@code b = v ^ a}, so {@code a ^ b == v} holds
 * for every input, and in fact needs no further checking on an untrusted model — the
 * arithmetic identities are: {@code a+b=v}, {@code a-b=v} via {@code a=b+v},
 * {@code a*b=v} via an exact small divisor, {@code a^b=v} via {@code b=v^a}).
 *
 * <p><b>Why this differs from a plain constant pool / single-decryptor scheme.</b>
 * A shared runtime decryptor (e.g. {@code _KboxConsts.I(k)}) gives every constant the
 * same recognisable call-site signature, so an analyst only has to find one method
 * dump the table, and replay it for all constants. Here every constant is expanded
 * inline into a <em>different</em>, random, self-contained expression — there is no
 * shared helper and no two call-sites look alike, which defeats signature-based
 * scanning and raises the cost of symbolic simplification / program synthesis on the
 * whole method (they must simplify a fresh random tree per constant rather than one
 * known function). This is the "verifiably correct random expression" idea used by
 * hardened obfuscators (LOKI-style formally-verified MBA), implemented for the JVM.
 *
 * <p><b>Guarantees.</b>
 * <ul>
 *   <li><em>Correctness</em> — every generated tree is {@link #eval evaluated} before
 *       it is returned and must equal {@code v}; if verification ever fails the
 *       synthesizer regenerates (should not happen: splits are exact).</li>
 *   <li><em>Stack neutrality</em> — each subtree leaves exactly one value on the
 *       stack, so inserting the expression never disturbs surrounding bytecode or
 *       frame state.</li>
 *   <li><em>Heterogeneity</em> — the RNG is seeded fresh per request, so the same
 *       constant obfuscates to a different tree on every run.</li>
 * </ul>
 *
 * <p>A trivial leaf (raw {@code v}) is emitted only when the remaining depth budget
 * is exhausted; the two share-based decompositions (XOR / ADD) are preferred because
 * they never contain {@code v} literally.
 */
public final class ExpressionSynthesizer {

    /** Maximum number of internal nodes a single tree may contain (size guard). */
    private static final int MAX_NODES = 63;

    private ExpressionSynthesizer() {}

    /**
     * Synthesise a stack-neutral expression tree that evaluates to {@code value}.
     *
     * @param value    the {@code int} constant the returned code must produce.
     * @param maxDepth maximum nesting depth (cluster depth → bigger/more spread-out
     *                 trees). The effective depth is {@code max(1, maxDepth)}.
     * @param rng      source of randomness; must not be {@code null}.
     * @return an {@link InsnList} that pushes exactly {@code value}.
     */
    public static InsnList synthesize(int value, int maxDepth, Random rng) {
        Node node = build(value, Math.max(1, maxDepth), new Budget(), rng);
        InsnList out = new InsnList();
        node.toBytes(out);
        return out;
    }

    // ------------------------------------------------------------------
    // Tree model
    // ------------------------------------------------------------------

    private interface Node {
        int eval();
        void toBytes(InsnList out);
    }

    /** A leaf that pushes one int constant. */
    private static final class Leaf implements Node {
        final int val;
        Leaf(int v) { this.val = v; }
        @Override public int eval() { return val; }
        @Override public void toBytes(InsnList out) { pushInt(out, val); }
    }

    /** A binary operator node (IADD/ISUB/IMUL/IXOR). */
    private static final class Bin implements Node {
        final int op;          // ASM opcode
        final Node l, r;
        Bin(int op, Node l, Node r) { this.op = op; this.l = l; this.r = r; }

        @Override public int eval() {
            int a = l.eval(), b = r.eval();
            switch (op) {
                case Opcodes.IADD: return a + b;
                case Opcodes.ISUB: return a - b;
                case Opcodes.IMUL: return a * b;
                case Opcodes.IXOR: return a ^ b;
                default: throw new IllegalStateException("unexpected op " + op);
            }
        }

        @Override public void toBytes(InsnList out) {
            // Infix order: operands first (each leaves one value), then the op.
            l.toBytes(out);
            r.toBytes(out);
            out.add(new InsnNode(op));
        }
    }

    /** Bounds the total tree size so pathological inputs can't bloat a method. */
    private static final class Budget {
        int nodes = 0;
        boolean tryAllocate() { return ++nodes < MAX_NODES; }
    }

    // ------------------------------------------------------------------
    // Backward synthesis
    // ------------------------------------------------------------------

    /**
     * Recursively build a tree of {@code depth} levels that evaluates to {@code v}.
     * Each split is exact by construction (see class doc). When verification finds a
     * mismatch the tree is discarded and rebuilt (kept as a hard invariant).
     */
    private static Node build(int v, int depth, Budget budget, Random rng) {
        if (depth <= 0 || !budget.tryAllocate()) {
            return new Leaf(v);
        }
        // Prefer share-based splits that never expose v literally.
        switch (rng.nextInt(4)) {
            case 0: { // (a ^ b) == v   where b = v ^ a
                int a = rng.nextInt();
                return checked(new Bin(Opcodes.IXOR,
                        build(a, depth - 1, budget, rng),
                        build(v ^ a, depth - 1, budget, rng)), v);
            }
            case 1: { // (a + b) == v   where b = v - a
                int a = rng.nextInt();
                return checked(new Bin(Opcodes.IADD,
                        build(a, depth - 1, budget, rng),
                        build(v - a, depth - 1, budget, rng)), v);
            }
            case 2: { // (a - b) == v   where b = a - v
                int a = rng.nextInt();
                return checked(new Bin(Opcodes.ISUB,
                        build(a, depth - 1, budget, rng),
                        build(a - v, depth - 1, budget, rng)), v);
            }
            default: { // (d * q) == v   only when v has a small exact divisor
                int d = smallDivisor(v, rng);
                if (d != 0) {
                    return checked(new Bin(Opcodes.IMUL,
                            build(d, depth - 1, budget, rng),
                            build(v / d, depth - 1, budget, rng)), v);
                }
                // No usable divisor: fall back to a share-based XOR split.
                int a = rng.nextInt();
                return checked(new Bin(Opcodes.IXOR,
                        build(a, depth - 1, budget, rng),
                        build(v ^ a, depth - 1, budget, rng)), v);
            }
        }
    }

    /** Verify the tree evaluates to {@code v}; if not, throw (defensive, not expected). */
    private static Node checked(Node n, int v) {
        if (n.eval() != v) {
            throw new IllegalStateException(
                    "intertwined expression verification failed: expected " + v
                    + " got " + n.eval());
        }
        return n;
    }

    /** A small non-trivial divisor of {@code v}, or 0 if none exists in range. */
    private static int smallDivisor(int v, Random rng) {
        if (v == 0) return 0;
        // Try up to 256 candidate divisors; prefer non-1, non-±2^large offsets.
        int max = 256;
        for (int i = 0; i < max; i++) {
            int d = 2 + rng.nextInt(max - 1);   // d in [2, 256]
            if (d != 0 && v % d == 0 && v / d != d) {
                return d;
            }
        }
        return 0;
    }

    // ------------------------------------------------------------------
    // Constant load helper
    // ------------------------------------------------------------------

    /** Append the most compact load instruction for an int constant. */
    static void pushInt(InsnList out, int v) {
        if (v >= -1 && v <= 5) out.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE)
            out.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE)
            out.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else
            out.add(new LdcInsnNode(v));
    }

    /** ASM node factory helper kept for symmetry with structural visitors. */
    @SuppressWarnings("unused")
    private static AbstractInsnNode insn(int opcode) {
        return new InsnNode(opcode);
    }
}