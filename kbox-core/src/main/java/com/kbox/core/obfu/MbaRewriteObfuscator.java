package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.concurrent.ParallelClassProcessor;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runtime-operand Mixed Boolean-Arithmetic rewrite (config {@code mbaRewrite}).
 *
 * <p>{@link MbaConstantObfuscator} rewrites compile-time <em>constants</em> into
 * random expression trees. This pass is the complementary half that
 * hardened obfuscators ship and KBox previously lacked: it rewrites the
 * <b>actual arithmetic at run time</b> — every {@code IADD/ISUB/IAND/IOR/IXOR}
 * between two live values — into an algebraically equivalent expression built
 * from bitwise primitives.</p>
 *
 * <p>The identities used are exact for all 32-bit two's-complement values
 * (arithmetic is modulo 2^32, so overflow is not a concern):</p>
 * <pre>
 *   a ^ b = (a | b) - (a &amp; b)
 *   a | b = (a ^ b) + (a &amp; b)
 *   a &amp; b = (a | b) - (a ^ b)
 *   a + b = (a ^ b) + ((a &amp; b) &lt;&lt; 1)      (also  a + b = (a | b) + (a &amp; b))
 *   a - b = (a ^ b) - ((~a &amp; b) &lt;&lt; 1)
 * </pre>
 *
 * <p>Because the identities hold for <em>arbitrary</em> operands, each rewrite is
 * recursively re-expanded ({@code depth} levels), so a single source-level
 * {@code +} becomes a randomized tree of bitwise ops whose shape differs per
 * method, per run. A decompiler therefore no longer recovers a faithful
 * arithmetic expression; symbolic simplification must fold the whole tree back.
 * Unlike a shared decoder there is no single signature to pattern-match.</p>
 *
 * <p><b>Correctness / stack discipline.</b> The rewrite consumes exactly the
 * two ints the original opcode consumed and pushes exactly one int, so it is
 * stack-neutral. The live operands are spilled to two freshly allocated locals
 * ({@code mn.maxLocals++}) so the expression can reference them any number of
 * times without stack juggling. {@code COMPUTE_MAXS/COMPUTE_FRAMES} in the
 * packager recompute the (larger) max stack, and the class is marked
 * CF-modified so frames are rebuilt.</p>
 */
public final class MbaRewriteObfuscator {

    private static final String TAG = "mba-rewrite";

    /** Guard against pathological growth on enormous methods. */
    private static final int MAX_METHOD_INSNS = 4000;
    /** Upper bound of rewritten sites per method. */
    private static final int MAX_SITES_PER_METHOD = 600;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final AtomicInteger sites = new AtomicInteger();

    /** Per-thread RNG (each worker owns one instance) — different shape per run. */
    private final ThreadLocal<Random> rngs = ThreadLocal.withInitial(() ->
            new Random(new SecureRandom().nextLong()));

    public MbaRewriteObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        int level = cfg.getMbaRewrite();
        if (level <= 0) {
            return; // opt-in
        }
        sites.set(0);
        ParallelClassProcessor.processAll(graph, cfg, this::obfClass, cfg.getParallelThreads());
        KBoxLog.info(TAG, "MBA-rewrote " + sites.get() + " run-time int arithmetic site(s)"
                + " (mbaRewrite=" + level + ", depth=" + depth(level) + ")");
    }

    private static int depth(int level) {
        // Level 1..5 = progressively deeper re-expansion. Depth is capped at 4:
        // each level doubles the leaf count, so depth 4 already yields ~16
        // sub-expressions per site — beyond that the size cost stops paying off.
        return Math.max(1, Math.min(level, 4));
    }

    private static boolean isArith(int op) {
        return op == Opcodes.IADD || op == Opcodes.ISUB
                || op == Opcodes.IAND || op == Opcodes.IOR || op == Opcodes.IXOR;
    }

    /** True when this exact method is a selected JNIC/VMP target. */
    private boolean isNativeOrVmpTarget(String owner, String name, String desc) {
        String key = ProtectionConfig.memberKey(owner, name, desc);
        return cfg.getNativeMethods().contains(key) || cfg.getVmpMethods().contains(key);
    }

    private void obfClass(ClassNode cn) {
        boolean changed = false;
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if ((mn.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) continue;
            if (mn.instructions.size() > MAX_METHOD_INSNS) continue;
            // JNIC/VMP targets are translated to the native interpreter, which
            // re-executes this method's bytecode. Rewriting their arithmetic both
            // wastes work (the body is replaced anyway) and can trip opcode paths
            // the native interpreter does not model identically. Same rule the
            // repo already applies to control-flow obfuscation for these methods.
            if (isNativeOrVmpTarget(cn.name, mn.name, mn.desc)) continue;
            List<AbstractInsnNode> targets = new ArrayList<>();
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
                if (isArith(ins.getOpcode())) targets.add(ins);
            }
            if (targets.isEmpty()) continue;
            Random rnd = rngs.get();
            int d = depth(cfg.getMbaRewrite());
            int done = 0;
            for (AbstractInsnNode ins : targets) {
                if (done >= MAX_SITES_PER_METHOD) break;
                int op = ins.getOpcode();
                if (!isArith(op)) continue; // earlier rewrites never touch these nodes
                int s1 = mn.maxLocals++;   // holds the top operand (b)
                int s0 = mn.maxLocals++;   // holds the next operand (a)
                InsnList repl = new InsnList();
                repl.add(new VarInsnNode(Opcodes.ISTORE, s1));
                repl.add(new VarInsnNode(Opcodes.ISTORE, s0));
                Node root = expand(op, Node.leaf(Node.A), Node.leaf(Node.B), d, rnd);
                emit(root, repl, s0, s1);
                // HARD BUDGET: a single expansion can add hundreds of nodes, and
                // this pass compounds with mbaConstants (which has already turned
                // every literal into an arithmetic tree). Without a live check a
                // 350-insn method grew to 33k nodes, blew the JVM's 64 KiB
                // per-method code limit (MethodTooLargeException) and made the
                // packager roll the WHOLE class back to unprotected bytes
                // (measured on StressApp.build: lambdas in that class then threw
                // AbstractMethodError because rollback only renames class names).
                if (mn.instructions.size() + repl.size() > MAX_METHOD_INSNS) {
                    mn.maxLocals -= 2;     // release the two unused temporaries
                    continue;              // keep the original arithmetic site
                }
                mn.instructions.insertBefore(ins, repl);
                mn.instructions.remove(ins);
                done++;
            }
            if (done > 0) {
                sites.addAndGet(done);
                changed = true;
                // The rewritten expression needs up to 3 operand-stack slots beyond
                // the original two operands before it collapses back to one value.
                // mn.maxStack is NOT recomputed until the packager serializes the
                // class (COMPUTE_MAXS), but JNIC/VMP read it EARLIER to size their
                // native interpreter stacks — with a stale (too small) value those
                // interpreters silently produce wrong results. Reserve the headroom.
                mn.maxStack = Math.min(65535, mn.maxStack + 4);
            }
        }
        if (changed) graph.markCfModified(cn.name);
    }

    // ------------------------------------------------------------------
    // Expression tree + emission
    // ------------------------------------------------------------------

    /** Tiny expression AST over the two spilled operands. */
    static final class Node {
        static final int A = 0, B = 1, NA = 2, ONE = 3, BIN = 4;
        final int kind;
        final int op;
        final Node l, r;

        private Node(int kind, int op, Node l, Node r) {
            this.kind = kind; this.op = op; this.l = l; this.r = r;
        }

        static Node leaf(int kind) { return new Node(kind, 0, null, null); }
        static Node one() { return leaf(ONE); }
        static Node bin(int op, Node l, Node r) { return new Node(BIN, op, l, r); }
        static Node not(Node n) { return n.kind == A ? new Node(NA, 0, null, null) : n; }
    }

    private static Node expand(int op, Node l, Node r, int depth, Random rnd) {
        if (depth <= 0) return Node.bin(op, l, r);
        switch (op) {
            case Opcodes.IADD: {
                if (rnd.nextBoolean()) {
                    // a + b = (a | b) + (a & b)
                    return Node.bin(Opcodes.IADD,
                            expand(Opcodes.IOR, l, r, depth - 1, rnd),
                            expand(Opcodes.IAND, l, r, depth - 1, rnd));
                }
                // a + b = (a ^ b) + ((a & b) << 1)
                Node x = expand(Opcodes.IXOR, l, r, depth - 1, rnd);
                Node shl = Node.bin(Opcodes.ISHL, Node.bin(Opcodes.IAND, l, r), Node.one());
                return Node.bin(Opcodes.IADD, x, shl);
            }
            case Opcodes.ISUB: {
                // a - b = (a ^ b) - ((~a & b) << 1)
                Node x = expand(Opcodes.IXOR, l, r, depth - 1, rnd);
                Node shl = Node.bin(Opcodes.ISHL, Node.bin(Opcodes.IAND, Node.not(l), r), Node.one());
                return Node.bin(Opcodes.ISUB, x, shl);
            }
            case Opcodes.IXOR:
                // a ^ b = (a | b) - (a & b)
                return Node.bin(Opcodes.ISUB,
                        expand(Opcodes.IOR, l, r, depth - 1, rnd),
                        expand(Opcodes.IAND, l, r, depth - 1, rnd));
            case Opcodes.IOR:
                // a | b = (a ^ b) + (a & b)
                return Node.bin(Opcodes.IADD,
                        expand(Opcodes.IXOR, l, r, depth - 1, rnd),
                        expand(Opcodes.IAND, l, r, depth - 1, rnd));
            case Opcodes.IAND:
                // a & b = (a | b) - (a ^ b)
                return Node.bin(Opcodes.ISUB,
                        expand(Opcodes.IOR, l, r, depth - 1, rnd),
                        expand(Opcodes.IXOR, l, r, depth - 1, rnd));
            default:
                return Node.bin(op, l, r);
        }
    }

    private static void emit(Node n, InsnList out, int s0, int s1) {
        switch (n.kind) {
            case Node.A:
                out.add(new VarInsnNode(Opcodes.ILOAD, s0));
                break;
            case Node.B:
                out.add(new VarInsnNode(Opcodes.ILOAD, s1));
                break;
            case Node.NA:
                out.add(new VarInsnNode(Opcodes.ILOAD, s0));
                out.add(new InsnNode(Opcodes.ICONST_M1));
                out.add(new InsnNode(Opcodes.IXOR)); // ~a
                break;
            case Node.ONE:
                out.add(new InsnNode(Opcodes.ICONST_1));
                break;
            default:
                emit(n.l, out, s0, s1);
                emit(n.r, out, s0, s1);
                out.add(new InsnNode(n.op));
                break;
        }
    }
}
