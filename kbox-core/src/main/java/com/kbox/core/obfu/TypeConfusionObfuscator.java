package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * <b>L3 — Type confusion</b> (high-risk bytecode). Three opt-in transforms that
 * are individually bytecode-verifier safe (they never execute untruthfully),
 * yet destroy a decompiler's local-type and stack inference:
 *
 * <ol>
 *   <li><b>Integer exception arg-relay (\u5f02\u5e38\u4f20\u53c2).</b> A chosen
 *       {@code int} constant literal is replaced by an always-thrown carrier
 *       exception that carries the value in its field and is caught immediately
 *       to re-produce it on the stack. The value now visibly transits a thrown
 *       object whose field the decompiler cannot tie back to the original
 *       local slot — genuine {@code locals}-type erasure that is still
 *       semantically identical.</li>
 *   <li><b>Reference param relay (locals \u8de8\u7c7b\u578b\u590d\u7528).</b> A
 *       reference-typed parameter is read at method entry, round-tripped through
 *       an exception carrier whose field is declared {@code Object}, then
 *       {@code CHECKCAST}+written back to its own slot. Runtime value is
 *       unchanged (cast always passes); the decompiler sees the parameter's
 *       type collapse to {@code Object} across an exception boundary.</li>
 *   <li><b>Reflection redirection.</b> {@code public static ()I} self-class
 *       calls are replaced with a {@code Class.forName + getDeclaredMethod +
 *       Method.invoke} equivalent so the call site is no longer a static
 *       linkage the decompiler can inline.</li>
 * </ol>
 *
 * <p>All transforms are opt-in via {@code typeConfusion} (default {@code 0}).
 * Level 1-2 enable the verifier-safe relays; level 3 additionally enables
 * reflection redirection. Transforms that are inapplicable (no match, in a
 * constructor, native, already-VMP'd, library class) are skipped silently and
 * never break the build.
 */
public final class TypeConfusionObfuscator {

    private static final String TAG = "typeconfusion";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    // Randomized per-build helper classes so no stable "carrier" symbol survives.
    private String carrierInt;   // carries (I)V, field $v I
    private String carrierRef;   // carries (Ljava/lang/Object;)V, field $o Ljava/lang/Object;

    private final java.util.concurrent.atomic.AtomicInteger intRelayed =
            new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger refRelayed =
            new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger refletced =
            new java.util.concurrent.atomic.AtomicInteger();

    public TypeConfusionObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        int strength = cfg.getTypeConfusionStrength();
        if (strength <= 0) {
            KBoxLog.info(TAG, "L3 type confusion disabled (typeConfusion=" + strength + ")");
            return;
        }
        carrierInt = "com/kbox/runtime/_" + randomName(12) + "$i";
        carrierRef = "com/kbox/runtime/_" + randomName(12) + "$r";
        intRelayed.set(0);
        refRelayed.set(0);
        refletced.set(0);

        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, this::perClass,
                cfg.getParallelThreads());
        ensureCarrierInt();
        if (strength >= 2) ensureCarrierRef();
        KBoxLog.info(TAG, "L3 type confusion (strength=" + strength
                + "): int-relays=" + intRelayed.get()
                + ", ref-relays=" + refRelayed.get()
                + ", reflection=" + refletced.get());
    }

    private void perClass(ClassNode cn) {
        if (!cfg.shouldProtectClass(cn.name)) return;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            int acc = mn.access;
            if ((acc & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE
                    | Opcodes.ACC_SYNTHETIC)) != 0) continue;
            if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
            String key = ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
            if (cfg.getVmpMethods().contains(key) || cfg.getNativeMethods().contains(key)) continue;

            try {
                confuseMethod(cn, mn);
            } catch (Throwable t) {
                KBoxLog.debug(TAG, "skip " + key + ": " + t.getMessage());
            }
        }
    }

    private void confuseMethod(ClassNode cn, MethodNode mn) {
        int strength = cfg.getTypeConfusionStrength();
        // (1) int exception arg-relay on random constant literals.
        if (strength >= 1) {
            relayIntLiterals(mn, strength >= 2 ? 3 : 1);
        }
        // (2) reference param relay — locals cross-type reuse.
        if (strength >= 2) {
            relayReferenceParams(cn, mn);
        }
        // (3) reflection redirection for public static ()I self calls.
        if (strength >= 3) {
            reflectStaticIntCalls(cn, mn);
        }
        // Mark for CF-modified (writer rebuilds frames/sizes for the new handlers).
        graph.markCfModified(cn.name);
    }

    // ------------------------------------------------------------------
    //  1) int literal -> always-thrown carrier exception, caught to re-produce
    // ------------------------------------------------------------------
    private void relayIntLiterals(MethodNode mn, int budget) {
        List<AbstractInsnNode> candidates = new ArrayList<>();
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            if (ins instanceof LdcInsnNode && ((LdcInsnNode) ins).cst instanceof Integer) {
                candidates.add(ins);
            } else if (ins instanceof IntInsnNode) {
                int op = ins.getOpcode();
                if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) candidates.add(ins);
            }
        }
        if (candidates.isEmpty()) return;

        // The exception arg-relay clears the operand stack when it throws, so it is
        // ONLY safe where the literal is pushed onto an EMPTY stack (depth 0). Any
        // value already on the stack below the literal would be destroyed. Compute
        // each candidate's pre-instruction stack depth; keep only depth==0 ones.
        Map<AbstractInsnNode, Integer> frameAt = frameIndexes(mn);
        Frame<BasicValue>[] frames = analyzeFrames(mn);
        List<AbstractInsnNode> safe = new ArrayList<>();
        if (frames != null) {
            for (AbstractInsnNode c : candidates) {
                Integer idx = frameAt.get(c);
                if (idx != null && frames[idx] != null && frames[idx].getStackSize() == 0) {
                    safe.add(c);
                }
            }
        }
        // Fallback when analysis fails: only relay a literal that is the very first
        // instruction of the method (provably depth 0 and no branch predecessors).
        if (safe.isEmpty() && frames == null) {
            AbstractInsnNode first = mn.instructions.getFirst();
            for (AbstractInsnNode c : candidates) {
                if (c == first) { safe.add(c); break; }
            }
        }
        if (safe.isEmpty()) return;
        int take = Math.min(budget, safe.size());
        for (int k = 0; k < take; k++) {
            AbstractInsnNode src = safe.get(ThreadLocalRandom.current().nextInt(safe.size()));
            int val;
            if (src instanceof LdcInsnNode) val = (Integer) ((LdcInsnNode) src).cst;
            else val = ((IntInsnNode) src).operand;
            if (relayIntAt(mn, src, val)) {
                safe.remove(src);
                intRelayed.incrementAndGet();
                KBoxLog.info(TAG, "  relay-int " + mn.name + mn.desc + " @" + localIndexOf(mn, src) + " val=" + val);
            }
        }
    }

    private static Map<AbstractInsnNode, Integer> frameIndexes(MethodNode mn) {
        Map<AbstractInsnNode, Integer> m = new HashMap<>();
        int i = 0;
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            m.put(ins, i++);
        }
        return m;
    }

    private static int localIndexOf(MethodNode mn, AbstractInsnNode target) {
        int i = 0;
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null && ins != target; ins = ins.getNext()) {
            i++;
        }
        return i;
    }

    @SuppressWarnings("unchecked")
    private static Frame<BasicValue>[] analyzeFrames(MethodNode mn) {
        try {
            Analyzer<BasicValue> a = new Analyzer<>(new BasicInterpreter());
            return a.analyze(mn.name, mn);
        } catch (Throwable t) {
            return null;
        }
    }

    /** Replaces {@code src} (which pushes int {@code val}) with a throw/catch relay. */
    private boolean relayIntAt(MethodNode mn, AbstractInsnNode src, int val) {
        int tv = mn.maxLocals++;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handle = new LabelNode();
        LabelNode after = new LabelNode();
        InsnList relay = new InsnList();
        relay.add(start);
        relay.add(new TypeInsnNode(Opcodes.NEW, carrierInt));
        relay.add(new InsnNode(Opcodes.DUP));
        pushInt(relay, val);
        relay.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, carrierInt,
                "<init>", "(I)V", false));
        relay.add(new InsnNode(Opcodes.ATHROW));
        relay.add(end); // try region ends after ATHROW
        relay.add(handle);
        relay.add(new VarInsnNode(Opcodes.ASTORE, tv));
        relay.add(new VarInsnNode(Opcodes.ALOAD, tv));
        relay.add(new FieldInsnNode(Opcodes.GETFIELD, carrierInt, "$v", "I"));
        relay.add(new JumpInsnNode(Opcodes.GOTO, after));
        relay.add(after);
        mn.instructions.insert(src, relay); // insert relay just before the literal
        mn.instructions.remove(src);        // then drop the literal
        mn.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handle, carrierInt));
        return true;
    }

    // ------------------------------------------------------------------
    //  2) reference parameter -> Object-typed carrier round-trip (type erase)
    // ------------------------------------------------------------------
    private void relayReferenceParams(ClassNode cn, MethodNode mn) {
        List<Integer> refParams = referenceParamSlots(mn);
        if (refParams.isEmpty()) return;
        int take = Math.min(2, refParams.size());
        for (int k = 0; k < take; k++) {
            int idx = refParams.get(ThreadLocalRandom.current().nextInt(refParams.size()));
            if (relayReferenceAt(mn, idx)) {
                refRelayed.incrementAndGet();
                KBoxLog.info(TAG, "  relay-ref " + mn.name + mn.desc + " slot=" + idx);
            }
        }
    }

    private List<Integer> referenceParamSlots(MethodNode mn) {
        List<Integer> out = new ArrayList<>();
        Type[] args = Type.getArgumentTypes(mn.desc);
        int slot;
        if ((mn.access & Opcodes.ACC_STATIC) != 0) slot = 0;
        else slot = 1;
        for (Type a : args) {
            if (a.getSort() == Type.OBJECT || a.getSort() == Type.ARRAY) {
                out.add(slot);
            }
            slot += a.getSize();
        }
        return out;
    }

    /** At method entry, round-trip reference param {@code idx} through the carrier. */
    private boolean relayReferenceAt(MethodNode mn, int idx) {
        String desc = paramDesc(mn, idx);
        if (desc == null) return false;
        int tv = mn.maxLocals++;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handle = new LabelNode();
        LabelNode after = new LabelNode();
        InsnList relay = new InsnList();
        relay.add(start);
        relay.add(new TypeInsnNode(Opcodes.NEW, carrierRef));
        relay.add(new InsnNode(Opcodes.DUP));
        relay.add(new VarInsnNode(Opcodes.ALOAD, idx));
        relay.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, carrierRef,
                "<init>", "(Ljava/lang/Object;)V", false));
        relay.add(new InsnNode(Opcodes.ATHROW));
        relay.add(end);
        relay.add(handle);
        relay.add(new VarInsnNode(Opcodes.ASTORE, tv));
        relay.add(new VarInsnNode(Opcodes.ALOAD, tv));
        relay.add(new FieldInsnNode(Opcodes.GETFIELD, carrierRef, "$o", "Ljava/lang/Object;"));
        // CHECKCAST takes an INTERNAL name (java/lang/String), not a descriptor.
        relay.add(new TypeInsnNode(Opcodes.CHECKCAST, Type.getType(desc).getInternalName()));
        relay.add(new JumpInsnNode(Opcodes.GOTO, after));
        relay.add(after);
        relay.add(new VarInsnNode(Opcodes.ASTORE, idx)); // write the (formerly-void-typed) value back
        mn.instructions.insert(relay); // prepend at method entry
        mn.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handle, carrierRef));
        return true;
    }

    private String paramDesc(MethodNode mn, int idx) {
        boolean stat = (mn.access & Opcodes.ACC_STATIC) != 0;
        Type[] args = Type.getArgumentTypes(mn.desc);
        int slot = stat ? 0 : 1;
        int w = stat ? 0 : 1;
        for (Type a : args) {
            if (slot == idx) {
                if (a.getSort() == Type.OBJECT || a.getSort() == Type.ARRAY) return a.getDescriptor();
                return null;
            }
            slot += a.getSize();
            w += a.getSize();
        }
        return null;
    }

    // ------------------------------------------------------------------
    //  3) reflection redirection for public static ()I self calls
    // ------------------------------------------------------------------
    private void reflectStaticIntCalls(ClassNode cn, MethodNode mn) {
        List<MethodInsnNode> targets = new ArrayList<>();
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
            if (!(ins instanceof MethodInsnNode)) continue;
            MethodInsnNode mi = (MethodInsnNode) ins;
            if (mi.getOpcode() != Opcodes.INVOKESTATIC) continue;
            if (!mi.desc.equals("()I")) continue;
            if (mi.name.equals("<clinit>")) continue;
            if (!graph.getClasses().containsKey(mi.owner)) continue;      // self-app only
            // CRITICAL: identifier renaming runs AFTER this stage and rewrites
            // MethodInsnNode owners, but NOT string literals. The `forName`
            // string would dangle for a class that gets renamed. Reflect only
            // classes whose names are preserved (kept / entry classes).
            if (cfg.shouldTransformClass(mi.owner)) continue;
            targets.add(mi);
        }
        if (targets.isEmpty()) return;
        int take = Math.min(2, targets.size());
        for (int k = 0; k < take; k++) {
            MethodInsnNode mi = targets.get(ThreadLocalRandom.current().nextInt(targets.size()));
            if (relayReflectStatic(mn, mi)) {
                targets.remove(mi);
                refletced.incrementAndGet();
            }
        }
    }

    /** Replace {@code INVOKESTATIC owner name ()I} with a reflection call. */
    private boolean relayReflectStatic(MethodNode mn, MethodInsnNode mi) {
        LabelNode after = new LabelNode();
        InsnList r = new InsnList();
        r.add(new LdcInsnNode(mi.owner.replace('/', '.')));
        r.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class",
                "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false));
        r.add(new LdcInsnNode(mi.name));
        r.add(new InsnNode(Opcodes.ICONST_0));
        r.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
        r.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class",
                "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        r.add(new InsnNode(Opcodes.DUP)); // keep a Method copy for invoke (setAccessible consumes one)
        r.add(new InsnNode(Opcodes.ICONST_1));
        r.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "setAccessible", "(Z)V", false));
        r.add(new InsnNode(Opcodes.ICONST_0));
        r.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        r.add(new InsnNode(Opcodes.ACONST_NULL));
        r.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        r.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
        r.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer",
                "intValue", "()I", false));
        r.add(new JumpInsnNode(Opcodes.GOTO, after));
        r.add(after);
        // Insert the reflection relay in place of the original static call.
        mn.instructions.insert(mi, r);
        mn.instructions.remove(mi);
        return true;
    }

    // ------------------------------------------------------------------
    //  helper runtime classes
    // ------------------------------------------------------------------
    private void ensureCarrierInt() {
        if (graph.getClasses().containsKey(carrierInt)) return;
        ClassNode cn = helperClass(carrierInt);
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "$v", "I", null, null));
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null);
        InsnList c = ctor.instructions;
        c.add(new VarInsnNode(Opcodes.ALOAD, 0));
        c.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Throwable", "<init>", "()V", false));
        c.add(new VarInsnNode(Opcodes.ALOAD, 0));
        c.add(new VarInsnNode(Opcodes.ILOAD, 1));
        c.add(new FieldInsnNode(Opcodes.PUTFIELD, carrierInt, "$v", "I"));
        c.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 2;
        ctor.maxLocals = 2;
        cn.methods.add(ctor);
        graph.getClasses().put(carrierInt, cn);
    }

    private void ensureCarrierRef() {
        if (graph.getClasses().containsKey(carrierRef)) return;
        ClassNode cn = helperClass(carrierRef);
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "$o", "Ljava/lang/Object;", null, null));
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(Ljava/lang/Object;)V", null, null);
        InsnList c = ctor.instructions;
        c.add(new VarInsnNode(Opcodes.ALOAD, 0));
        c.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Throwable", "<init>", "()V", false));
        c.add(new VarInsnNode(Opcodes.ALOAD, 0));
        c.add(new VarInsnNode(Opcodes.ALOAD, 1));
        c.add(new FieldInsnNode(Opcodes.PUTFIELD, carrierRef, "$o", "Ljava/lang/Object;"));
        c.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 2;
        ctor.maxLocals = 2;
        cn.methods.add(ctor);
        graph.getClasses().put(carrierRef, cn);
    }

    /** Base synthetic exception class: the relay throws &amp; catches these, so they
     *  MUST extend {@code java/lang/Throwable}. */
    private ClassNode helperClass(String name) {
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        cn.name = name;
        cn.superName = "java/lang/Throwable";
        graph.markCfModified(name);
        return cn;
    }

    // ------------------------------------------------------------------
    private static void pushInt(InsnList list, int v) {
        if (v >= -1 && v <= 5) {
            list.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            list.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            list.add(new IntInsnNode(Opcodes.SIPUSH, v));
        } else {
            list.add(new LdcInsnNode(v));
        }
    }

    private static String randomName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        char[] b = new char[len];
        for (int i = 0; i < len; i++) b[i] = cs.charAt(ThreadLocalRandom.current().nextInt(cs.length()));
        return new String(b);
    }
}