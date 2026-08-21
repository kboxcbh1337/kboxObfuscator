package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Hides the call graph by injecting <em>dead-code bait calls</em>: at the
 * start of every protected method we insert an opaque-predicate-guarded call
 * to a synthetic decoy method that reads a never-true constant and drops the
 * result. The true call graph is unchanged (the decoy is provably
 * unreachable), but a static call-graph analyzer / decompiler now sees dozens
 * of spurious edges from every method into the decoy hub, obscuring the
 * real relationships.
 *
 * <p>This is deliberately safe: we never rewrite a real call site, so there
 * is no stack-order risk and no chance of breaking runtime behavior. The
 * decoy hub ({@code com/kbox/runtime/_KboxDecoy}) is injected into the
 * output and never renamed.
 *
 * <p>Opaque predicate: {@code if (constant == someOtherConstant)} — both are
 * pushed as constants, so the JVM verifier inlines the comparison and the
 * branch is constant-condition; the call is dead code the JIT removes.
 * A decompiler, however, will happily trace the edge.
 */
public final class CallGraphHider {

    private static final String TAG = "callhide";
    private static final SecureRandom RNG = new SecureRandom();

    /** Randomized per-build decoy class/prefix so no stable "_KboxDecoy" signature. */
    private String decoyClass;
    private String decoyPrefix;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public CallGraphHider(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    private String randomDecoyName() {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 16; i++) sb.append(cs.charAt(RNG.nextInt(cs.length())));
        return "com/kbox/runtime/_" + sb;
    }

    public void apply() {
        if (!cfg.isHideCallGraph()) return;
        decoyClass = randomDecoyName();
        decoyPrefix = decoyClass;
        int injected = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            if (cn.name.startsWith("com/kbox/runtime/")) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                injected += injectBait(mn);
            }
        }
        injectDecoyClass();
        KBoxLog.info(TAG, "Call graph hidden: " + injected + " decoy calls injected into "
                + graph.getClasses().size() + " classes (decoy=" + decoyClass + ")");
    }

    /**
     * Injects a guarded decoy call at the start of the method.
     */
    private int injectBait(MethodNode mn) {
        InsnList l = new InsnList();
        // Opaque predicate: two distinct constants that the verifier folds.
        int a = RNG.nextInt(1_000_000);
        int b = a + 1; // guaranteed unequal -> branch never taken to decoy
        // a != b always, so IF_ICMPEQ to skip is never taken -> decoy is dead.
        org.objectweb.asm.tree.LabelNode skipLabel = new org.objectweb.asm.tree.LabelNode();
        l.add(new LdcInsnNode(a));
        l.add(new LdcInsnNode(b));
        l.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.IF_ICMPEQ, skipLabel));
        // Dead region: call decoy (returns Object), POP, then jump to skip.
        l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, decoyPrefix, "decoy$"
                + (RNG.nextInt(8)), "()Ljava/lang/Object;", false));
        l.add(new InsnNode(Opcodes.POP));
        l.add(skipLabel);

        // Insert at the very start.
        AbstractInsnNode first = mn.instructions.getFirst();
        mn.instructions.insertBefore(first, l);
        return 1;
    }

    /** Injects the decoy hub class with a handful of distinct decoy methods. */
    private void injectDecoyClass() {
        if (graph.getClasses().containsKey(decoyClass)) return;
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = decoyClass;
        cn.superName = "java/lang/Object";
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);
        for (int i = 0; i < 8; i++) {
            MethodNode dm = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "decoy$" + i, "()Ljava/lang/Object;", null, null);
            dm.instructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Object"));
            dm.instructions.add(new InsnNode(Opcodes.DUP));
            dm.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
            dm.instructions.add(new InsnNode(Opcodes.ARETURN));
            dm.maxStack = 2;
            dm.maxLocals = 0;
            cn.methods.add(dm);
        }
        graph.getClasses().put(decoyClass, cn);
    }
}