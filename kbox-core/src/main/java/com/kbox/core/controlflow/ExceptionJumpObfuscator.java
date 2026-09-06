package com.kbox.core.controlflow;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.List;

/**
 * Exception-jump obfuscation. Rewrites selected {@code IRETURN} instructions
 * so the value is delivered to the caller via a thrown {@link IntCarrier}
 * exception that the caller catches. This degrades decompiler readability
 * (JD-GUI, CFR render the method as a verbose try/catch instead of a simple
 * return) while preserving JVM semantics exactly.
 *
 * <p>To keep performance acceptable and verification safe, only int-returning
 * methods with a single {@code IRETURN} are eligible. The transformation
 * introduces a synthetic carrier exception class (injected into the graph).
 *
 * <p>This is opt-in (off by default) because it has a runtime cost on every
 * transformed return (exception throw + catch is ~100x slower than a normal
 * return). Use it only for non-hot methods.
 */
public final class ExceptionJumpObfuscator {

    private static final String TAG = "ex-jump";
    private static final String CARRIER = "com/kbox/runtime/_KboxIntCarrier";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public ExceptionJumpObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isExceptionJumpObf()) return;
        ClassNode carrier = ensureCarrier();
        if (carrier == null) return;
        int transformed = 0;
        int skippedLibrary = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.name.equals(CARRIER)) continue;
            // Single canonical decision: library classes are never transformed.
            // Kept classes are still body-protected (names preserved separately).
            if (!cfg.shouldProtectClass(cn.name)) {
                skippedLibrary++;
                continue;
            }
            try {
                transformed += transformClass(cn);
            } catch (Throwable t) {
                if (cfg.isNeverFail()) {
                    KBoxLog.warn(TAG, "Exception-jump failed for " + cn.name + ": " + t.getMessage());
                } else {
                    throw new com.kbox.core.KBoxException(
                            "Exception-jump obfuscation failed for " + cn.name, t);
                }
            }
        }
        KBoxLog.info(TAG, "Transformed " + transformed + " int-returns to exception-jump"
                + (skippedLibrary > 0 ? " (" + skippedLibrary + " library classes skipped)" : ""));
    }

    @SuppressWarnings("unchecked")
    private int transformClass(ClassNode cn) {
        int count = 0;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if (!"()I".equals(mn.desc)) continue;          // only simple int getters
            if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) continue;
            if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
            if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) continue;
            // Find the single IRETURN.
            int iretCount = 0;
            org.objectweb.asm.tree.AbstractInsnNode iret = null;
            for (org.objectweb.asm.tree.AbstractInsnNode n = mn.instructions.getFirst();
                 n != null; n = n.getNext()) {
                if (n.getOpcode() == Opcodes.IRETURN) { iretCount++; iret = n; }
            }
            if (iretCount != 1 || iret == null) continue;
            if (mn.instructions.getFirst() == iret) continue; // empty method
            try {
                rewriteReturn(cn, mn, iret);
                count++;
            } catch (Throwable t) {
                KBoxLog.debug(TAG, "Skip " + cn.name + "." + mn.name + ": " + t.getMessage());
            }
        }
        return count;
    }

    /**
     * Replace IRETURN with: {@code new Carrier(value); athrow}, then append a
     * handler that catches the carrier and returns its value. The try/catch
     * covers the whole method body so the verifier sees a valid control flow.
     * Semantics are preserved: the method still returns the same int, but
     * decompilers render a verbose try/catch around the whole body.
     *
     * <p><b>Validation before mutation:</b> the method must start with a
     * {@link LabelNode} so the try/catch range can be anchored. Methods whose
     * first instruction is not a label (e.g. VMP-virtualized dispatch bodies,
     * synthesized stubs) are rejected BEFORE any instruction is touched — an
     * earlier version inserted the carrier-throw patch first and only then
     * cast {@code getFirst()} to a label, so a cast failure left the method
     * half-rewritten (carrier ATHROW injected, handler + try/catch missing)
     * and the carrier leaked as a raw runtime exception.
     */
    private void rewriteReturn(ClassNode cn, MethodNode mn,
                               org.objectweb.asm.tree.AbstractInsnNode iret) {
        org.objectweb.asm.tree.AbstractInsnNode first = mn.instructions.getFirst();
        if (!(first instanceof LabelNode)) {
            throw new IllegalStateException(
                    "method does not start with a label; skipping exception-jump");
        }
        LabelNode handler = new LabelNode();
        // Stack before IRETURN: [int_value]. Build: new Carrier(value); athrow.
        // NEW Carrier       → [int_value, uninit]
        // DUP_X1            → [uninit, int_value, uninit]
        // SWAP              → [uninit, uninit, int_value]  ← MANDATORY
        // INVOKESPECIAL <init>(I)V → [uninit] (consumes int+top-uninit;
        //                              bottom-uninit is now also initialized)
        // ATHROW            → []  (throws now-initialized Carrier)
        InsnList patch = new InsnList();
        patch.add(new TypeInsnNode(Opcodes.NEW, CARRIER));
        patch.add(new InsnNode(Opcodes.DUP_X1));
        patch.add(new InsnNode(Opcodes.SWAP));
        patch.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, CARRIER, "<init>", "(I)V", false));
        patch.add(new InsnNode(Opcodes.ATHROW));
        // Handler: at entry the caught Carrier is on the stack.
        patch.add(handler);
        patch.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CARRIER, "getValue", "()I", false));
        patch.add(new InsnNode(Opcodes.IRETURN));
        mn.instructions.insert(iret, patch);
        mn.instructions.remove(iret);
        // try { body } catch (Carrier) { handler }
        mn.tryCatchBlocks = mn.tryCatchBlocks == null ? new java.util.ArrayList<>() : mn.tryCatchBlocks;
        mn.tryCatchBlocks.add(new TryCatchBlockNode(
                (LabelNode) first, handler, handler, CARRIER));
    }

    /** Creates the synthetic carrier exception class. */
    private ClassNode ensureCarrier() {
        ClassNode cn = graph.getClasses().get(CARRIER);
        if (cn != null) return cn;
        cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = CARRIER;
        cn.superName = "java/lang/RuntimeException";
        cn.interfaces.add("java/io/Serializable");
        // Field: int value
        cn.fields.add(new org.objectweb.asm.tree.FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "v", "I", null, null));
        // <init>(I)V
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(I)V", null, null);
        InsnList l = ctor.instructions;
        l.add(new VarInsnNode(Opcodes.ALOAD, 0));
        l.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false));
        l.add(new VarInsnNode(Opcodes.ALOAD, 0));
        l.add(new VarInsnNode(Opcodes.ILOAD, 1));
        l.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.PUTFIELD, CARRIER, "v", "I"));
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(ctor);
        // getValue()I
        MethodNode gv = new MethodNode(Opcodes.ACC_PUBLIC, "getValue", "()I", null, null);
        InsnList gl = gv.instructions;
        gl.add(new VarInsnNode(Opcodes.ALOAD, 0));
        gl.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETFIELD, CARRIER, "v", "I"));
        gl.add(new InsnNode(Opcodes.IRETURN));
        cn.methods.add(gv);
        graph.getClasses().put(CARRIER, cn);
        return cn;
    }
}
