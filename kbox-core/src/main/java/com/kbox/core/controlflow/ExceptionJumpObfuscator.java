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
        ClassNode valueCarrier = ensureValueCarrier();
        if (valueCarrier == null) return;
        java.util.concurrent.atomic.AtomicInteger transformed = new java.util.concurrent.atomic.AtomicInteger();
        // Per-class independent (carrier already injected above); failures are
        // caught + logged by the processor, matching neverFail semantics.
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, cn -> {
            if (cn.name.equals(CARRIER) || cn.name.equals(VALUE_CARRIER)) return;
            transformed.addAndGet(transformClass(cn));
        }, cfg.getParallelThreads());
        KBoxLog.info(TAG, "Transformed " + transformed.get() + " returns to exception-jump");
    }

    @SuppressWarnings("unchecked")
    private int transformClass(ClassNode cn) {
        int count = 0;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) continue;
            if ((mn.access & Opcodes.ACC_NATIVE) != 0) continue;
            if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) continue;
            // 条目 38：全签名覆盖 —— ()I 保持 IntCarrier 快路径；J/F/D/A 返回
            // 用通用 ValueCarrier（装箱后抛出）。每个方法仍只改一处 return。
            int retOp = returnOpcodeFor(mn.desc);
            if (retOp < 0) continue;
            int retCount = 0;
            org.objectweb.asm.tree.AbstractInsnNode ret = null;
            for (org.objectweb.asm.tree.AbstractInsnNode n = mn.instructions.getFirst();
                 n != null; n = n.getNext()) {
                if (n.getOpcode() == retOp) { retCount++; ret = n; }
            }
            if (retCount != 1 || ret == null) continue;
            if (mn.instructions.getFirst() == ret) continue; // empty method
            try {
                if (retOp == Opcodes.IRETURN) {
                    rewriteReturn(cn, mn, ret);
                } else {
                    rewriteValueReturn(cn, mn, ret, retOp);
                }
                count++;
            } catch (Throwable t) {
                KBoxLog.debug(TAG, "Skip " + cn.name + "." + mn.name + ": " + t.getMessage());
            }
        }
        return count;
    }

    /** 方法描述符对应的 *RETURN opcode；签名不简单（>1 个返回槽等）时 -1。 */
    private static int returnOpcodeFor(String desc) {
        if (desc == null) return -1;
        int close = desc.lastIndexOf(')');
        if (close < 0) return -1;
        String ret = desc.substring(close + 1);
        if (ret.equals("I") || ret.equals("Z") || ret.equals("B") || ret.equals("C")
                || ret.equals("S")) return Opcodes.IRETURN;
        if (ret.equals("J")) return Opcodes.LRETURN;
        if (ret.equals("F")) return Opcodes.FRETURN;
        if (ret.equals("D")) return Opcodes.DRETURN;
        if (ret.length() == 1) return -1; // V
        if (ret.startsWith("L") || ret.startsWith("[")) return Opcodes.ARETURN;
        return -1;
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
        graph.markCfModified(cn.name);
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

    // ------------------------------------------------------------------
    // 条目 38：J/F/D/A 返回的通用载体（ValueCarrier）
    // ------------------------------------------------------------------

    private static final String VALUE_CARRIER = "com/kbox/runtime/_KboxValueCarrier";

    /**
     * 通用返回值异常跳跃：{@code XRETURN} 改为装箱后 {@code new ValueCarrier(boxed);
     * athrow}，handler 里 {@code getValue()} → 拆箱 → {@code XRETURN}。
     * ARETURN 不装箱直接携带。
     */
    private void rewriteValueReturn(ClassNode cn, MethodNode mn,
                                    org.objectweb.asm.tree.AbstractInsnNode ret, int retOp) {
        if (!(mn.instructions.getFirst() instanceof LabelNode)) {
            throw new IllegalStateException("method does not start with a label");
        }
        String retType = mn.desc.substring(mn.desc.lastIndexOf(')') + 1);
        String boxOwner;   // valueOf 的所有者，null = 引用类型不装箱
        String boxDesc;
        String unboxOwner = null;
        String unboxName = null;
        String unboxDesc = null;
        String castTo = null;
        switch (retOp) {
            case Opcodes.LRETURN:
                boxOwner = "java/lang/Long"; boxDesc = "(J)Ljava/lang/Long;";
                unboxOwner = "java/lang/Long"; unboxName = "longValue"; unboxDesc = "()J";
                break;
            case Opcodes.FRETURN:
                boxOwner = "java/lang/Float"; boxDesc = "(F)Ljava/lang/Float;";
                unboxOwner = "java/lang/Float"; unboxName = "floatValue"; unboxDesc = "()F";
                break;
            case Opcodes.DRETURN:
                boxOwner = "java/lang/Double"; boxDesc = "(D)Ljava/lang/Double;";
                unboxOwner = "java/lang/Double"; unboxName = "doubleValue"; unboxDesc = "()D";
                break;
            case Opcodes.ARETURN:
                boxOwner = null; boxDesc = null;
                castTo = retType.startsWith("L")
                        ? retType.substring(1, retType.length() - 1) : retType;
                break;
            default:
                throw new IllegalStateException("unsupported return opcode " + retOp);
        }
        LabelNode handler = new LabelNode();
        InsnList patch = new InsnList();
        if (boxOwner != null) {
            patch.add(new MethodInsnNode(Opcodes.INVOKESTATIC, boxOwner, "valueOf", boxDesc, false));
        }
        // new ValueCarrier(value); athrow  —— 值在栈顶（1 个槽：装箱后为引用）
        patch.add(new TypeInsnNode(Opcodes.NEW, VALUE_CARRIER));
        patch.add(new InsnNode(Opcodes.DUP_X1));
        patch.add(new InsnNode(Opcodes.SWAP));
        patch.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, VALUE_CARRIER,
                "<init>", "(Ljava/lang/Object;)V", false));
        patch.add(new InsnNode(Opcodes.ATHROW));
        // handler：拆箱后原样返回
        patch.add(handler);
        patch.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, VALUE_CARRIER,
                "getValue", "()Ljava/lang/Object;", false));
        if (castTo != null) {
            patch.add(new TypeInsnNode(Opcodes.CHECKCAST, castTo));
        } else {
            patch.add(new TypeInsnNode(Opcodes.CHECKCAST, boxOwner));
            patch.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, unboxOwner,
                    unboxName, unboxDesc, false));
        }
        patch.add(new InsnNode(retOp));
        mn.instructions.insert(ret, patch);
        mn.instructions.remove(ret);
        mn.tryCatchBlocks = mn.tryCatchBlocks == null ? new java.util.ArrayList<>() : mn.tryCatchBlocks;
        mn.tryCatchBlocks.add(new TryCatchBlockNode(
                (LabelNode) mn.instructions.getFirst(), handler, handler, VALUE_CARRIER));
        graph.markCfModified(cn.name);
    }

    /** 通用 Object 载体异常类。 */
    private ClassNode ensureValueCarrier() {
        ClassNode cn = graph.getClasses().get(VALUE_CARRIER);
        if (cn != null) return cn;
        cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = VALUE_CARRIER;
        cn.superName = "java/lang/RuntimeException";
        cn.interfaces.add("java/io/Serializable");
        cn.fields.add(new org.objectweb.asm.tree.FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL, "v", "Ljava/lang/Object;", null, null));
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "(Ljava/lang/Object;)V", null, null);
        InsnList l = ctor.instructions;
        l.add(new VarInsnNode(Opcodes.ALOAD, 0));
        l.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false));
        l.add(new VarInsnNode(Opcodes.ALOAD, 0));
        l.add(new VarInsnNode(Opcodes.ALOAD, 1));
        l.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.PUTFIELD, VALUE_CARRIER, "v", "Ljava/lang/Object;"));
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(ctor);
        MethodNode gv = new MethodNode(Opcodes.ACC_PUBLIC, "getValue", "()Ljava/lang/Object;", null, null);
        InsnList gl = gv.instructions;
        gl.add(new VarInsnNode(Opcodes.ALOAD, 0));
        gl.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETFIELD, VALUE_CARRIER, "v", "Ljava/lang/Object;"));
        gl.add(new InsnNode(Opcodes.ARETURN));
        cn.methods.add(gv);
        graph.getClasses().put(VALUE_CARRIER, cn);
        return cn;
    }
}
