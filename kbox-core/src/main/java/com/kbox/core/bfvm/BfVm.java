package com.kbox.core.bfvm;

import com.kbox.core.bfvm.compile.BfMethodCompiler;
import com.kbox.core.bfvm.compile.BfProgramWriter;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Facade: converts the method bodies of a JVM class into Brainfuck programs. Each eligible
 * method body is compiled to a BFVM stream, serialized as a Brainfuck program (embedded as
 * a string constant), and replaced by a thin stub that calls
 * {@link com.kbox.runtime.bfvm.BfRuntime#call}. Unchanged methods are copied verbatim
 * (including their original stack map frames).
 *
 * <p>The pipeline invokes {@link BfvmMethodInjector} on {@code ClassNode}s directly; this
 * byte[]-based facade remains for standalone use and tests.
 */
public final class BfVm {
    /** Guard: LDC string constants must fit in the class file (65535-byte CONSTANT_Utf8). */
    public static final int MAX_BF_SOURCE = 60000;

    private BfVm() {
    }

    public static BfVmResult protect(byte[] classBytes) {
        return protect(classBytes, BfVmOptions.DEFAULT);
    }

    public static BfVmResult protect(byte[] classBytes, BfVmOptions opts) {
        ClassNode cn = new ClassNode(Opcodes.ASM9);
        new ClassReader(classBytes).accept(cn, 0);
        BfVmResult res = new BfVmResult();
        List<MethodNode> out = new ArrayList<>(cn.methods.size());
        for (MethodNode mn : cn.methods) {
            if (!isEligible(mn, opts)) {
                out.add(mn);
                continue;
            }
            String key = mn.name + mn.desc;
            try {
                byte[] stream = BfMethodCompiler.compile(mn, cn.name);
                String bf = BfProgramWriter.write(stream);
                if (bf.length() > MAX_BF_SOURCE) {
                    res.skipped.add(key + " (BF program too large)");
                    out.add(mn);
                    continue;
                }
                out.add(buildBody(cn.name, mn.access, mn.name, mn.desc, bf));
                res.transformed.add(key);
            } catch (UnsupportedOperationException e) {
                res.skipped.add(key + " (" + e.getMessage() + ")");
                out.add(mn);
            }
        }
        cn.methods = out;
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        res.bytes = cw.toByteArray();
        return res;
    }

    private static boolean isEligible(MethodNode mn, BfVmOptions opts) {
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (mn.instructions == null || mn.instructions.size() == 0) {
            return false;
        }
        if (mn.name.equals("<clinit>")) {
            return false;
        }
        if (mn.name.equals("<init>") && !opts.includeCtors) {
            return false;
        }
        if ((mn.access & Opcodes.ACC_SYNCHRONIZED) != 0 && !opts.includeSynchronized) {
            return false;
        }
        if (opts.methodNameFilter != null && !opts.methodNameFilter.test(mn.name)) {
            return false;
        }
        return true;
    }

    /**
     * Build the replacement stub body:
     * {@code BfRuntime.call(bfSource, ownerClass, self, args)} then unbox + return.
     * Package-visible so {@link BfvmMethodInjector} can reuse it on a ClassNode.
     */
    static MethodNode buildBody(String ownerInternal, int access, String name, String desc, String bf) {
        boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
        Type[] args = Type.getArgumentTypes(desc);
        Type ret = Type.getReturnType(desc);

        MethodNode m = new MethodNode(Opcodes.ASM9, access, name, desc, null, null);
        m.visitLdcInsn(bf);
        m.visitLdcInsn(Type.getObjectType(ownerInternal));
        if (isStatic) {
            m.visitInsn(Opcodes.ACONST_NULL);
        } else {
            m.visitVarInsn(Opcodes.ALOAD, 0);
        }
        m.visitLdcInsn(args.length);
        m.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        int slot = isStatic ? 0 : 1;
        for (int i = 0; i < args.length; i++) {
            m.visitInsn(Opcodes.DUP);
            pushIndex(m, i);
            m.visitVarInsn(loadOpcode(args[i]), slot);
            box(m, args[i]);
            m.visitInsn(Opcodes.AASTORE);
            slot += args[i].getSize(); // long/double occupy two local slots
        }
        m.visitMethodInsn(Opcodes.INVOKESTATIC,
                "com/kbox/runtime/bfvm/BfRuntime", "call",
                "(Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                false);
        switch (ret.getSort()) {
            case Type.VOID:
                m.visitInsn(Opcodes.POP);
                m.visitInsn(Opcodes.RETURN);
                break;
            case Type.INT:
            case Type.BOOLEAN:
            case Type.CHAR:
            case Type.BYTE:
            case Type.SHORT:
                m.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Integer");
                m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false);
                m.visitInsn(Opcodes.IRETURN);
                break;
            case Type.LONG:
                m.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Long");
                m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false);
                m.visitInsn(Opcodes.LRETURN);
                break;
            case Type.FLOAT:
                m.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Float");
                m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false);
                m.visitInsn(Opcodes.FRETURN);
                break;
            case Type.DOUBLE:
                m.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Double");
                m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false);
                m.visitInsn(Opcodes.DRETURN);
                break;
            case Type.OBJECT:
            case Type.ARRAY:
                m.visitTypeInsn(Opcodes.CHECKCAST, ret.getInternalName());
                m.visitInsn(Opcodes.ARETURN);
                break;
            default:
                throw new BfVmException("unsupported return type " + ret);
        }
        m.maxStack = 8 + args.length;
        m.maxLocals = Math.max(m.maxLocals, slot + 2);
        return m;
    }

    private static void pushIndex(MethodNode m, int i) {
        if (i <= 5) {
            m.visitInsn(Opcodes.ICONST_0 + i);
        } else {
            m.visitLdcInsn(i);
        }
    }

    private static int loadOpcode(Type t) {
        switch (t.getSort()) {
            case Type.LONG:
                return Opcodes.LLOAD;
            case Type.FLOAT:
                return Opcodes.FLOAD;
            case Type.DOUBLE:
                return Opcodes.DLOAD;
            case Type.OBJECT:
            case Type.ARRAY:
                return Opcodes.ALOAD;
            default:
                return Opcodes.ILOAD;
        }
    }

    private static void box(MethodNode m, Type t) {
        switch (t.getSort()) {
            case Type.LONG:
                m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false);
                break;
            case Type.FLOAT:
                m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false);
                break;
            case Type.DOUBLE:
                m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false);
                break;
            case Type.BOOLEAN:
                m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false);
                break;
            case Type.CHAR:
                m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false);
                break;
            case Type.INT:
            case Type.SHORT:
            case Type.BYTE:
                m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
                break;
            default:
                // reference / array: pushed as-is
                break;
        }
    }
}
