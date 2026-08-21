package com.kbox.core.jnic;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.HashMap;
import java.util.Map;

/**
 * Translates a Java {@link MethodNode} into a C function that uses JNI for
 * every interaction with the JVM (objects, fields, method calls, exceptions).
 *
 * <p>The generated C function has the JNI signature
 * {@code JNIEXPORT <retType> JNICALL Java_<class>_<method>(JNIEnv*, jobject, ...)}.
 * Each JVM opcode becomes a few C statements that operate on a local
 * {@code value_t} stack of tagged unions. This is intentionally simple — it is
 * not a JIT — so it stays correct for the small set of methods we target
 * (license checks, hash computations, etc.).
 *
 * <p>Supports the same opcode subset as the VMP translator; unsupported opcodes
 * throw {@link UnsupportedException} so the caller falls back to obfuscation.
 */
public final class JniCTranslator {

    private static final String TAG = "jnic";

    public static final class UnsupportedException extends RuntimeException {
        public UnsupportedException(String msg) { super(msg); }
    }

    public static final class CFunction {
        public final String name;        // opaque C symbol (e.g. "_kfn0")
        public final String returnType;
        public final String body;
        public final String[] argTypes;
        /** Original Java class (internal, slash-form), method name and descriptor.
         *  Used by {@code JNI_OnLoad} to build the {@code RegisterNatives} table
         *  so the actual C symbols never reveal the Java method identity. */
        public final String javaClass;
        public final String javaName;
        public final String javaDesc;
        public CFunction(String name, String returnType, String body, String[] argTypes,
                         String javaClass, String javaName, String javaDesc) {
            this.name = name; this.returnType = returnType; this.body = body; this.argTypes = argTypes;
            this.javaClass = javaClass; this.javaName = javaName; this.javaDesc = javaDesc;
        }
    }

    /**
     * Translates a Java method to a C function with an <b>opaque</b> symbol name
     * (e.g. {@code _kfn0}). The symbol carries no information about the Java class
     * or method; binding happens at runtime via {@code JNI_OnLoad} +
     * {@code RegisterNatives}, so static analysis of the native library cannot
     * map functions back to their Java counterparts by name.
     */
    public static CFunction translate(String className, MethodNode mn, int index) {
        String symbol = "_kfn" + index;
        Type[] argTypes = Type.getArgumentTypes(mn.desc);
        Type retType = Type.getReturnType(mn.desc);
        String cRet = cType(retType);
        String[] cArgs = new String[argTypes.length + 2];
        cArgs[0] = "JNIEnv*";
        cArgs[1] = mn.name.equals("<init>") ? "jclass" : "jobject";
        for (int i = 0; i < argTypes.length; i++) cArgs[i + 2] = cType(argTypes[i]);

        StringBuilder sb = new StringBuilder();
        sb.append("JNIEXPORT ").append(cRet).append(" JNICALL ").append(symbol)
                .append("(").append(String.join(", ", cArgs)).append(") {\n");
        try {
            emitBody(sb, mn);
        } catch (UnsupportedException e) {
            throw e;
        }
        // Default return for non-void types (in case control falls through).
        if (retType.getSort() == Type.VOID) sb.append("  return;\n");
        else sb.append("  return 0;\n");
        sb.append("}\n");
        return new CFunction(symbol, cRet, sb.toString(), cArgs,
                className, mn.name, mn.desc);
    }

    /** Emits C statements equivalent to the JVM bytecode body. */
    private static void emitBody(StringBuilder sb, MethodNode mn) {
        // We use a stack of "jvalue"-like values: a tagged struct with int/object holders.
        sb.append("  // KBox-JNIC generated body; method ").append(mn.name).append(mn.desc).append("\n");
        sb.append("  // Local variables stack machine: emulated with a small array.\n");
        sb.append("  kbox_value_t _stk[64]; int _sp = 0;\n");
        sb.append("  kbox_value_t _locals[64];\n");
        Map<LabelNode, String> labels = new HashMap<>();
        int lidx = 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof LabelNode) {
                String lbl = "L" + (lidx++);
                labels.put((LabelNode) n, lbl);
                sb.append(lbl).append(":\n");
                continue;
            }
            if (n instanceof org.objectweb.asm.tree.LineNumberNode) continue;
            emitInsn(sb, n, labels);
        }
        sb.append("  // end of method\n");
    }

    private static void emitInsn(StringBuilder sb, AbstractInsnNode n, Map<LabelNode, String> labels) {
        int op = n.getOpcode();
        if (n instanceof InsnNode) {
            switch (op) {
                case Opcodes.ICONST_0: pushInt(sb, 0); break;
                case Opcodes.ICONST_1: pushInt(sb, 1); break;
                case Opcodes.ICONST_2: pushInt(sb, 2); break;
                case Opcodes.ICONST_3: pushInt(sb, 3); break;
                case Opcodes.ICONST_4: pushInt(sb, 4); break;
                case Opcodes.ICONST_5: pushInt(sb, 5); break;
                case Opcodes.ICONST_M1: pushInt(sb, -1); break;
                case Opcodes.ACONST_NULL: pushNull(sb); break;
                case Opcodes.IADD: binop(sb, "+"); break;
                case Opcodes.ISUB: binop(sb, "-"); break;
                case Opcodes.IMUL: binop(sb, "*"); break;
                case Opcodes.IDIV: binop(sb, "/"); break;
                case Opcodes.IREM: binop(sb, "%"); break;
                case Opcodes.INEG: sb.append("  _stk[_sp-1].i = -_stk[_sp-1].i;\n"); break;
                case Opcodes.IAND: binop(sb, "&"); break;
                case Opcodes.IOR: binop(sb, "|"); break;
                case Opcodes.IXOR: binop(sb, "^"); break;
                case Opcodes.ISHL: binop(sb, "<<"); break;
                case Opcodes.ISHR: binop(sb, ">>"); break;
                case Opcodes.IUSHR: ushr(sb); break;
                case Opcodes.IRETURN: sb.append("  return _stk[--_sp].i;\n"); break;
                case Opcodes.ARETURN: sb.append("  return _stk[--_sp].l;\n"); break;
                case Opcodes.RETURN: sb.append("  return;\n"); break;
                case Opcodes.POP: sb.append("  _sp--;\n"); break;
                case Opcodes.DUP: sb.append("  _stk[_sp] = _stk[_sp-1]; _sp++;\n"); break;
                case Opcodes.ARRAYLENGTH: sb.append("  _stk[_sp-1].i = (*_env)->GetArrayLength(_env, _stk[_sp-1].l);\n"); break;
                case Opcodes.ATHROW:
                    sb.append("  (*_env)->Throw(_env, (jthrowable)_stk[--_sp].l); return 0;\n");
                    break;
                default: throw new UnsupportedException("InsnNode op " + op);
            }
            return;
        }
        if (n instanceof IntInsnNode) {
            IntInsnNode i = (IntInsnNode) n;
            if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) pushInt(sb, i.operand);
            else throw new UnsupportedException("IntInsnNode op " + op);
            return;
        }
        if (n instanceof LdcInsnNode) {
            LdcInsnNode ldc = (LdcInsnNode) n;
            if (ldc.cst instanceof Integer) pushInt(sb, (Integer) ldc.cst);
            else if (ldc.cst instanceof String) pushString(sb, (String) ldc.cst);
            else throw new UnsupportedException("LdcInsnNode " + ldc.cst.getClass());
            return;
        }
        if (n instanceof VarInsnNode) {
            VarInsnNode v = (VarInsnNode) n;
            String slot = "_locals[" + v.var + "]";
            if (op == Opcodes.ILOAD || op == Opcodes.ALOAD || op == Opcodes.LLOAD) {
                sb.append("  _stk[_sp++] = ").append(slot).append(";\n");
            } else if (op == Opcodes.ISTORE || op == Opcodes.ASTORE || op == Opcodes.LSTORE) {
                sb.append("  ").append(slot).append(" = _stk[--_sp];\n");
            } else throw new UnsupportedException("VarInsnNode op " + op);
            return;
        }
        if (n instanceof org.objectweb.asm.tree.IincInsnNode) {
            org.objectweb.asm.tree.IincInsnNode inc = (org.objectweb.asm.tree.IincInsnNode) n;
            sb.append("  _locals[").append(inc.var).append("].i += ").append(inc.incr).append(";\n");
            return;
        }
        if (n instanceof JumpInsnNode) {
            JumpInsnNode j = (JumpInsnNode) n;
            String tgt = labels.get(j.label);
            if (tgt == null) tgt = "L_unknown";
            String cond = condExpr(op);
            if (op == Opcodes.GOTO) {
                sb.append("  goto ").append(tgt).append(";\n");
            } else {
                sb.append("  { int _v = _stk[--_sp].i; if (").append(cond).append(") goto ")
                        .append(tgt).append("; }\n");
            }
            return;
        }
        if (n instanceof FieldInsnNode) {
            FieldInsnNode f = (FieldInsnNode) n;
            String cls = f.owner.replace('/', '.');
            switch (op) {
                case Opcodes.GETSTATIC:
                    sb.append("  { jclass _c = (*_env)->FindClass(_env, \"")
                            .append(f.owner).append("\"); jfieldID _f = (*_env)->GetStaticFieldID(_env, _c, \"")
                            .append(f.name).append("\", \"").append(fieldSig(f.desc)).append("\"); _stk[_sp++].l = (jlong)(intptr_t)(*_env)->GetStaticObjectField(_env, _c, _f); }\n");
                    break;
                case Opcodes.PUTSTATIC:
                    sb.append("  { jclass _c = (*_env)->FindClass(_env, \"").append(f.owner)
                            .append("\"); jfieldID _f = (*_env)->GetStaticFieldID(_env, _c, \"").append(f.name)
                            .append("\", \"").append(fieldSig(f.desc)).append("\"); (*_env)->SetStaticObjectField(_env, _c, _f, (jobject)(intptr_t)_stk[--_sp].l); }\n");
                    break;
                case Opcodes.GETFIELD:
                    sb.append("  { jobject _o = (jobject)(intptr_t)_stk[--_sp].l; jfieldID _f = (*_env)->GetFieldID(_env, (*_env)->GetObjectClass(_env, _o), \"")
                            .append(f.name).append("\", \"").append(fieldSig(f.desc)).append("\"); _stk[_sp++].l = (jlong)(intptr_t)(*_env)->GetObjectField(_env, _o, _f); }\n");
                    break;
                case Opcodes.PUTFIELD:
                    sb.append("  { jobject _v = (jobject)(intptr_t)_stk[--_sp].l; jobject _o = (jobject)(intptr_t)_stk[--_sp].l; jfieldID _f = (*_env)->GetFieldID(_env, (*_env)->GetObjectClass(_env, _o), \"")
                            .append(f.name).append("\", \"").append(fieldSig(f.desc)).append("\"); (*_env)->SetObjectField(_env, _o, _f, _v); }\n");
                    break;
                default: throw new UnsupportedException("FieldInsnNode op " + op);
            }
            return;
        }
        if (n instanceof MethodInsnNode) {
            MethodInsnNode m = (MethodInsnNode) n;
            emitMethodCall(sb, m);
            return;
        }
        if (n instanceof TypeInsnNode) {
            TypeInsnNode t = (TypeInsnNode) n;
            if (op == Opcodes.NEW) {
                sb.append("  { jclass _c = (*_env)->FindClass(_env, \"").append(t.desc)
                        .append("\"); jmethodID _ctor = (*_env)->GetMethodID(_env, _c, \"<init>\", \"()V\"); _stk[_sp++].l = (jlong)(intptr_t)(*_env)->NewObject(_env, _c, _ctor); }\n");
                return;
            }
            // Otherwise unsupported for now.
            throw new UnsupportedException("TypeInsnNode op " + op);
        }
        throw new UnsupportedException("Unhandled insn " + n.getClass().getSimpleName());
    }

    private static void emitMethodCall(StringBuilder sb, MethodInsnNode m) {
        Type[] argTypes = Type.getArgumentTypes(m.desc);
        Type retType = Type.getReturnType(m.desc);
        StringBuilder argList = new StringBuilder();
        for (int i = argTypes.length - 1; i >= 0; i--) {
            String a = "_stk[--_sp]." + cTypeSuffix(argTypes[i]);
            if (argList.length() > 0) argList.insert(0, ", ");
            argList.insert(0, a);
        }
        if (m.getOpcode() != Opcodes.INVOKESTATIC) {
            // receiver
            argList.insert(0, ", ");
            argList.insert(0, "(jobject)(intptr_t)_stk[--_sp].l");
        }
        String sig = methodSig(m.desc);
        String retSuffix = retType.getSort() == Type.VOID ? "" : cTypeSuffix(retType);
        switch (m.getOpcode()) {
            case Opcodes.INVOKESTATIC:
                sb.append("  { jclass _c = (*_env)->FindClass(_env, \"").append(m.owner)
                        .append("\"); jmethodID _mid = (*_env)->GetStaticMethodID(_env, _c, \"").append(m.name)
                        .append("\", \"").append(sig).append("\"); ");
                if (retType.getSort() == Type.VOID) {
                    sb.append("(*_env)->CallStaticVoidMethod(_env, _c, _mid").append(argList).append("); }\n");
                } else {
                    sb.append("_stk[_sp++].").append(retSuffix).append(" = (*_env)->CallStatic")
                            .append(callType(retType)).append("Method(_env, _c, _mid").append(argList).append("); }\n");
                }
                break;
            case Opcodes.INVOKEVIRTUAL:
            case Opcodes.INVOKEINTERFACE:
                sb.append("  { jobject _o = (jobject)(intptr_t)_stk[--_sp].l; jmethodID _mid = (*_env)->GetMethodID(_env, (*_env)->GetObjectClass(_env, _o), \"")
                        .append(m.name).append("\", \"").append(sig).append("\"); ");
                if (retType.getSort() == Type.VOID) {
                    sb.append("(*_env)->CallVoidMethod(_env, _o, _mid").append(argList).append("); }\n");
                } else {
                    sb.append("_stk[_sp++].").append(retSuffix).append(" = (*_env)->Call")
                            .append(callType(retType)).append("Method(_env, _o, _mid").append(argList).append("); }\n");
                }
                break;
            case Opcodes.INVOKESPECIAL:
                sb.append("  { jobject _o = (jobject)(intptr_t)_stk[--_sp].l; jclass _c = (*_env)->FindClass(_env, \"")
                        .append(m.owner).append("\"); jmethodID _mid = (*_env)->GetMethodID(_env, _c, \"").append(m.name)
                        .append("\", \"").append(sig).append("\"); ");
                if (retType.getSort() == Type.VOID) {
                    sb.append("(*_env)->CallNonvirtualVoidMethod(_env, _o, _c, _mid").append(argList).append("); }\n");
                } else {
                    sb.append("_stk[_sp++].").append(retSuffix).append(" = (*_env)->CallNonvirtual")
                            .append(callType(retType)).append("Method(_env, _o, _c, _mid").append(argList).append("); }\n");
                }
                break;
            default: throw new UnsupportedException("MethodInsnNode op " + m.getOpcode());
        }
    }

    // ---- helpers (public for reuse by JniBytecodeInterp) ----

    public static String cType(Type t) {
        switch (t.getSort()) {
            case Type.VOID: return "void";
            case Type.BOOLEAN: case Type.BYTE: case Type.CHAR: case Type.SHORT:
            case Type.INT: return "jint";
            case Type.LONG: return "jlong";
            case Type.FLOAT: return "jfloat";
            case Type.DOUBLE: return "jdouble";
            default: return "jobject";
        }
    }
    private static String cTypeSuffix(Type t) {
        switch (t.getSort()) {
            case Type.BOOLEAN: case Type.BYTE: case Type.CHAR: case Type.SHORT:
            case Type.INT: return "i";
            case Type.LONG: return "l";
            case Type.FLOAT: return "f";
            case Type.DOUBLE: return "d";
            default: return "l"; // objects stored as jlong ptr
        }
    }
    private static String callType(Type t) {
        switch (t.getSort()) {
            case Type.BOOLEAN: return "Boolean";
            case Type.BYTE: return "Byte";
            case Type.CHAR: return "Char";
            case Type.SHORT: return "Short";
            case Type.INT: return "Int";
            case Type.LONG: return "Long";
            case Type.FLOAT: return "Float";
            case Type.DOUBLE: return "Double";
            default: return "Object";
        }
    }
    private static String fieldSig(String desc) { return desc; }
    private static String methodSig(String desc) { return desc; }
    private static String condExpr(int op) {
        switch (op) {
            case Opcodes.IFEQ: return "_v == 0";
            case Opcodes.IFNE: return "_v != 0";
            case Opcodes.IFLT: return "_v < 0";
            case Opcodes.IFGE: return "_v >= 0";
            case Opcodes.IFGT: return "_v > 0";
            case Opcodes.IFLE: return "_v <= 0";
            default: return "0";
        }
    }
    private static void pushInt(StringBuilder sb, int v) {
        sb.append("  _stk[_sp].i = ").append(v).append("; _sp++;\n");
    }
    private static void pushNull(StringBuilder sb) {
        sb.append("  _stk[_sp].l = 0; _sp++;\n");
    }
    private static void pushString(StringBuilder sb, String s) {
        sb.append("  _stk[_sp].l = (jlong)(intptr_t)(*_env)->NewStringUTF(_env, \"").append(escapeC(s))
                .append("\"); _sp++;\n");
    }

    /**
     * Escapes a Java string for embedding inside a C string literal. Backslash,
     * double-quote and all C control characters (newline, CR, tab, form feed,
     * backspace, bell) are converted to their C escapes so a string that
     * contains a real 0x0A / 0x0D (e.g. "Main-Class: \nOriginal-...") does not
     * break out of the literal and fail gcc with "missing terminating quote".
     * Non-printable / non-ASCII bytes are emitted as octal escapes to stay
     * source-portable.
     */
    private static String escapeC(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\f': sb.append("\\f"); break;
                case '\b': sb.append("\\b"); break;
                default:
                    if (c >= 0x20 && c <= 0x7E) sb.append(c);
                    else sb.append('\\').append(String.format("%03o", (int) c));
            }
        }
        return sb.toString();
    }
    private static void binop(StringBuilder sb, String op) {
        sb.append("  { int _b = _stk[--_sp].i; int _a = _stk[--_sp].i; _stk[_sp].i = _a ").append(op)
                .append(" _b; _sp++; }\n");
    }

    /** Java IUSHR: logical right shift on the 32-bit int. */
    private static void ushr(StringBuilder sb) {
        sb.append("  { int _b = _stk[--_sp].i; unsigned int _a = (unsigned int)_stk[--_sp].i;")
                .append(" _stk[_sp].i = (int)(_a >> _b); _sp++; }\n");
    }

}
