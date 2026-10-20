package com.kbox.runtime.bfvm;

import java.lang.invoke.MethodType;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

/**
 * Executes a BFVM stream recovered from a Brainfuck program. Implements the JVM stack
 * machine semantics: operand stack, local variable slots, boxing, method dispatch via
 * reflection, object allocation, field access and array operations.
 *
 * <p>Values are stored boxed (Integer/Long/Float/Double/Boolean/Character/String/arrays).
 * Category-2 values (long/double) are detected by their runtime type for the dup/pop
 * family. Method calls, field access and object allocation are resolved through the real
 * JVM, so calls to other transformed methods transparently re-enter the VM.
 */
public final class VmCore {
    private VmCore() {
    }

    public static Object execute(byte[] stream, Class<?> owner, Object self, Object[] args, ClassLoader loader) {
        if (stream == null || stream.length < 2) {
            throw new BfVmException("invalid BFVM stream");
        }
        Cursor c = new Cursor(stream, 0);
        int maxLocals = c.u16();
        String desc = c.utf8();
        ClassLoader eff = loader != null ? loader : BfRuntime.class.getClassLoader();
        // P1-5：异常表（start, end, handler, catchType）。pc 在构建期回填。
        int handlerCount = c.u16();
        int[] hStart = new int[handlerCount];
        int[] hEnd = new int[handlerCount];
        int[] hPc = new int[handlerCount];
        String[] hType = new String[handlerCount];
        for (int i = 0; i < handlerCount; i++) {
            int hasType = c.u8();
            hType[i] = hasType != 0 ? c.utf8() : null;
            hStart[i] = c.i32();
            hEnd[i] = c.i32();
            hPc[i] = c.i32();
        }
        Object[] locals = new Object[Math.max(maxLocals, 1)];
        Class<?>[] argTypes = MethodType.fromMethodDescriptorString(desc, eff).parameterArray();
        if (self != null) {
            locals[0] = self;
        }
        int slot = self != null ? 1 : 0;
        for (int i = 0; i < args.length && i < argTypes.length; i++) {
            locals[slot] = stackRep(argTypes[i], args[i]);
            slot += slotSize(argTypes[i]); // long/double occupy two local slots
        }
        State s = new State();

        // P1-5：try/catch 包住整个分派循环。无异常时 JVM 的 try 是零成本的；
        // 有异常时按 (pc, 类型) 查异常表：命中则清栈、压异常、跳到 handler。
        int monitorDepth = 0;
        try {
        for (;;) {
            final int pc = c.pc;
            try {
            int op = c.u8();
            switch (op) {
                case Opcode.NOP:
                    break;

                case Opcode.CONST_INT:
                    s.push(Integer.valueOf(c.i32()));
                    break;
                case Opcode.CONST_LONG:
                    s.push(Long.valueOf(c.i64()));
                    break;
                case Opcode.CONST_FLOAT:
                    s.push(Float.valueOf(Float.intBitsToFloat(c.i32())));
                    break;
                case Opcode.CONST_DOUBLE:
                    s.push(Double.valueOf(Double.longBitsToDouble(c.i64())));
                    break;
                case Opcode.CONST_STRING:
                    s.push(c.utf8());
                    break;
                case Opcode.CONST_CLASS:
                    s.push(resolveClass(c.utf8(), eff));
                    break;
                case Opcode.ACONST_NULL:
                    s.push(null);
                    break;

                case Opcode.ILOAD:
                case Opcode.LLOAD:
                case Opcode.FLOAD:
                case Opcode.DLOAD:
                case Opcode.ALOAD: {
                    int localSlot = c.u8();
                    s.push(locals[localSlot]);
                    break;
                }
                case Opcode.ISTORE:
                case Opcode.LSTORE:
                case Opcode.FSTORE:
                case Opcode.DSTORE:
                case Opcode.ASTORE: {
                    int localSlot = c.u8();
                    locals[localSlot] = s.pop();
                    break;
                }
                case Opcode.IINC: {
                    int localSlot = c.u8();
                    int delta = (byte) c.u8();
                    locals[localSlot] = Integer.valueOf(((Integer) locals[localSlot]).intValue() + delta);
                    break;
                }

                // ---- arithmetic ----
                case Opcode.IADD:
                    s.push(Integer.valueOf(iPop(s) + iPop(s)));
                    break;
                case Opcode.ISUB:
                    s.push(Integer.valueOf(iSub(s)));
                    break;
                case Opcode.IMUL:
                    s.push(Integer.valueOf(iMul(s)));
                    break;
                case Opcode.IDIV:
                    s.push(Integer.valueOf(iDiv(s)));
                    break;
                case Opcode.IREM:
                    s.push(Integer.valueOf(iRem(s)));
                    break;
                case Opcode.INEG:
                    s.push(Integer.valueOf(-iPop(s)));
                    break;

                case Opcode.LADD:
                    s.push(Long.valueOf(lPop(s) + lPop(s)));
                    break;
                case Opcode.LSUB: {
                    long b = lPop(s);
                    long a = lPop(s);
                    s.push(Long.valueOf(a - b));
                    break;
                }
                case Opcode.LMUL:
                    s.push(Long.valueOf(lMul(s)));
                    break;
                case Opcode.LDIV:
                    s.push(Long.valueOf(lDiv(s)));
                    break;
                case Opcode.LREM:
                    s.push(Long.valueOf(lRem(s)));
                    break;
                case Opcode.LNEG:
                    s.push(Long.valueOf(-lPop(s)));
                    break;

                case Opcode.FADD:
                    s.push(Float.valueOf(fPop(s) + fPop(s)));
                    break;
                case Opcode.FSUB: {
                    float b = fPop(s);
                    float a = fPop(s);
                    s.push(Float.valueOf(a - b));
                    break;
                }
                case Opcode.FMUL:
                    s.push(Float.valueOf(fMul(s)));
                    break;
                case Opcode.FDIV:
                    s.push(Float.valueOf(fDiv(s)));
                    break;
                case Opcode.FREM:
                    s.push(Float.valueOf(fRem(s)));
                    break;
                case Opcode.FNEG:
                    s.push(Float.valueOf(-fPop(s)));
                    break;

                case Opcode.DADD:
                    s.push(Double.valueOf(dPop(s) + dPop(s)));
                    break;
                case Opcode.DSUB: {
                    double b = dPop(s);
                    double a = dPop(s);
                    s.push(Double.valueOf(a - b));
                    break;
                }
                case Opcode.DMUL:
                    s.push(Double.valueOf(dMul(s)));
                    break;
                case Opcode.DDIV:
                    s.push(Double.valueOf(dDiv(s)));
                    break;
                case Opcode.DREM:
                    s.push(Double.valueOf(dRem(s)));
                    break;
                case Opcode.DNEG:
                    s.push(Double.valueOf(-dPop(s)));
                    break;

                // ---- shifts & bitwise ----
                case Opcode.ISHL: {
                    int b = iPop(s);
                    int a = iPop(s);
                    s.push(Integer.valueOf(a << b));
                    break;
                }
                case Opcode.ISHR: {
                    int b = iPop(s);
                    int a = iPop(s);
                    s.push(Integer.valueOf(a >> b));
                    break;
                }
                case Opcode.IUSHR: {
                    int b = iPop(s);
                    int a = iPop(s);
                    s.push(Integer.valueOf(a >>> b));
                    break;
                }
                case Opcode.LSHL: {
                    long b = lPop(s);
                    long a = lPop(s);
                    s.push(Long.valueOf(a << b));
                    break;
                }
                case Opcode.LSHR: {
                    long b = lPop(s);
                    long a = lPop(s);
                    s.push(Long.valueOf(a >> b));
                    break;
                }
                case Opcode.LUSHR: {
                    long b = lPop(s);
                    long a = lPop(s);
                    s.push(Long.valueOf(a >>> b));
                    break;
                }
                case Opcode.IAND:
                    s.push(Integer.valueOf(iPop(s) & iPop(s)));
                    break;
                case Opcode.IOR:
                    s.push(Integer.valueOf(iPop(s) | iPop(s)));
                    break;
                case Opcode.IXOR:
                    s.push(Integer.valueOf(iPop(s) ^ iPop(s)));
                    break;
                case Opcode.LAND:
                    s.push(Long.valueOf(lPop(s) & lPop(s)));
                    break;
                case Opcode.LOR:
                    s.push(Long.valueOf(lPop(s) | lPop(s)));
                    break;
                case Opcode.LXOR:
                    s.push(Long.valueOf(lPop(s) ^ lPop(s)));
                    break;

                // ---- conversions ----
                case Opcode.I2L:
                    s.push(Long.valueOf(iPop(s)));
                    break;
                case Opcode.I2F:
                    s.push(Float.valueOf(iPop(s)));
                    break;
                case Opcode.I2D:
                    s.push(Double.valueOf(iPop(s)));
                    break;
                case Opcode.L2I:
                    s.push(Integer.valueOf((int) lPop(s)));
                    break;
                case Opcode.L2F:
                    s.push(Float.valueOf(lPop(s)));
                    break;
                case Opcode.L2D:
                    s.push(Double.valueOf(lPop(s)));
                    break;
                case Opcode.F2I:
                    s.push(Integer.valueOf((int) fPop(s)));
                    break;
                case Opcode.F2L:
                    s.push(Long.valueOf((long) fPop(s)));
                    break;
                case Opcode.F2D:
                    s.push(Double.valueOf(fPop(s)));
                    break;
                case Opcode.D2I:
                    s.push(Integer.valueOf((int) dPop(s)));
                    break;
                case Opcode.D2L:
                    s.push(Long.valueOf((long) dPop(s)));
                    break;
                case Opcode.D2F:
                    s.push(Float.valueOf((float) dPop(s)));
                    break;
                case Opcode.I2B:
                    s.push(Integer.valueOf((byte) iPop(s)));
                    break;
                case Opcode.I2C:
                    s.push(Integer.valueOf((char) iPop(s)));
                    break;
                case Opcode.I2S:
                    s.push(Integer.valueOf((short) iPop(s)));
                    break;

                // ---- comparisons ----
                case Opcode.LCMP: {
                    long b = lPop(s);
                    long a = lPop(s);
                    s.push(Integer.valueOf(Long.compare(a, b)));
                    break;
                }
                case Opcode.FCMPL: {
                    float b = fPop(s);
                    float a = fPop(s);
                    s.push(Integer.valueOf(fcmp(a, b, true)));
                    break;
                }
                case Opcode.FCMPG: {
                    float b = fPop(s);
                    float a = fPop(s);
                    s.push(Integer.valueOf(fcmp(a, b, false)));
                    break;
                }
                case Opcode.DCMPL: {
                    double b = dPop(s);
                    double a = dPop(s);
                    s.push(Integer.valueOf(dcmp(a, b, true)));
                    break;
                }
                case Opcode.DCMPG: {
                    double b = dPop(s);
                    double a = dPop(s);
                    s.push(Integer.valueOf(dcmp(a, b, false)));
                    break;
                }

                // ---- branches ----
                case Opcode.IFEQ: {
                    int t = c.i32();
                    if (iPop(s) == 0) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IFNE: {
                    int t = c.i32();
                    if (iPop(s) != 0) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IFLT: {
                    int t = c.i32();
                    if (iPop(s) < 0) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IFGE: {
                    int t = c.i32();
                    if (iPop(s) >= 0) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IFGT: {
                    int t = c.i32();
                    if (iPop(s) > 0) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IFLE: {
                    int t = c.i32();
                    if (iPop(s) <= 0) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ICMPEQ: {
                    int t = c.i32();
                    int b = iPop(s);
                    int a = iPop(s);
                    if (a == b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ICMPNE: {
                    int t = c.i32();
                    int b = iPop(s);
                    int a = iPop(s);
                    if (a != b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ICMPLT: {
                    int t = c.i32();
                    int b = iPop(s);
                    int a = iPop(s);
                    if (a < b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ICMPGE: {
                    int t = c.i32();
                    int b = iPop(s);
                    int a = iPop(s);
                    if (a >= b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ICMPGT: {
                    int t = c.i32();
                    int b = iPop(s);
                    int a = iPop(s);
                    if (a > b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ICMPLE: {
                    int t = c.i32();
                    int b = iPop(s);
                    int a = iPop(s);
                    if (a <= b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ACMPEQ: {
                    int t = c.i32();
                    Object b = deref(s.pop());
                    Object a = deref(s.pop());
                    if (a == b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IF_ACMPNE: {
                    int t = c.i32();
                    Object b = deref(s.pop());
                    Object a = deref(s.pop());
                    if (a != b) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IFNULL: {
                    int t = c.i32();
                    if (deref(s.pop()) == null) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.IFNONNULL: {
                    int t = c.i32();
                    if (deref(s.pop()) != null) {
                        c.pc = t;
                    }
                    break;
                }
                case Opcode.GOTO:
                    c.pc = c.i32();
                    break;
                case Opcode.TABLESWITCH: {
                    int def = c.i32();
                    int low = c.i32();
                    int high = c.i32();
                    int n = high - low + 1;
                    int[] targets = c.i32s(n);
                    int idx = iPop(s);
                    if (idx < low || idx > high) {
                        c.pc = def;
                    } else {
                        c.pc = targets[idx - low];
                    }
                    break;
                }
                case Opcode.LOOKUPSWITCH: {
                    int def = c.i32();
                    int npairs = c.i32();
                    int idx = iPop(s);
                    int target = def;
                    for (int i = 0; i < npairs; i++) {
                        int key = c.i32();
                        int t = c.i32();
                        if (key == idx) {
                            target = t;
                            break;
                        }
                    }
                    c.pc = target;
                    break;
                }

                // ---- stack shuffles ----
                case Opcode.POP:
                    s.pop();
                    break;
                case Opcode.POP2:
                    s.pop2();
                    break;
                case Opcode.DUP:
                    s.dup();
                    break;
                case Opcode.DUP_X1:
                    s.dupX1();
                    break;
                case Opcode.DUP_X2:
                    s.dupX2();
                    break;
                case Opcode.DUP2:
                    s.dup2();
                    break;
                case Opcode.DUP2_X1:
                    s.dup2X1();
                    break;
                case Opcode.DUP2_X2:
                    s.dup2X2();
                    break;
                case Opcode.SWAP:
                    s.swap();
                    break;

                // ---- arrays ----
                case Opcode.ARRAYLENGTH:
                    s.push(Integer.valueOf(Array.getLength(deref(s.pop()))));
                    break;

                case Opcode.IALOAD: {
                    int i = iPop(s);
                    s.push(Integer.valueOf(((int[]) s.pop())[i]));
                    break;
                }
                case Opcode.LALOAD: {
                    int i = iPop(s);
                    s.push(Long.valueOf(((long[]) s.pop())[i]));
                    break;
                }
                case Opcode.FALOAD: {
                    int i = iPop(s);
                    s.push(Float.valueOf(((float[]) s.pop())[i]));
                    break;
                }
                case Opcode.DALOAD: {
                    int i = iPop(s);
                    s.push(Double.valueOf(((double[]) s.pop())[i]));
                    break;
                }
                case Opcode.AALOAD: {
                    int i = iPop(s);
                    Object[] a = (Object[]) deref(s.pop());
                    s.push(deref(a[i]));
                    break;
                }
                case Opcode.BALOAD: {
                    int i = iPop(s);
                    Object a = s.pop();
                    if (a instanceof byte[]) {
                        s.push(Integer.valueOf(((byte[]) a)[i]));
                    } else {
                        s.push(Integer.valueOf(((boolean[]) a)[i] ? 1 : 0));
                    }
                    break;
                }
                case Opcode.CALOAD: {
                    int i = iPop(s);
                    s.push(Integer.valueOf(((char[]) s.pop())[i]));
                    break;
                }
                case Opcode.SALOAD: {
                    int i = iPop(s);
                    s.push(Integer.valueOf(((short[]) s.pop())[i]));
                    break;
                }

                case Opcode.IASTORE: {
                    int v = iPop(s);
                    int i = iPop(s);
                    ((int[]) s.pop())[i] = v;
                    break;
                }
                case Opcode.LASTORE: {
                    long v = lPop(s);
                    int i = iPop(s);
                    ((long[]) s.pop())[i] = v;
                    break;
                }
                case Opcode.FASTORE: {
                    float v = fPop(s);
                    int i = iPop(s);
                    ((float[]) s.pop())[i] = v;
                    break;
                }
                case Opcode.DASTORE: {
                    double v = dPop(s);
                    int i = iPop(s);
                    ((double[]) s.pop())[i] = v;
                    break;
                }
                case Opcode.AASTORE: {
                    Object v = deref(s.pop());
                    int i = iPop(s);
                    ((Object[]) deref(s.pop()))[i] = v;
                    break;
                }
                case Opcode.BASTORE: {
                    int v = iPop(s);
                    int i = iPop(s);
                    Object a = s.pop();
                    if (a instanceof byte[]) {
                        ((byte[]) a)[i] = (byte) v;
                    } else {
                        ((boolean[]) a)[i] = v != 0;
                    }
                    break;
                }
                case Opcode.CASTORE: {
                    int v = iPop(s);
                    int i = iPop(s);
                    ((char[]) s.pop())[i] = (char) v;
                    break;
                }
                case Opcode.SASTORE: {
                    int v = iPop(s);
                    int i = iPop(s);
                    ((short[]) s.pop())[i] = (short) v;
                    break;
                }

                case Opcode.NEWARRAY: {
                    int atype = c.u8();
                    int count = iPop(s);
                    Class<?> comp;
                    switch (atype) {
                        case 4: comp = boolean.class; break;
                        case 5: comp = char.class; break;
                        case 6: comp = float.class; break;
                        case 7: comp = double.class; break;
                        case 8: comp = byte.class; break;
                        case 9: comp = short.class; break;
                        case 10: comp = int.class; break;
                        case 11: comp = long.class; break;
                        default: throw new BfVmException("bad NEWARRAY atype " + atype);
                    }
                    s.push(Array.newInstance(comp, count));
                    break;
                }
                case Opcode.ANEWARRAY: {
                    String compName = c.utf8();
                    int count = iPop(s);
                    s.push(Array.newInstance(resolveClass(compName, eff), count));
                    break;
                }

                // ---- objects ----
                case Opcode.NEW: {
                    Class<?> cls = resolveClass(c.utf8(), eff);
                    s.push(new Uninitialized(cls));
                    break;
                }

                // ---- fields ----
                case Opcode.GETSTATIC: {
                    String[] r = c.ref();
                    Class<?> cls = resolveClass(r[0], eff);
                    Field f = findField(cls, r[1]);
                    s.push(stackRep(f.getType(), fieldGet(f, null)));
                    break;
                }
                case Opcode.PUTSTATIC: {
                    String[] r = c.ref();
                    Class<?> cls = resolveClass(r[0], eff);
                    Field f = findField(cls, r[1]);
                    // NEW pushes an Uninitialized placeholder; <init> materializes it
                    // by setting its `instance`. Every consumer must deref — for a
                    // static field the value is often a freshly constructed singleton
                    // (`new MixinService()` → PUTSTATIC), and passing the placeholder
                    // to Field.set throws "Can not set static ... to <placeholder>".
                    Object v = deref(s.pop());
                    fieldSet(f, null, coerceTo(f.getType(), v));
                    break;
                }
                case Opcode.GETFIELD: {
                    String[] r = c.ref();
                    Object o = deref(s.pop());
                    Field f = findField(o.getClass(), r[1]);
                    s.push(stackRep(f.getType(), fieldGet(f, o)));
                    break;
                }
                case Opcode.PUTFIELD: {
                    String[] r = c.ref();
                    Object v = deref(s.pop());
                    Object o = deref(s.pop());
                    Field f = findField(o.getClass(), r[1]);
                    fieldSet(f, o, coerceTo(f.getType(), v));
                    break;
                }

                // ---- method invocation ----
                case Opcode.INVOKESTATIC: {
                    String[] r = c.ref();
                    Class<?> cls = resolveClass(r[0], eff);
                    MethodType mt = MethodType.fromMethodDescriptorString(r[2], eff);
                    Object[] argv = popArgs(s, mt.parameterArray());
                    Method m = findMethod(cls, r[1], r[2], true);
                    Object res = methodInvoke(m, null, argv);
                    if (mt.returnType() != void.class) {
                        s.push(stackRep(mt.returnType(), res));
                    }
                    break;
                }
                case Opcode.INVOKEVIRTUAL:
                case Opcode.INVOKEINTERFACE: {
                    String[] r = c.ref();
                    MethodType mt = MethodType.fromMethodDescriptorString(r[2], eff);
                    Object[] argv = popArgs(s, mt.parameterArray());
                    Object recv = deref(s.pop());
                    Method m = findMethod(recv.getClass(), r[1], r[2], false);
                    Object res = methodInvoke(m, recv, argv);
                    if (mt.returnType() != void.class) {
                        s.push(stackRep(mt.returnType(), res));
                    }
                    break;
                }
                case Opcode.INVOKESPECIAL: {
                    String[] r = c.ref();
                    MethodType mt = MethodType.fromMethodDescriptorString(r[2], eff);
                    Object[] argv = popArgs(s, mt.parameterArray());
                    Object obj = s.pop();
                    if (r[1].equals("<init>")) {
                        if (obj instanceof Uninitialized) {
                            Uninitialized u = (Uninitialized) obj;
                            u.instance = ctorNew(findConstructor(u.type, r[2]), argv);
                        } else {
                            ctorNew(findConstructor(obj.getClass(), r[2]), argv);
                        }
                    } else {
                        Object recv = deref(obj);
                        Method m = findMethod(recv.getClass(), r[1], r[2], false);
                        Object res = methodInvoke(m, recv, argv);
                        if (mt.returnType() != void.class) {
                            s.push(stackRep(mt.returnType(), res));
                        }
                    }
                    break;
                }

                // ---- type checks & throw ----
                case Opcode.CHECKCAST: {
                    Class<?> cls = resolveClass(c.utf8(), eff);
                    Object o = deref(s.pop());
                    if (o != null && !cls.isInstance(o)) {
                        throw new ClassCastException(cls.getName());
                    }
                    s.push(o);
                    break;
                }
                case Opcode.INSTANCEOF: {
                    Class<?> cls = resolveClass(c.utf8(), eff);
                    Object o = deref(s.pop());
                    s.push(Integer.valueOf(o != null && cls.isInstance(o) ? 1 : 0));
                    break;
                }
                case Opcode.ATHROW: {
                    Object t = deref(s.pop());
                    if (t instanceof RuntimeException) {
                        throw (RuntimeException) t;
                    }
                    if (t instanceof Error) {
                        throw (Error) t;
                    }
                    // Non-runtime throwable (e.g. KBox's exception-relay carrier):
                    // rethrow the ORIGINAL instance so this frame's own exception
                    // table can match it. Wrapping it in BfVmException loses the
                    // type and turns a locally-caught carrier into a hard failure.
                    sneakyThrow((Throwable) t);
                    break; // unreachable
                }

                // ---- P1-5：monitor / multianewarray / invokedynamic ----
                case Opcode.MONITORENTER: {
                    deref(s.pop());
                    VM_MONITOR.lock();
                    monitorDepth++;
                    break;
                }
                case Opcode.MONITOREXIT: {
                    s.pop();
                    if (monitorDepth > 0) {
                        monitorDepth--;
                        VM_MONITOR.unlock();
                    }
                    break;
                }
                case Opcode.MULTIANEWARRAY: {
                    String arrDesc = c.utf8();
                    int dims = c.u8();
                    int[] sizes = new int[dims];
                    for (int i = dims - 1; i >= 0; i--) {
                        sizes[i] = ((Number) deref(s.pop())).intValue();
                    }
                    s.push(multiArray(arrDesc, sizes, eff));
                    break;
                }
                case Opcode.INVOKEDYNAMIC: {
                    String name = c.utf8();
                    String d = c.utf8();
                    int bsmTag = c.u8();
                    String[] bsmRef = c.ref();
                    int argc = c.u8();
                    Object[] bsmArgs = new Object[argc];
                    for (int i = 0; i < argc; i++) {
                        bsmArgs[i] = readBsmArg(c, eff);
                    }
                    MethodType siteType = MethodType.fromMethodDescriptorString(d, eff);
                    Object[] argv = popArgs(s, siteType.parameterArray());
                    java.lang.invoke.MethodHandle target =
                            indyTarget(bsmTag, bsmRef, name, siteType, bsmArgs, eff, owner);
                    Object res = target.invokeWithArguments(argv);
                    if (siteType.returnType() != void.class) {
                        s.push(stackRep(siteType.returnType(), res));
                    }
                    break;
                }

                // ---- returns ----
                case Opcode.RETURN:
                    return null;
                case Opcode.IRETURN:
                    return Integer.valueOf(iPop(s));
                case Opcode.LRETURN:
                    return Long.valueOf(lPop(s));
                case Opcode.FRETURN:
                    return Float.valueOf(fPop(s));
                case Opcode.DRETURN:
                    return Double.valueOf(dPop(s));
                case Opcode.ARETURN:
                    return deref(s.pop());

                default:
                    throw new BfVmException("bad BFVM opcode " + op);
            }
            } catch (Throwable t) {
                int target = findHandler(hStart, hEnd, hPc, hType, pc, t, eff);
                if (target >= 0) {
                    s.clear();
                    s.push(t);
                    c.pc = target;
                    continue;
                }
                if (t instanceof RuntimeException) throw (RuntimeException) t;
                if (t instanceof Error) throw (Error) t;
                // Preserve the original type for the caller's own catch table.
                sneakyThrow(t);
                throw new AssertionError("unreachable");
            }
        }
        } finally {
            // 异常逃出本帧时释放还持有的 monitor，避免跨线程死锁。
            while (monitorDepth > 0) {
                monitorDepth--;
                VM_MONITOR.unlock();
            }
        }
    }

    // ---- P1-5 helpers ----

    /** VM 级重入锁：monitorenter/exit 用它做互斥（比真实对象锁粗，但语义正确且可重入）。 */
    private static final java.util.concurrent.locks.ReentrantLock VM_MONITOR =
            new java.util.concurrent.locks.ReentrantLock();

    /** 按 (pc, 异常类型) 找异常表条目；返回 handler pc，找不到返回 -1。 */
    private static int findHandler(int[] start, int[] end, int[] handler, String[] type,
                                   int pc, Throwable t, ClassLoader eff) {
        for (int i = 0; i < start.length; i++) {
            if (pc < start[i] || pc >= end[i]) continue;
            if (type[i] == null) return handler[i];   // catch-all（finally）
            try {
                if (resolveClass(type[i], eff).isInstance(t)) return handler[i];
            } catch (Throwable ignore) {
                // 类型解析失败：跳过该条，等价于"不匹配"
            }
        }
        return -1;
    }

    /** MULTIANEWARRAY：按维度一次性建多维数组。 */
    private static Object multiArray(String desc, int[] sizes, ClassLoader eff) {
        String component = desc.substring(desc.lastIndexOf('[') + 1);
        Class<?> leaf;
        if (component.startsWith("L") && component.endsWith(";")) {
            leaf = resolveClass(component.substring(1, component.length() - 1), eff);
        } else {
            leaf = primitiveClass(component.charAt(0));
        }
        return java.lang.reflect.Array.newInstance(leaf, sizes);
    }

    private static Class<?> primitiveClass(char c) {
        switch (c) {
            case 'Z': return boolean.class;
            case 'B': return byte.class;
            case 'C': return char.class;
            case 'S': return short.class;
            case 'I': return int.class;
            case 'J': return long.class;
            case 'F': return float.class;
            case 'D': return double.class;
            default: throw new BfVmException("bad array component " + c);
        }
    }

    /** invokedynamic：重建 CallSite 并取出 target。 */
    private static java.lang.invoke.MethodHandle indyTarget(int bsmTag, String[] bsm, String name,
            MethodType siteType, Object[] bsmArgs, ClassLoader eff, Class<?> caller) {
        try {
            // BSM 自身是公开方法（LambdaMetafactory/StringConcatFactory），用 publicLookup 即可；
            // 对 JDK 类做 privateLookupIn 会被模块系统拒绝（illegal lookupClass）。
            java.lang.invoke.MethodHandle bsmMh =
                    lookupHandle(bsmTag, bsm[0], bsm[1], bsm[2], eff, false);
            Object[] call = new Object[bsmArgs.length + 3];
            // caller 必须是<b>被虚拟化的那个类</b>：LambdaMetafactory 用它定义 lambda 类并
            // 访问实现方法，传 VmCore 会导致非法访问。
            call[0] = privateLookup(caller != null ? caller : VmCore.class);
            call[1] = name;
            call[2] = siteType;
            System.arraycopy(bsmArgs, 0, call, 3, bsmArgs.length);
            java.lang.invoke.CallSite cs =
                    (java.lang.invoke.CallSite) bsmMh.invokeWithArguments(call);
            return cs.getTarget();
        } catch (Throwable t) {
            throw new BfVmException("invokedynamic bootstrap failed: " + name + siteType, t);
        }
    }

    /**
     * 还原一个 MethodHandle 常量。
     *
     * <p>LambdaMetafactory 的实现方法通常是 {@code private static}，必须用"带私有访问权"的
     * lookup 才找得到。</p>
     */
    private static java.lang.invoke.MethodHandle lookupHandle(int tag, String owner, String name,
            String desc, ClassLoader eff, boolean privateAccess) {
        try {
            Class<?> c = resolveClass(owner, eff);
            java.lang.invoke.MethodHandles.Lookup lk = privateAccess
                    ? privateLookup(c)
                    : java.lang.invoke.MethodHandles.publicLookup();
            if (tag == 1 || tag == 2 || tag == 3 || tag == 4) {
                Class<?> ft = fieldType(desc, eff);
                switch (tag) {
                    case 1: return lk.findGetter(c, name, ft);
                    case 2: return lk.findStaticGetter(c, name, ft);
                    case 3: return lk.findSetter(c, name, ft);
                    default: return lk.findStaticSetter(c, name, ft);
                }
            }
            MethodType mt = MethodType.fromMethodDescriptorString(desc, eff);
            switch (tag) {
                case 5: return lk.findVirtual(c, name, mt);
                case 6: return lk.findStatic(c, name, mt);
                case 7: return lk.findSpecial(c, name, mt, c);
                case 8: return lk.findConstructor(c, mt);
                case 9: return lk.findVirtual(c, name, mt);
                default: throw new BfVmException("bad handle tag " + tag);
            }
        } catch (Throwable t) {
            throw new BfVmException("handle lookup failed: " + owner + "." + name + desc, t);
        }
    }

    private static Class<?> fieldType(String desc, ClassLoader eff) {
        return MethodType.fromMethodDescriptorString("()" + desc, eff).returnType();
    }

    private static java.lang.invoke.MethodHandles.Lookup privateLookup(Class<?> owner) {
        // Java 9+：privateLookupIn（编译目标是 8，只能反射调用）。
        try {
            java.lang.reflect.Method m = java.lang.invoke.MethodHandles.class.getMethod(
                    "privateLookupIn", Class.class, java.lang.invoke.MethodHandles.Lookup.class);
            return (java.lang.invoke.MethodHandles.Lookup)
                    m.invoke(null, owner, java.lang.invoke.MethodHandles.lookup());
        } catch (Throwable ignore) {
            // Java 8 无 privateLookupIn：直接构造 full-privilege Lookup（ALL_MODES = -1）。
            try {
                java.lang.reflect.Constructor<java.lang.invoke.MethodHandles.Lookup> c =
                        java.lang.invoke.MethodHandles.Lookup.class.getDeclaredConstructor(
                                Class.class, int.class);
                c.setAccessible(true);
                return c.newInstance(owner, -1);
            } catch (Throwable ignore2) {
                try {
                    return java.lang.invoke.MethodHandles.publicLookup().in(owner);
                } catch (Throwable ignore3) {
                    return java.lang.invoke.MethodHandles.publicLookup();
                }
            }
        }
    }

    /** 读取一个 invokedynamic 的 BSM 常量参数。 */
    private static Object readBsmArg(Cursor c, ClassLoader eff) {
        int tag = c.u8();
        switch (tag) {
            case 1: return Integer.valueOf(c.i32());
            case 2: return Long.valueOf(c.i64());
            case 3: return Float.valueOf(Float.intBitsToFloat(c.i32()));
            case 4: return Double.valueOf(Double.longBitsToDouble(c.i64()));
            case 5: return c.utf8();
            case 6: return MethodType.fromMethodDescriptorString(c.utf8(), eff);
            case 7: {
                int htag = c.u8();
                String[] r = c.ref();
                return lookupHandle(htag, r[0], r[1], r[2], eff, true);
            }
            default: throw new BfVmException("bad bsm arg tag " + tag);
        }
    }

    // ---- operand helpers ----
    private static int iPop(State s) {
        return ((Integer) s.pop()).intValue();
    }

    private static long lPop(State s) {
        return ((Long) s.pop()).longValue();
    }

    private static float fPop(State s) {
        return ((Float) s.pop()).floatValue();
    }

    private static double dPop(State s) {
        return ((Double) s.pop()).doubleValue();
    }

    private static int iSub(State s) {
        int b = iPop(s);
        return iPop(s) - b;
    }

    private static int iMul(State s) {
        int b = iPop(s);
        return iPop(s) * b;
    }

    private static int iDiv(State s) {
        int b = iPop(s);
        return iPop(s) / b;
    }

    private static int iRem(State s) {
        int b = iPop(s);
        return iPop(s) % b;
    }

    private static long lMul(State s) {
        long b = lPop(s);
        return lPop(s) * b;
    }

    private static long lDiv(State s) {
        long b = lPop(s);
        return lPop(s) / b;
    }

    private static long lRem(State s) {
        long b = lPop(s);
        return lPop(s) % b;
    }

    private static float fMul(State s) {
        float b = fPop(s);
        return fPop(s) * b;
    }

    private static float fDiv(State s) {
        float b = fPop(s);
        return fPop(s) / b;
    }

    private static float fRem(State s) {
        float b = fPop(s);
        return fPop(s) % b;
    }

    private static double dMul(State s) {
        double b = dPop(s);
        return dPop(s) * b;
    }

    private static double dDiv(State s) {
        double b = dPop(s);
        return dPop(s) / b;
    }

    private static double dRem(State s) {
        double b = dPop(s);
        return dPop(s) % b;
    }

    private static int fcmp(float a, float b, boolean nanLess) {
        if (Float.isNaN(a) || Float.isNaN(b)) {
            return nanLess ? -1 : 1;
        }
        return Float.compare(a, b);
    }

    private static int dcmp(double a, double b, boolean nanLess) {
        if (Double.isNaN(a) || Double.isNaN(b)) {
            return nanLess ? -1 : 1;
        }
        return Double.compare(a, b);
    }

    private static int slotSize(Class<?> c) {
        return (c == long.class || c == double.class) ? 2 : 1;
    }

    /**
     * Pops {@code n} values and coerces each to the boxed form of its declared
     * parameter type so reflective invocation accepts them. JVM int-category
     * primitives (int/char/boolean/byte/short) are all stored as {@link Integer}
     * on the VM stack; {@link #coerceTo} re-boxes to what the reflective call needs.
     */
    private static Object[] popArgs(State s, Class<?>[] paramTypes) {
        Object[] argv = new Object[paramTypes.length];
        for (int i = paramTypes.length - 1; i >= 0; i--) {
            argv[i] = coerceTo(paramTypes[i], deref(s.pop()));
        }
        return argv;
    }

    /**
     * Converts a reflective result/argument to the JVM stack representation:
     * int-category primitives (char/boolean/byte/short) become {@link Integer},
     * so downstream {@code iPop} / arithmetic / comparisons see an int.
     */
    private static Object stackRep(Class<?> declared, Object v) {
        if (v == null) return null;
        if (declared == Character.TYPE) return Integer.valueOf((int) ((Character) v).charValue());
        if (declared == Boolean.TYPE) return Integer.valueOf(((Boolean) v).booleanValue() ? 1 : 0);
        if (declared == Byte.TYPE) return Integer.valueOf(((Byte) v).byteValue());
        if (declared == Short.TYPE) return Integer.valueOf(((Short) v).shortValue());
        if (declared == Integer.TYPE) return Integer.valueOf(((Number) v).intValue());
        if (declared == Long.TYPE) return Long.valueOf(((Number) v).longValue());
        if (declared == Float.TYPE) return Float.valueOf(((Number) v).floatValue());
        if (declared == Double.TYPE) return Double.valueOf(((Number) v).doubleValue());
        return v;
    }

    /** Re-boxes a VM stack value to the boxed form a reflective call/field-write expects. */
    private static Object coerceTo(Class<?> declared, Object v) {
        if (v == null) return null;
        if (declared == Character.TYPE) return v instanceof Character ? v : Character.valueOf((char) ((Number) v).intValue());
        if (declared == Boolean.TYPE) return v instanceof Boolean ? v : Boolean.valueOf(((Number) v).intValue() != 0);
        if (declared == Byte.TYPE) return v instanceof Byte ? v : Byte.valueOf((byte) ((Number) v).intValue());
        if (declared == Short.TYPE) return v instanceof Short ? v : Short.valueOf((short) ((Number) v).intValue());
        if (declared == Integer.TYPE) return v instanceof Integer ? v : Integer.valueOf(((Number) v).intValue());
        if (declared == Long.TYPE) return v instanceof Long ? v : Long.valueOf(((Number) v).longValue());
        if (declared == Float.TYPE) return v instanceof Float ? v : Float.valueOf(((Number) v).floatValue());
        if (declared == Double.TYPE) return v instanceof Double ? v : Double.valueOf(((Number) v).doubleValue());
        return v;
    }

    private static Object deref(Object o) {
        if (o instanceof Uninitialized) {
            return ((Uninitialized) o).instance;
        }
        return o;
    }

    /** Placeholder pushed by NEW; materialized when INVOKESPECIAL &lt;init&gt; runs. */
    private static final class Uninitialized {
        final Class<?> type;
        Object instance;

        Uninitialized(Class<?> type) {
            this.type = type;
        }
    }

    // ---- checked-exception wrappers for reflection ----
    private static Object fieldGet(Field f, Object o) {
        try {
            return f.get(o);
        } catch (IllegalAccessException e) {
            throw new BfVmException("field access failed: " + f, e);
        }
    }

    private static void fieldSet(Field f, Object o, Object v) {
        try {
            // Central safety net: an Uninitialized placeholder must never reach
            // reflection (see PUTSTATIC). deref() is a no-op for ordinary values.
            f.set(deref(o), deref(v));
        } catch (IllegalAccessException e) {
            throw new BfVmException("field write failed: " + f, e);
        }
    }

    private static Object methodInvoke(Method m, Object recv, Object[] argv) {
        // JDK 17+: Object.clone() is `protected native` in java.base and cannot
        // be made accessible to the unnamed module. Array clone() is exactly what
        // enum values() / defensive copies use; reproduce it with a shallow copy
        // (same semantics) instead of failing with InaccessibleObjectException.
        if ("clone".equals(m.getName()) && recv != null && recv.getClass().isArray()
                && (argv == null || argv.length == 0)) {
            Class<?> comp = recv.getClass().getComponentType();
            int len = java.lang.reflect.Array.getLength(recv);
            Object copy = java.lang.reflect.Array.newInstance(comp, len);
            System.arraycopy(recv, 0, copy, 0, len);
            return copy;
        }
        try {
            return m.invoke(recv, argv);
        } catch (IllegalAccessException e) {
            throw new BfVmException("method invoke failed: " + m, e);
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw asUnchecked(e.getCause());
        }
    }

    private static Object ctorNew(Constructor<?> ct, Object[] argv) {
        try {
            return ct.newInstance(argv);
        } catch (InstantiationException | IllegalAccessException e) {
            throw new BfVmException("constructor failed: " + ct, e);
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw asUnchecked(e.getCause());
        }
    }

    private static RuntimeException asUnchecked(Throwable t) {
        if (t instanceof RuntimeException) {
            return (RuntimeException) t;
        }
        if (t instanceof Error) {
            throw (Error) t;
        }
        // Invoked Java code threw a checked exception: rethrow the ORIGINAL
        // instance so the interpreted caller's exception table can match it by
        // type (KBox's exception-relay carriers are Throwable subclasses that are
        // neither RuntimeException nor Error).
        sneakyThrow(t);
        return null; // unreachable
    }

    /** Throws any Throwable without a checked-exception declaration. */
    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void sneakyThrow(Throwable t) throws T {
        throw (T) t;
    }

    // ---- reflection resolution ----
    private static Class<?> resolveClass(String internalName, ClassLoader loader) {
        String dotted = internalName.replace('/', '.');
        try {
            return Class.forName(dotted, false, loader);
        } catch (ClassNotFoundException e) {
            try {
                return Class.forName(dotted);
            } catch (ClassNotFoundException e2) {
                throw new BfVmException("cannot resolve class " + internalName, e2);
            }
        }
    }

    private static Field findField(Class<?> c, String name) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            try {
                Field f = k.getDeclaredField(name);
                // JDK 17+ module system: java.base is not open to the unnamed
                // module, so setAccessible on e.g. a protected JDK field throws
                // InaccessibleObjectException. Public fields still work.
                try { f.setAccessible(true); } catch (RuntimeException ignored) { }
                return f;
            } catch (NoSuchFieldException e) {
                // continue up the hierarchy
            }
        }
        // Interface constants (e.g. a static final field declared on an interface
        // implemented by a superclass) are legal GETSTATIC targets.
        for (Class<?> iface : allInterfaces(c)) {
            try {
                Field f = iface.getDeclaredField(name);
                try { f.setAccessible(true); } catch (RuntimeException ignored) { }
                return f;
            } catch (NoSuchFieldException ignored) {
            }
        }
        throw new BfVmException("field not found: " + c.getName() + "." + name);
    }

    private static Method findMethod(Class<?> c, String name, String desc, boolean isStatic) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            for (Method m : k.getDeclaredMethods()) {
                if (m.getName().equals(name)
                        && MethodType.methodType(m.getReturnType(), m.getParameterTypes())
                                .toMethodDescriptorString().equals(desc)
                        && Modifier.isStatic(m.getModifiers()) == isStatic) {
                    // Object.clone() is protected in java.base and cannot be made
                    // accessible; methodInvoke() reproduces array clone() itself.
                    try { m.setAccessible(true); } catch (RuntimeException ignored) { }
                    return m;
                }
            }
        }
        for (Class<?> iface : allInterfaces(c)) {
            for (Method m : iface.getDeclaredMethods()) {
                if (m.getName().equals(name)
                        && MethodType.methodType(m.getReturnType(), m.getParameterTypes())
                                .toMethodDescriptorString().equals(desc)
                        && Modifier.isStatic(m.getModifiers()) == isStatic) {
                    try { m.setAccessible(true); } catch (RuntimeException ignored) { }
                    return m;
                }
            }
        }
        throw new BfVmException("method not found: " + c.getName() + "." + name + desc);
    }

    private static Constructor<?> findConstructor(Class<?> c, String desc) {
        for (Constructor<?> ct : c.getDeclaredConstructors()) {
            if (MethodType.methodType(void.class, ct.getParameterTypes())
                    .toMethodDescriptorString().equals(desc)) {
                try { ct.setAccessible(true); } catch (RuntimeException ignored) { }
                return ct;
            }
        }
        throw new BfVmException("constructor not found: " + c.getName() + desc);
    }

    private static Set<Class<?>> allInterfaces(Class<?> c) {
        Set<Class<?>> out = new HashSet<>();
        Deque<Class<?>> q = new ArrayDeque<>();
        // Interfaces of EVERY superclass, not just the runtime class: Guava's
        // SingletonImmutableList extends ImmutableList (a class) which implements
        // List/Collection, so Collection#stream (a default method) is only
        // reachable through a superclass' interface list.
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            q.addAll(Arrays.asList(k.getInterfaces()));
        }
        while (!q.isEmpty()) {
            Class<?> i = q.poll();
            if (!out.add(i)) {
                continue;
            }
            q.addAll(Arrays.asList(i.getInterfaces()));
        }
        return out;
    }

    /** Operand stack with JVM category awareness for the dup/pop family. */
    private static final class State {
        Object[] stack = new Object[256];
        int sp;

        void push(Object v) {
            if (sp == stack.length) {
                stack = Arrays.copyOf(stack, stack.length * 2);
            }
            stack[sp++] = v;
        }

        /** 异常进入 handler 时清空操作数栈（JVM 语义）。 */
        void clear() {
            Arrays.fill(stack, 0, sp, null);
            sp = 0;
        }

        Object pop() {
            if (sp == 0) {
                throw new BfVmException("operand stack underflow");
            }
            return stack[--sp];
        }

        boolean cat2Top() {
            Object t = stack[sp - 1];
            return t instanceof Long || t instanceof Double;
        }

        void dup() {
            push(stack[sp - 1]);
        }

        void dupX1() {
            Object a = stack[sp - 1];
            Object b = stack[sp - 2];
            stack[sp - 2] = a;
            stack[sp - 1] = b;
            push(a);
        }

        void dupX2() {
            Object a = stack[sp - 1];
            Object b = stack[sp - 2];
            if (b instanceof Long || b instanceof Double) {
                stack[sp - 2] = a;
                stack[sp - 1] = b;
                push(a);
            } else {
                Object c = stack[sp - 3];
                stack[sp - 3] = a;
                stack[sp - 2] = c;
                stack[sp - 1] = b;
                push(a);
            }
        }

        void dup2() {
            Object a = stack[sp - 1];
            if (a instanceof Long || a instanceof Double) {
                push(a);
            } else {
                Object b = stack[sp - 2];
                push(b);
                push(a);
            }
        }

        void dup2X1() {
            Object a = stack[sp - 1];
            Object b = stack[sp - 2];
            Object c = stack[sp - 3];
            stack[sp - 3] = b;
            stack[sp - 2] = a;
            stack[sp - 1] = c;
            push(b);
            push(a);
        }

        void dup2X2() {
            Object a = stack[sp - 1];
            if (a instanceof Long || a instanceof Double) {
                push(a);
                return;
            }
            Object b = stack[sp - 2];
            if (b instanceof Long || b instanceof Double) {
                stack[sp - 2] = a;
                stack[sp - 1] = b;
                push(a);
                return;
            }
            Object c = stack[sp - 3];
            if (c instanceof Long || c instanceof Double) {
                stack[sp - 3] = b;
                stack[sp - 2] = a;
                stack[sp - 1] = c;
                push(b);
                push(a);
                return;
            }
            Object d = stack[sp - 4];
            stack[sp - 4] = b;
            stack[sp - 3] = a;
            stack[sp - 2] = d;
            stack[sp - 1] = c;
            push(b);
            push(a);
        }

        void swap() {
            Object a = stack[sp - 1];
            stack[sp - 1] = stack[sp - 2];
            stack[sp - 2] = a;
        }

        void pop2() {
            if (cat2Top()) {
                if (sp < 1) {
                    throw new BfVmException("operand stack underflow (pop2)");
                }
                sp--;
            } else {
                if (sp < 2) {
                    throw new BfVmException("operand stack underflow (pop2)");
                }
                sp -= 2;
            }
        }
    }

    /** Cursor over the BFVM stream with big-endian readers. */
    private static final class Cursor {
        final byte[] b;
        int pc;

        Cursor(byte[] b, int pc) {
            this.b = b;
            this.pc = pc;
        }

        int u8() {
            return b[pc++] & 0xFF;
        }

        int u16() {
            int v = (b[pc] & 0xFF) << 8 | (b[pc + 1] & 0xFF);
            pc += 2;
            return v;
        }

        int i32() {
            int v = (b[pc] & 0xFF) << 24
                    | (b[pc + 1] & 0xFF) << 16
                    | (b[pc + 2] & 0xFF) << 8
                    | (b[pc + 3] & 0xFF);
            pc += 4;
            return v;
        }

        long i64() {
            long v = 0;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (b[pc + i] & 0xFF);
            }
            pc += 8;
            return v;
        }

        int[] i32s(int n) {
            int[] r = new int[n];
            for (int i = 0; i < n; i++) {
                r[i] = i32();
            }
            return r;
        }

        String utf8() {
            int len = (b[pc] & 0xFF) << 8 | (b[pc + 1] & 0xFF);
            String s = new String(b, pc + 2, len, StandardCharsets.UTF_8);
            pc += 2 + len;
            return s;
        }

        String[] ref() {
            return new String[]{utf8(), utf8(), utf8()};
        }
    }
}
