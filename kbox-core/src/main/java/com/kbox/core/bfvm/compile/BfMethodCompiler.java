package com.kbox.core.bfvm.compile;

import com.kbox.core.bfvm.BfVmException;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Translates a JVM method body (ASM {@link MethodNode}) into the compact BFVM instruction
 * stream. The stream is later turned into a Brainfuck program by {@link BfProgramWriter}.
 *
 * <p>v1 scope: no exception handlers (methods containing try/catch are rejected), no
 * INVOKEDYNAMIC / MULTIANEWARRAY / JSR / RET / monitor instructions. Everything else
 * commonly produced by javac is supported.
 */
public final class BfMethodCompiler {
    private BfMethodCompiler() {
    }

    /** {@code true} when the method body uses any opcode BFVM cannot translate. */
    public static boolean isSupported(MethodNode mn) {
        if (!mn.tryCatchBlocks.isEmpty()) {
            return false;
        }
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            int op = n.getOpcode();
            switch (op) {
                case Opcodes.MONITORENTER:
                case Opcodes.MONITOREXIT:
                case Opcodes.JSR:
                case Opcodes.RET:
                case Opcodes.INVOKEDYNAMIC:
                case Opcodes.MULTIANEWARRAY:
                    return false;
                default:
                    break;
            }
        }
        return true;
    }

    public static byte[] compile(MethodNode mn, String owner) {
        if (!mn.tryCatchBlocks.isEmpty()) {
            throw new UnsupportedOperationException(
                    "method has exception handlers (unsupported in v1): " + mn.name + mn.desc);
        }
        ByteWriter w = new ByteWriter();
        w.u16(Math.max(mn.maxLocals, 1));
        w.utf8(mn.desc); // parameter layout so the VM can mirror JVM local slots
        Map<LabelNode, Integer> labels = new HashMap<>();
        List<Patch> patches = new ArrayList<>();
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof LabelNode) {
                labels.put((LabelNode) n, w.size());
                continue;
            }
            if (n instanceof LineNumberNode || n instanceof FrameNode) {
                continue;
            }
            emit(n, w, labels, patches);
        }
        for (Patch p : patches) {
            Integer target = labels.get(p.label);
            if (target == null) {
                throw new BfVmException("unresolved branch target label");
            }
            w.patchI32(p.offset, target);
        }
        return w.toByteArray();
    }

    private static void emit(AbstractInsnNode n, ByteWriter w,
                             Map<LabelNode, Integer> labels, List<Patch> patches) {
        int op = n.getOpcode();
        switch (op) {
            case Opcodes.NOP:
                w.u8(Opcode.NOP);
                break;

            case Opcodes.ACONST_NULL:
                w.u8(Opcode.ACONST_NULL);
                break;

            case Opcodes.ICONST_M1:
                w.u8(Opcode.CONST_INT);
                w.i32(-1);
                break;
            case Opcodes.ICONST_0:
            case Opcodes.ICONST_1:
            case Opcodes.ICONST_2:
            case Opcodes.ICONST_3:
            case Opcodes.ICONST_4:
            case Opcodes.ICONST_5:
                w.u8(Opcode.CONST_INT);
                w.i32(op - Opcodes.ICONST_0);
                break;

            case Opcodes.LCONST_0:
                w.u8(Opcode.CONST_LONG);
                w.i64(0L);
                break;
            case Opcodes.LCONST_1:
                w.u8(Opcode.CONST_LONG);
                w.i64(1L);
                break;

            case Opcodes.FCONST_0:
                w.u8(Opcode.CONST_FLOAT);
                w.i32(Float.floatToIntBits(0.0f));
                break;
            case Opcodes.FCONST_1:
                w.u8(Opcode.CONST_FLOAT);
                w.i32(Float.floatToIntBits(1.0f));
                break;
            case Opcodes.FCONST_2:
                w.u8(Opcode.CONST_FLOAT);
                w.i32(Float.floatToIntBits(2.0f));
                break;

            case Opcodes.DCONST_0:
                w.u8(Opcode.CONST_DOUBLE);
                w.i64(Double.doubleToLongBits(0.0d));
                break;
            case Opcodes.DCONST_1:
                w.u8(Opcode.CONST_DOUBLE);
                w.i64(Double.doubleToLongBits(1.0d));
                break;

            case Opcodes.BIPUSH:
            case Opcodes.SIPUSH:
                w.u8(Opcode.CONST_INT);
                w.i32(((IntInsnNode) n).operand);
                break;

            case Opcodes.LDC: {
                Object cst = ((LdcInsnNode) n).cst;
                if (cst instanceof Integer) {
                    w.u8(Opcode.CONST_INT);
                    w.i32(((Integer) cst).intValue());
                } else if (cst instanceof Long) {
                    w.u8(Opcode.CONST_LONG);
                    w.i64(((Long) cst).longValue());
                } else if (cst instanceof Float) {
                    w.u8(Opcode.CONST_FLOAT);
                    w.i32(Float.floatToIntBits(((Float) cst).floatValue()));
                } else if (cst instanceof Double) {
                    w.u8(Opcode.CONST_DOUBLE);
                    w.i64(Double.doubleToLongBits(((Double) cst).doubleValue()));
                } else if (cst instanceof String) {
                    w.u8(Opcode.CONST_STRING);
                    w.utf8((String) cst);
                } else if (cst instanceof Type) {
                    w.u8(Opcode.CONST_CLASS);
                    w.utf8(((Type) cst).getInternalName());
                } else {
                    throw new UnsupportedOperationException(
                            "unsupported LDC constant " + cst.getClass().getName());
                }
                break;
            }

            case Opcodes.ILOAD:
            case Opcodes.LLOAD:
            case Opcodes.FLOAD:
            case Opcodes.DLOAD:
            case Opcodes.ALOAD:
                w.u8(Opcode.ILOAD + (op - Opcodes.ILOAD));
                w.u8(((VarInsnNode) n).var);
                break;
            case Opcodes.ISTORE:
            case Opcodes.LSTORE:
            case Opcodes.FSTORE:
            case Opcodes.DSTORE:
            case Opcodes.ASTORE:
                w.u8(Opcode.ISTORE + (op - Opcodes.ISTORE));
                w.u8(((VarInsnNode) n).var);
                break;
            case Opcodes.IINC: {
                IincInsnNode i = (IincInsnNode) n;
                w.u8(Opcode.IINC);
                w.u8(i.var);
                w.u8((byte) i.incr);
                break;
            }

            // Arithmetic / shifts / bitwise / conversions / comparisons / stack / returns /
            // array loads & stores / ARRAYLENGTH / ATHROW: numeric values equal the JVM opcode.
            case Opcodes.IADD:
            case Opcodes.ISUB:
            case Opcodes.IMUL:
            case Opcodes.IDIV:
            case Opcodes.IREM:
            case Opcodes.INEG:
            case Opcodes.LADD:
            case Opcodes.LSUB:
            case Opcodes.LMUL:
            case Opcodes.LDIV:
            case Opcodes.LREM:
            case Opcodes.LNEG:
            case Opcodes.FADD:
            case Opcodes.FSUB:
            case Opcodes.FMUL:
            case Opcodes.FDIV:
            case Opcodes.FREM:
            case Opcodes.FNEG:
            case Opcodes.DADD:
            case Opcodes.DSUB:
            case Opcodes.DMUL:
            case Opcodes.DDIV:
            case Opcodes.DREM:
            case Opcodes.DNEG:
            case Opcodes.ISHL:
            case Opcodes.ISHR:
            case Opcodes.IUSHR:
            case Opcodes.LSHL:
            case Opcodes.LSHR:
            case Opcodes.LUSHR:
            case Opcodes.IAND:
            case Opcodes.IOR:
            case Opcodes.IXOR:
            case Opcodes.LAND:
            case Opcodes.LOR:
            case Opcodes.LXOR:
            case Opcodes.I2L:
            case Opcodes.I2F:
            case Opcodes.I2D:
            case Opcodes.L2I:
            case Opcodes.L2F:
            case Opcodes.L2D:
            case Opcodes.F2I:
            case Opcodes.F2L:
            case Opcodes.F2D:
            case Opcodes.D2I:
            case Opcodes.D2L:
            case Opcodes.D2F:
            case Opcodes.I2B:
            case Opcodes.I2C:
            case Opcodes.I2S:
            case Opcodes.LCMP:
            case Opcodes.FCMPL:
            case Opcodes.FCMPG:
            case Opcodes.DCMPL:
            case Opcodes.DCMPG:
            case Opcodes.POP:
            case Opcodes.POP2:
            case Opcodes.DUP:
            case Opcodes.DUP_X1:
            case Opcodes.DUP_X2:
            case Opcodes.DUP2:
            case Opcodes.DUP2_X1:
            case Opcodes.DUP2_X2:
            case Opcodes.SWAP:
            case Opcodes.IRETURN:
            case Opcodes.LRETURN:
            case Opcodes.FRETURN:
            case Opcodes.DRETURN:
            case Opcodes.ARETURN:
            case Opcodes.RETURN:
            case Opcodes.IALOAD:
            case Opcodes.LALOAD:
            case Opcodes.FALOAD:
            case Opcodes.DALOAD:
            case Opcodes.AALOAD:
            case Opcodes.BALOAD:
            case Opcodes.CALOAD:
            case Opcodes.SALOAD:
            case Opcodes.IASTORE:
            case Opcodes.LASTORE:
            case Opcodes.FASTORE:
            case Opcodes.DASTORE:
            case Opcodes.AASTORE:
            case Opcodes.BASTORE:
            case Opcodes.CASTORE:
            case Opcodes.SASTORE:
            case Opcodes.ARRAYLENGTH:
            case Opcodes.ATHROW:
                w.u8(op);
                break;

            case Opcodes.IFEQ:
            case Opcodes.IFNE:
            case Opcodes.IFLT:
            case Opcodes.IFGE:
            case Opcodes.IFGT:
            case Opcodes.IFLE:
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ:
            case Opcodes.IF_ACMPNE:
            case Opcodes.IFNULL:
            case Opcodes.IFNONNULL:
            case Opcodes.GOTO:
                branch(w, patches, mapBranch(op), ((JumpInsnNode) n).label);
                break;

            case Opcodes.TABLESWITCH: {
                TableSwitchInsnNode t = (TableSwitchInsnNode) n;
                w.u8(Opcode.TABLESWITCH);
                patches.add(new Patch(w.size(), t.dflt));
                w.i32(0);
                w.i32(t.min);
                w.i32(t.max);
                for (LabelNode l : t.labels) {
                    patches.add(new Patch(w.size(), l));
                    w.i32(0);
                }
                break;
            }
            case Opcodes.LOOKUPSWITCH: {
                LookupSwitchInsnNode l = (LookupSwitchInsnNode) n;
                w.u8(Opcode.LOOKUPSWITCH);
                patches.add(new Patch(w.size(), l.dflt));
                w.i32(0);
                w.i32(l.keys.size());
                for (int i = 0; i < l.keys.size(); i++) {
                    w.i32(l.keys.get(i));
                    patches.add(new Patch(w.size(), l.labels.get(i)));
                    w.i32(0);
                }
                break;
            }

            case Opcodes.NEW:
            case Opcodes.ANEWARRAY:
            case Opcodes.CHECKCAST:
            case Opcodes.INSTANCEOF:
                w.u8(mapTypeOp(op));
                w.utf8(((TypeInsnNode) n).desc);
                break;

            case Opcodes.NEWARRAY:
                w.u8(Opcode.NEWARRAY);
                w.u8(((IntInsnNode) n).operand);
                break;

            case Opcodes.GETSTATIC:
            case Opcodes.PUTSTATIC:
            case Opcodes.GETFIELD:
            case Opcodes.PUTFIELD: {
                FieldInsnNode f = (FieldInsnNode) n;
                w.u8(mapFieldOp(op));
                w.ref(f.owner, f.name, f.desc);
                break;
            }
            case Opcodes.INVOKEVIRTUAL:
            case Opcodes.INVOKESPECIAL:
            case Opcodes.INVOKESTATIC:
            case Opcodes.INVOKEINTERFACE: {
                MethodInsnNode m = (MethodInsnNode) n;
                w.u8(mapInvokeOp(op));
                w.ref(m.owner, m.name, m.desc);
                break;
            }

            default:
                throw new UnsupportedOperationException("unsupported opcode " + opcodeName(op));
        }
    }

    private static void branch(ByteWriter w, List<Patch> patches, int opcode, LabelNode label) {
        w.u8(opcode);
        patches.add(new Patch(w.size(), label));
        w.i32(0);
    }

    private static int mapBranch(int op) {
        switch (op) {
            case Opcodes.IFEQ: return Opcode.IFEQ;
            case Opcodes.IFNE: return Opcode.IFNE;
            case Opcodes.IFLT: return Opcode.IFLT;
            case Opcodes.IFGE: return Opcode.IFGE;
            case Opcodes.IFGT: return Opcode.IFGT;
            case Opcodes.IFLE: return Opcode.IFLE;
            case Opcodes.IF_ICMPEQ: return Opcode.IF_ICMPEQ;
            case Opcodes.IF_ICMPNE: return Opcode.IF_ICMPNE;
            case Opcodes.IF_ICMPLT: return Opcode.IF_ICMPLT;
            case Opcodes.IF_ICMPGE: return Opcode.IF_ICMPGE;
            case Opcodes.IF_ICMPGT: return Opcode.IF_ICMPGT;
            case Opcodes.IF_ICMPLE: return Opcode.IF_ICMPLE;
            case Opcodes.IF_ACMPEQ: return Opcode.IF_ACMPEQ;
            case Opcodes.IF_ACMPNE: return Opcode.IF_ACMPNE;
            case Opcodes.IFNULL: return Opcode.IFNULL;
            case Opcodes.IFNONNULL: return Opcode.IFNONNULL;
            case Opcodes.GOTO: return Opcode.GOTO;
            default: throw new BfVmException("not a branch: " + op);
        }
    }

    private static int mapTypeOp(int op) {
        switch (op) {
            case Opcodes.NEW: return Opcode.NEW;
            case Opcodes.ANEWARRAY: return Opcode.ANEWARRAY;
            case Opcodes.CHECKCAST: return Opcode.CHECKCAST;
            case Opcodes.INSTANCEOF: return Opcode.INSTANCEOF;
            default: throw new BfVmException("not a type op: " + op);
        }
    }

    private static int mapFieldOp(int op) {
        switch (op) {
            case Opcodes.GETSTATIC: return Opcode.GETSTATIC;
            case Opcodes.PUTSTATIC: return Opcode.PUTSTATIC;
            case Opcodes.GETFIELD: return Opcode.GETFIELD;
            case Opcodes.PUTFIELD: return Opcode.PUTFIELD;
            default: throw new BfVmException("not a field op: " + op);
        }
    }

    private static int mapInvokeOp(int op) {
        switch (op) {
            case Opcodes.INVOKEVIRTUAL: return Opcode.INVOKEVIRTUAL;
            case Opcodes.INVOKESPECIAL: return Opcode.INVOKESPECIAL;
            case Opcodes.INVOKESTATIC: return Opcode.INVOKESTATIC;
            case Opcodes.INVOKEINTERFACE: return Opcode.INVOKEINTERFACE;
            default: throw new BfVmException("not an invoke op: " + op);
        }
    }

    private static String opcodeName(int op) {
        switch (op) {
            case Opcodes.MONITORENTER: return "MONITORENTER";
            case Opcodes.MONITOREXIT: return "MONITOREXIT";
            case Opcodes.JSR: return "JSR";
            case Opcodes.RET: return "RET";
            case Opcodes.INVOKEDYNAMIC: return "INVOKEDYNAMIC";
            case Opcodes.MULTIANEWARRAY: return "MULTIANEWARRAY";
            default: return String.valueOf(op);
        }
    }

    private static final class Patch {
        final int offset;
        final LabelNode label;

        Patch(int offset, LabelNode label) {
            this.offset = offset;
            this.label = label;
        }
    }

    /** Growable big-endian byte buffer used while building the stream. */
    static final class ByteWriter {
        private byte[] buf = new byte[256];
        private int size;

        int size() {
            return size;
        }

        void u8(int v) {
            ensure(1);
            buf[size++] = (byte) v;
        }

        void u16(int v) {
            ensure(2);
            buf[size++] = (byte) (v >>> 8);
            buf[size++] = (byte) v;
        }

        void i32(int v) {
            ensure(4);
            buf[size++] = (byte) (v >>> 24);
            buf[size++] = (byte) (v >>> 16);
            buf[size++] = (byte) (v >>> 8);
            buf[size++] = (byte) v;
        }

        void i64(long v) {
            ensure(8);
            for (int i = 7; i >= 0; i--) {
                buf[size++] = (byte) (v >>> (8 * i));
            }
        }

        void utf8(String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            if (b.length > 0xFFFF) {
                throw new IllegalArgumentException("utf8 too long: " + s);
            }
            u16(b.length);
            ensure(b.length);
            System.arraycopy(b, 0, buf, size, b.length);
            size += b.length;
        }

        void ref(String owner, String name, String desc) {
            utf8(owner);
            utf8(name);
            utf8(desc);
        }

        void patchI32(int offset, int v) {
            buf[offset] = (byte) (v >>> 24);
            buf[offset + 1] = (byte) (v >>> 16);
            buf[offset + 2] = (byte) (v >>> 8);
            buf[offset + 3] = (byte) v;
        }

        byte[] toByteArray() {
            byte[] out = new byte[size];
            System.arraycopy(buf, 0, out, 0, size);
            return out;
        }

        private void ensure(int n) {
            if (size + n <= buf.length) {
                return;
            }
            int cap = buf.length;
            while (cap < size + n) {
                cap *= 2;
            }
            byte[] nb = new byte[cap];
            System.arraycopy(buf, 0, nb, 0, size);
            buf = nb;
        }
    }
}
