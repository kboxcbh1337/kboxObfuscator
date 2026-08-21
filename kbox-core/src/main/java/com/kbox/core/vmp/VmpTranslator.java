package com.kbox.core.vmp;

import com.kbox.core.KBoxException;
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

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Translates a JVM {@link MethodNode} into a {@code byte[]} VMP program plus a
 * constant-pool spec (resolved lazily at runtime by {@link com.kbox.runtime.VmpInterpreter}).
 *
 * <p>Algorithm:
 * <ol>
 *   <li>Compute label offsets via a first pass.</li>
 *   <li>Emit each JVM opcode as one or more VMP opcodes from {@link VmpOp}.
 *       Unsupported opcodes abort the translation (caller falls back).</li>
 *   <li>Serialize operands as fixed-width little-endian fields.</li>
 *   <li>Build the exception table from {@code mn.tryCatchBlocks}.</li>
 * </ol>
 *
 * The translator is conservative: any opcode not in {@link #SUPPORTED} causes
 * an {@link UnsupportedOpcodeException} so the caller can mark the method as
 * not-VMP-eligible.
 */
public final class VmpTranslator {

    private static final String TAG = "vmp";

    /** Thrown when a method contains an opcode we don't know how to translate. */
    public static final class UnsupportedOpcodeException extends RuntimeException {
        public final int opcode;
        public UnsupportedOpcodeException(int op) { super("Unsupported opcode: " + op); this.opcode = op; }
    }

    /** Result of a successful translation. */
    public static final class Result {
        public final byte[] code;
        public final Object[] cpRaw;
        public final int maxLocals;
        public final int maxStack;
        public final int argCount;
        public final int[][] exceptions; // [start,end,handler,catchTypeCp]
        /** ASM {@link Type#getSort()} of the method's return descriptor (BOOLEAN/BYTE/CHAR/SHORT/INT/...). */
        public final int retSort;
        public Result(byte[] code, Object[] cpRaw, int maxLocals, int maxStack,
                      int argCount, int[][] exceptions) {
            this(code, cpRaw, maxLocals, maxStack, argCount, exceptions,
                    Type.getReturnType("()V").getSort()); // default VOID; overridden by translate()
        }
        public Result(byte[] code, Object[] cpRaw, int maxLocals, int maxStack,
                      int argCount, int[][] exceptions, int retSort) {
            this.code = code; this.cpRaw = cpRaw;
            this.maxLocals = maxLocals; this.maxStack = maxStack;
            this.argCount = argCount; this.exceptions = exceptions;
            this.retSort = retSort;
        }
    }

    /** Returns true if every opcode in {@code mn} is supported. */
    public static boolean isSupported(MethodNode mn) {
        try {
            translate(mn);
            return true;
        } catch (UnsupportedOpcodeException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public static Result translate(MethodNode mn) {
        ConstantPool cp = new ConstantPool();
        // 1. Pre-scan: assign offsets to labels so we can emit them as ints.
        Map<LabelNode, Integer> labelPc = new HashMap<>();
        // We don't know final pc yet, so do a 2-pass: first pass records target labels.
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof JumpInsnNode) labelPc.put(((JumpInsnNode) n).label, 0);
        }
        // The dispatch will fix up real offsets at emit time. We use a placeholder scheme:
        // we record (label) -> pc by walking linearly and computing the byte length of each
        // emitted instruction (since each opcode has a known operand size).

        // 2. Emit.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Map<LabelNode, Integer> resolvedPc = new HashMap<>();
        List<int[]> fixups = new ArrayList<>(); // (outPos, label-idx) for GOTO/IFx
        Map<LabelNode, Integer> labelIdx = new HashMap<>();
        int lidx = 0;
        for (Map.Entry<LabelNode, Integer> e : labelPc.entrySet()) {
            labelIdx.put(e.getKey(), lidx++);
        }

        // Pass 1: compute pc of each label.
        int pc = 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof LabelNode) {
                resolvedPc.put((LabelNode) n, pc);
                continue;
            }
            if (n instanceof org.objectweb.asm.tree.LineNumberNode
                    || n instanceof org.objectweb.asm.tree.FrameNode) {
                continue; // debugging metadata occupies no bytecode
            }
            int len = emittedLength(n);
            if (len < 0) throw new UnsupportedOpcodeException(n.getOpcode());
            pc += len;
        }

        // Pass 2: emit bytes.
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof LabelNode) continue;
            if (n instanceof org.objectweb.asm.tree.LineNumberNode
                    || n instanceof org.objectweb.asm.tree.FrameNode) {
                continue;
            }
            emit(out, n, cp, resolvedPc);
        }
        out.write(VmpOp.END & 0xFF);

        // 3. Exception table.
        int[][] ex = null;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) {
            ex = new int[mn.tryCatchBlocks.size()][];
            for (int i = 0; i < mn.tryCatchBlocks.size(); i++) {
                org.objectweb.asm.tree.TryCatchBlockNode tcb = mn.tryCatchBlocks.get(i);
                int start = resolvedPc.getOrDefault(tcb.start, 0);
                int end = resolvedPc.getOrDefault(tcb.end, pc);
                int handler = resolvedPc.getOrDefault(tcb.handler, 0);
                int catchCp = tcb.type == null ? -1 : cp.classRef(tcb.type);
                ex[i] = new int[]{start, end, handler, catchCp};
            }
        }

        return new Result(out.toByteArray(), cp.toArray(), mn.maxLocals, mn.maxStack,
                Type.getArgumentTypes(mn.desc).length, ex,
                Type.getReturnType(mn.desc).getSort());
    }

    // ---- emit ----

    private static void emit(ByteArrayOutputStream out, AbstractInsnNode n,
                             ConstantPool cp, Map<LabelNode, Integer> labelPc) {
        int op = n.getOpcode();
        if (op < 0) return; // LineNumberNode / FrameNode occupy no bytecode
        // ---- constants / loads ----
        if (n instanceof InsnNode) {
            switch (op) {
                case Opcodes.ACONST_NULL: out.write(VmpOp.ACONST_NULL & 0xFF); return;
                case Opcodes.ICONST_0: writeOp(out, VmpOp.ICONST, 0); return;
                case Opcodes.ICONST_1: writeOp(out, VmpOp.ICONST, 1); return;
                case Opcodes.ICONST_2: writeOp(out, VmpOp.ICONST, 2); return;
                case Opcodes.ICONST_3: writeOp(out, VmpOp.ICONST, 3); return;
                case Opcodes.ICONST_4: writeOp(out, VmpOp.ICONST, 4); return;
                case Opcodes.ICONST_5: writeOp(out, VmpOp.ICONST, 5); return;
                case Opcodes.ICONST_M1: writeOp(out, VmpOp.ICONST, -1); return;
                case Opcodes.LCONST_0: writeOp2(out, VmpOp.LCONST, 0, 0); return;
                case Opcodes.LCONST_1: writeOp2(out, VmpOp.LCONST, 0, 1); return;
                case Opcodes.FCONST_0: writeOp(out, VmpOp.FCONST, 0); return;
                case Opcodes.FCONST_1: writeOp(out, VmpOp.FCONST, 1); return;
                case Opcodes.FCONST_2: writeOp(out, VmpOp.FCONST, 2); return;
                case Opcodes.DCONST_0: writeOp2(out, VmpOp.DCONST, 0, 0); return;
                case Opcodes.DCONST_1: writeOp2(out, VmpOp.DCONST, 0, 1); return;

                case Opcodes.IADD: out.write(VmpOp.IADD & 0xFF); return;
                case Opcodes.ISUB: out.write(VmpOp.ISUB & 0xFF); return;
                case Opcodes.IMUL: out.write(VmpOp.IMUL & 0xFF); return;
                case Opcodes.IDIV: out.write(VmpOp.IDIV & 0xFF); return;
                case Opcodes.IREM: out.write(VmpOp.IREM & 0xFF); return;
                case Opcodes.INEG: out.write(VmpOp.INEG & 0xFF); return;
                case Opcodes.ISHL: out.write(VmpOp.ISHL & 0xFF); return;
                case Opcodes.ISHR: out.write(VmpOp.ISHR & 0xFF); return;
                case Opcodes.IUSHR: out.write(VmpOp.IUSHR & 0xFF); return;
                case Opcodes.IAND: out.write(VmpOp.IAND & 0xFF); return;
                case Opcodes.IOR: out.write(VmpOp.IOR & 0xFF); return;
                case Opcodes.IXOR: out.write(VmpOp.IXOR & 0xFF); return;

                case Opcodes.POP: out.write(VmpOp.POP & 0xFF); return;
                case Opcodes.POP2: out.write(VmpOp.POP2 & 0xFF); return;
                case Opcodes.DUP: out.write(VmpOp.DUP & 0xFF); return;
                case Opcodes.DUP_X1: out.write(VmpOp.DUP_X1 & 0xFF); return;
                case Opcodes.DUP_X2: out.write(VmpOp.DUP_X2 & 0xFF); return;
                case Opcodes.DUP2: out.write(VmpOp.DUP2 & 0xFF); return;
                case Opcodes.DUP2_X1: out.write(VmpOp.DUP2_X1 & 0xFF); return;
                case Opcodes.DUP2_X2: out.write(VmpOp.DUP2_X2 & 0xFF); return;
                case Opcodes.SWAP: out.write(VmpOp.SWAP & 0xFF); return;

                // --- Type conversions ---
                case Opcodes.I2L: out.write(VmpOp.I2L & 0xFF); return;
                case Opcodes.I2F: out.write(VmpOp.I2F & 0xFF); return;
                case Opcodes.I2D: out.write(VmpOp.I2D & 0xFF); return;
                case Opcodes.L2I: out.write(VmpOp.L2I & 0xFF); return;
                case Opcodes.L2F: out.write(VmpOp.L2F & 0xFF); return;
                case Opcodes.L2D: out.write(VmpOp.L2D & 0xFF); return;
                case Opcodes.F2I: out.write(VmpOp.F2I & 0xFF); return;
                case Opcodes.F2L: out.write(VmpOp.F2L & 0xFF); return;
                case Opcodes.F2D: out.write(VmpOp.F2D & 0xFF); return;
                case Opcodes.D2I: out.write(VmpOp.D2I & 0xFF); return;
                case Opcodes.D2L: out.write(VmpOp.D2L & 0xFF); return;
                case Opcodes.D2F: out.write(VmpOp.D2F & 0xFF); return;
                case Opcodes.I2B: out.write(VmpOp.I2B & 0xFF); return;
                case Opcodes.I2C: out.write(VmpOp.I2C & 0xFF); return;
                case Opcodes.I2S: out.write(VmpOp.I2S & 0xFF); return;

                // --- Long arithmetic ---
                case Opcodes.LADD: out.write(VmpOp.LADD & 0xFF); return;
                case Opcodes.LSUB: out.write(VmpOp.LSUB & 0xFF); return;
                case Opcodes.LMUL: out.write(VmpOp.LMUL & 0xFF); return;
                case Opcodes.LDIV: out.write(VmpOp.LDIV & 0xFF); return;
                case Opcodes.LREM: out.write(VmpOp.LREM & 0xFF); return;
                case Opcodes.LNEG: out.write(VmpOp.LNEG & 0xFF); return;
                case Opcodes.LSHL: out.write(VmpOp.LSHL & 0xFF); return;
                case Opcodes.LSHR: out.write(VmpOp.LSHR & 0xFF); return;
                case Opcodes.LUSHR: out.write(VmpOp.LUSHR & 0xFF); return;
                case Opcodes.LAND: out.write(VmpOp.LAND & 0xFF); return;
                case Opcodes.LOR: out.write(VmpOp.LOR & 0xFF); return;
                case Opcodes.LXOR: out.write(VmpOp.LXOR & 0xFF); return;
                case Opcodes.LCMP: out.write(VmpOp.LCMP & 0xFF); return;

                // --- Float/double arithmetic ---
                case Opcodes.FADD: out.write(VmpOp.FADD & 0xFF); return;
                case Opcodes.FSUB: out.write(VmpOp.FSUB & 0xFF); return;
                case Opcodes.FMUL: out.write(VmpOp.FMUL & 0xFF); return;
                case Opcodes.FDIV: out.write(VmpOp.FDIV & 0xFF); return;
                case Opcodes.FREM: out.write(VmpOp.FREM & 0xFF); return;
                case Opcodes.FNEG: out.write(VmpOp.FNEG & 0xFF); return;
                case Opcodes.DADD: out.write(VmpOp.DADD & 0xFF); return;
                case Opcodes.DSUB: out.write(VmpOp.DSUB & 0xFF); return;
                case Opcodes.DMUL: out.write(VmpOp.DMUL & 0xFF); return;
                case Opcodes.DDIV: out.write(VmpOp.DDIV & 0xFF); return;
                case Opcodes.DREM: out.write(VmpOp.DREM & 0xFF); return;
                case Opcodes.DNEG: out.write(VmpOp.DNEG & 0xFF); return;
                case Opcodes.FCMPL: out.write(VmpOp.FCMPL & 0xFF); return;
                case Opcodes.FCMPG: out.write(VmpOp.FCMPG & 0xFF); return;
                case Opcodes.DCMPL: out.write(VmpOp.DCMPL & 0xFF); return;
                case Opcodes.DCMPG: out.write(VmpOp.DCMPG & 0xFF); return;

                case Opcodes.ARRAYLENGTH: out.write(VmpOp.ARRAYLENGTH & 0xFF); return;
                case Opcodes.AALOAD: out.write(VmpOp.AALOAD & 0xFF); return;
                case Opcodes.AASTORE: out.write(VmpOp.AASTORE & 0xFF); return;
                case Opcodes.IALOAD: out.write(VmpOp.IALOAD & 0xFF); return;
                case Opcodes.IASTORE: out.write(VmpOp.IASTORE & 0xFF); return;
                case Opcodes.BALOAD: out.write(VmpOp.BALOAD & 0xFF); return;
                case Opcodes.BASTORE: out.write(VmpOp.BASTORE & 0xFF); return;
                case Opcodes.CALOAD: out.write(VmpOp.CALOAD & 0xFF); return;
                case Opcodes.CASTORE: out.write(VmpOp.CASTORE & 0xFF); return;
                case Opcodes.SALOAD: out.write(VmpOp.SALOAD & 0xFF); return;
                case Opcodes.SASTORE: out.write(VmpOp.SASTORE & 0xFF); return;

                case Opcodes.MONITORENTER: out.write(VmpOp.MONITORENTER & 0xFF); return;
                case Opcodes.MONITOREXIT: out.write(VmpOp.MONITOREXIT & 0xFF); return;
                case Opcodes.ATHROW: out.write(VmpOp.ATHROW & 0xFF); return;

                case Opcodes.IRETURN: out.write(VmpOp.IRETURN & 0xFF); return;
                case Opcodes.LRETURN: out.write(VmpOp.LRETURN & 0xFF); return;
                case Opcodes.FRETURN: out.write(VmpOp.FRETURN & 0xFF); return;
                case Opcodes.DRETURN: out.write(VmpOp.DRETURN & 0xFF); return;
                case Opcodes.ARETURN: out.write(VmpOp.ARETURN & 0xFF); return;
                case Opcodes.RETURN: out.write(VmpOp.RETURN & 0xFF); return;
                default: throw new UnsupportedOpcodeException(op);
            }
        }
        if (n instanceof IntInsnNode) {
            IntInsnNode i = (IntInsnNode) n;
            if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) {
                writeOp(out, VmpOp.ICONST, i.operand);
                return;
            }
            if (op == Opcodes.NEWARRAY) {
                writeOp(out, VmpOp.NEWARRAY, i.operand);
                return;
            }
            throw new UnsupportedOpcodeException(op);
        }
        if (n instanceof LdcInsnNode) {
            LdcInsnNode ldc = (LdcInsnNode) n;
            if (ldc.cst instanceof String) {
                writeOp(out, VmpOp.STRING, cp.stringRef((String) ldc.cst));
                return;
            }
            if (ldc.cst instanceof Type) {
                Type t = (Type) ldc.cst;
                writeOp(out, VmpOp.CLASS, cp.classRef(t.getInternalName()));
                return;
            }
            if (ldc.cst instanceof Integer) { writeOp(out, VmpOp.ICONST, (Integer) ldc.cst); return; }
            if (ldc.cst instanceof Float) { writeOp(out, VmpOp.FCONST, Float.floatToRawIntBits((Float) ldc.cst)); return; }
            if (ldc.cst instanceof Long) { long l = (Long) ldc.cst; writeOp2(out, VmpOp.LCONST, (int) (l >>> 32), (int) l); return; }
            if (ldc.cst instanceof Double) { long l = Double.doubleToRawLongBits((Double) ldc.cst); writeOp2(out, VmpOp.DCONST, (int) (l >>> 32), (int) l); return; }
            throw new UnsupportedOpcodeException(op);
        }
        if (n instanceof VarInsnNode) {
            VarInsnNode v = (VarInsnNode) n;
            switch (op) {
                case Opcodes.ILOAD: case Opcodes.ALOAD: writeOpU2(out, VmpOp.ILOAD, v.var); return;
                case Opcodes.LLOAD: case Opcodes.DLOAD: writeOpU2(out, VmpOp.LLOAD, v.var); return;
                case Opcodes.FLOAD: writeOpU2(out, VmpOp.FLOAD, v.var); return;
                case Opcodes.ISTORE: case Opcodes.ASTORE: writeOpU2(out, VmpOp.ISTORE, v.var); return;
                case Opcodes.LSTORE: case Opcodes.DSTORE: writeOpU2(out, VmpOp.LSTORE, v.var); return;
                case Opcodes.FSTORE: writeOpU2(out, VmpOp.FSTORE, v.var); return;
                default: throw new UnsupportedOpcodeException(op);
            }
        }
        if (n instanceof org.objectweb.asm.tree.IincInsnNode) {
            org.objectweb.asm.tree.IincInsnNode inc = (org.objectweb.asm.tree.IincInsnNode) n;
            out.write(VmpOp.IINC & 0xFF);
            writeU2(out, inc.var);
            writeInt(out, inc.incr);
            return;
        }
        if (n instanceof JumpInsnNode) {
            JumpInsnNode j = (JumpInsnNode) n;
            int target = labelPc.getOrDefault(j.label, 0);
            byte vop;
            switch (op) {
                case Opcodes.IFEQ: vop = VmpOp.IFEQ; break;
                case Opcodes.IFNE: vop = VmpOp.IFNE; break;
                case Opcodes.IFLT: vop = VmpOp.IFLT; break;
                case Opcodes.IFGE: vop = VmpOp.IFGE; break;
                case Opcodes.IFGT: vop = VmpOp.IFGT; break;
                case Opcodes.IFLE: vop = VmpOp.IFLE; break;
                case Opcodes.IF_ICMPEQ: vop = VmpOp.IF_ICMPEQ; break;
                case Opcodes.IF_ICMPNE: vop = VmpOp.IF_ICMPNE; break;
                case Opcodes.IF_ICMPLT: vop = VmpOp.IF_ICMPLT; break;
                case Opcodes.IF_ICMPGE: vop = VmpOp.IF_ICMPGE; break;
                case Opcodes.IF_ICMPGT: vop = VmpOp.IF_ICMPGT; break;
                case Opcodes.IF_ICMPLE: vop = VmpOp.IF_ICMPLE; break;
                case Opcodes.IFNULL: vop = VmpOp.IFNULL; break;
                case Opcodes.IFNONNULL: vop = VmpOp.IFNONNULL; break;
                case Opcodes.IF_ACMPEQ: vop = VmpOp.IF_ACMPEQ; break;
                case Opcodes.IF_ACMPNE: vop = VmpOp.IF_ACMPNE; break;
                case Opcodes.GOTO: vop = VmpOp.GOTO; break;
                default: throw new UnsupportedOpcodeException(op);
            }
            out.write(vop & 0xFF);
            writeInt(out, target);
            return;
        }
        if (n instanceof FieldInsnNode) {
            FieldInsnNode f = (FieldInsnNode) n;
            int idx = cp.memberRef(f.owner, f.name, f.desc);
            switch (op) {
                case Opcodes.GETSTATIC: writeOp(out, VmpOp.GETSTATIC, idx); return;
                case Opcodes.PUTSTATIC: writeOp(out, VmpOp.PUTSTATIC, idx); return;
                case Opcodes.GETFIELD: writeOp(out, VmpOp.GETFIELD, idx); return;
                case Opcodes.PUTFIELD: writeOp(out, VmpOp.PUTFIELD, idx); return;
                default: throw new UnsupportedOpcodeException(op);
            }
        }
        if (n instanceof MethodInsnNode) {
            MethodInsnNode m = (MethodInsnNode) n;
            int idx = cp.memberRef(m.owner, m.name, m.desc);
            switch (op) {
                case Opcodes.INVOKEVIRTUAL: writeOp(out, VmpOp.INVOKEVIRTUAL, idx); return;
                case Opcodes.INVOKESPECIAL: writeOp(out, VmpOp.INVOKESPECIAL, idx); return;
                case Opcodes.INVOKESTATIC: writeOp(out, VmpOp.INVOKESTATIC, idx); return;
                case Opcodes.INVOKEINTERFACE: writeOp(out, VmpOp.INVOKEINTERFACE, idx); return;
                default: throw new UnsupportedOpcodeException(op);
            }
        }
        if (n instanceof TypeInsnNode) {
            TypeInsnNode t = (TypeInsnNode) n;
            int idx = cp.classRef(t.desc);
            switch (op) {
                case Opcodes.NEW: writeOp(out, VmpOp.NEW, idx); return;
                case Opcodes.ANEWARRAY: writeOp(out, VmpOp.ANEWARRAY, idx); return;
                case Opcodes.CHECKCAST: writeOp(out, VmpOp.CHECKCAST, idx); return;
                case Opcodes.INSTANCEOF: writeOp(out, VmpOp.INSTANCEOF, idx); return;
                default: throw new UnsupportedOpcodeException(op);
            }
        }
        // Switches / invokedynamic / multi-new-array / line numbers unsupported.
        throw new UnsupportedOpcodeException(op);
    }

    private static int emittedLength(AbstractInsnNode n) {
        if (n instanceof LabelNode) return 0;
        int op = n.getOpcode();
        if (n instanceof InsnNode) {
            switch (op) {
                case Opcodes.ACONST_NULL: case Opcodes.IADD: case Opcodes.ISUB:
                case Opcodes.IMUL: case Opcodes.IDIV: case Opcodes.IREM: case Opcodes.INEG:
                case Opcodes.ISHL: case Opcodes.ISHR: case Opcodes.IUSHR:
                case Opcodes.IAND: case Opcodes.IOR: case Opcodes.IXOR:
                case Opcodes.POP: case Opcodes.POP2: case Opcodes.DUP: case Opcodes.DUP_X1:
                case Opcodes.DUP_X2: case Opcodes.DUP2: case Opcodes.DUP2_X1: case Opcodes.DUP2_X2:
                case Opcodes.SWAP:
                case Opcodes.ARRAYLENGTH: case Opcodes.AALOAD: case Opcodes.AASTORE:
                case Opcodes.IALOAD: case Opcodes.IASTORE:
                case Opcodes.BALOAD: case Opcodes.BASTORE:
                case Opcodes.CALOAD: case Opcodes.CASTORE:
                case Opcodes.SALOAD: case Opcodes.SASTORE:
                case Opcodes.MONITORENTER: case Opcodes.MONITOREXIT: case Opcodes.ATHROW:
                case Opcodes.IRETURN: case Opcodes.LRETURN: case Opcodes.FRETURN:
                case Opcodes.DRETURN: case Opcodes.ARETURN: case Opcodes.RETURN:
                // Type conversions
                case Opcodes.I2L: case Opcodes.I2F: case Opcodes.I2D:
                case Opcodes.L2I: case Opcodes.L2F: case Opcodes.L2D:
                case Opcodes.F2I: case Opcodes.F2L: case Opcodes.F2D:
                case Opcodes.D2I: case Opcodes.D2L: case Opcodes.D2F:
                case Opcodes.I2B: case Opcodes.I2C: case Opcodes.I2S:
                // Long arithmetic
                case Opcodes.LADD: case Opcodes.LSUB: case Opcodes.LMUL:
                case Opcodes.LDIV: case Opcodes.LREM: case Opcodes.LNEG:
                case Opcodes.LSHL: case Opcodes.LSHR: case Opcodes.LUSHR:
                case Opcodes.LAND: case Opcodes.LOR: case Opcodes.LXOR: case Opcodes.LCMP:
                // Float/double arithmetic
                case Opcodes.FADD: case Opcodes.FSUB: case Opcodes.FMUL:
                case Opcodes.FDIV: case Opcodes.FREM: case Opcodes.FNEG:
                case Opcodes.DADD: case Opcodes.DSUB: case Opcodes.DMUL:
                case Opcodes.DDIV: case Opcodes.DREM: case Opcodes.DNEG:
                case Opcodes.FCMPL: case Opcodes.FCMPG:
                case Opcodes.DCMPL: case Opcodes.DCMPG:
                    return 1;
                case Opcodes.ICONST_0: case Opcodes.ICONST_1: case Opcodes.ICONST_2:
                case Opcodes.ICONST_3: case Opcodes.ICONST_4: case Opcodes.ICONST_5:
                case Opcodes.ICONST_M1:
                    return 1 + 4;
                case Opcodes.LCONST_0: case Opcodes.LCONST_1:
                case Opcodes.DCONST_0: case Opcodes.DCONST_1:
                    return 1 + 8;
                case Opcodes.FCONST_0: case Opcodes.FCONST_1: case Opcodes.FCONST_2:
                    return 1 + 4;
                default: return -1;
            }
        }
        if (n instanceof IntInsnNode) {
            return 1 + 4;
        }
        if (n instanceof LdcInsnNode) {
            // Long/Double constants are emitted as op + 2 ints (9 bytes), not 5.
            Object cst = ((LdcInsnNode) n).cst;
            if (cst instanceof Long || cst instanceof Double) return 1 + 8;
            return 1 + 4;
        }
        if (n instanceof VarInsnNode) return 1 + 2;
        if (n instanceof org.objectweb.asm.tree.IincInsnNode) return 1 + 2 + 4;
        if (n instanceof JumpInsnNode) return 1 + 4;
        if (n instanceof FieldInsnNode) return 1 + 4;
        if (n instanceof MethodInsnNode) return 1 + 4;
        if (n instanceof TypeInsnNode) return 1 + 4;
        return -1;
    }

    private static void writeOp(ByteArrayOutputStream out, byte vop, int operand) {
        out.write(vop & 0xFF);
        writeInt(out, operand);
    }
    private static void writeOp2(ByteArrayOutputStream out, byte vop, int hi, int lo) {
        out.write(vop & 0xFF);
        writeInt(out, hi);
        writeInt(out, lo);
    }
    private static void writeOpU2(ByteArrayOutputStream out, byte vop, int operand) {
        out.write(vop & 0xFF);
        writeU2(out, operand);
    }
    private static void writeInt(ByteArrayOutputStream out, int v) {
        ByteBuffer b = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        b.putInt(v);
        out.write(b.array(), 0, 4);
    }
    private static void writeU2(ByteArrayOutputStream out, int v) {
        out.write((v >> 8) & 0xFF);
        out.write(v & 0xFF);
    }

    /** Simple constant pool: dedups member & class/string specs. */
    static final class ConstantPool {
        private final List<Object> items = new ArrayList<>();
        private final Map<String, Integer> index = new HashMap<>();
        int stringRef(String s) { return intern(s); }
        int classRef(String internal) { return intern(internal.replace('/', '.')); }
        int memberRef(String owner, String name, String desc) {
            return intern(owner.replace('/', '.') + "#" + name + "#" + desc);
        }
        private int intern(String s) {
            Integer i = index.get(s);
            if (i != null) return i;
            items.add(s);
            i = items.size() - 1;
            index.put(s, i);
            return i;
        }
        Object[] toArray() { return items.toArray(); }
    }
}
