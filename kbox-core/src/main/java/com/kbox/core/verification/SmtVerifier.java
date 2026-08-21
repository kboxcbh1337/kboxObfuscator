package com.kbox.core.verification;

import com.kbox.core.log.KBoxLog;

/**
 * Lightweight formal verification of VMP bytecode transformations using
 * symbolic-execution and constraint-checking concepts.
 *
 * <p>Since a full SMT solver (Z3) cannot be bundled, this class implements a
 * best-effort "symbolic execution + concrete folding" approach:
 * <ul>
 *   <li>Parse VMP bytecode streams into instruction sequences.</li>
 *   <li>Maintain a symbolic stack where each slot is either a concrete
 *       {@code int} or {@code Unknown}.</li>
 *   <li>Execute arithmetic concretely when both operands are known.</li>
 *   <li>Propagate unknowns through method calls, field accesses, and branches.</li>
 *   <li>Compare final concrete results at return points.</li>
 * </ul>
 *
 * <p>All verification is best-effort: failures log a warning but never abort
 * the build (mirroring {@code cfg.isNeverFail()} behaviour).
 *
 * <p>VMP opcode constants are replicated inline from {@code VmpOp} to avoid
 * circular dependencies between the {@code vmp} and {@code verification} packages.
 */
public final class SmtVerifier {

    private static final String TAG = "smt";

    private SmtVerifier() {}

    // ---------- VMP opcode constants (replicated from VmpOp) ----------

    // Constants / loads
    private static final byte ACONST_NULL = 0x01;
    private static final byte ICONST      = 0x02; // 1 int operand
    private static final byte LCONST      = 0x03; // 2 int operands
    private static final byte FCONST      = 0x04; // 1 int operand
    private static final byte DCONST      = 0x05; // 2 int operands
    private static final byte STRING      = 0x06; // 1 int operand
    private static final byte CLASS       = 0x07; // 1 int operand

    private static final byte ILOAD       = 0x10; // 1 u2 operand: var
    private static final byte LLOAD       = 0x11; // 1 u2 operand: var
    private static final byte FLOAD       = 0x12; // 1 u2 operand: var
    private static final byte DLOAD       = 0x13; // 1 u2 operand: var
    private static final byte ALOAD       = 0x14; // 1 u2 operand: var

    private static final byte ISTORE      = 0x18; // 1 u2 operand: var
    private static final byte LSTORE      = 0x19; // 1 u2 operand: var
    private static final byte FSTORE      = 0x1A; // 1 u2 operand: var
    private static final byte DSTORE      = 0x1B; // 1 u2 operand: var
    private static final byte ASTORE      = 0x1C; // 1 u2 operand: var

    // Integer arithmetic
    private static final byte IADD        = 0x20;
    private static final byte ISUB        = 0x21;
    private static final byte IMUL        = 0x22;
    private static final byte IDIV        = 0x23;
    private static final byte IREM        = 0x24;
    private static final byte INEG        = 0x25;
    private static final byte ISHL        = 0x26;
    private static final byte ISHR        = 0x27;
    private static final byte IUSHR       = 0x28;
    private static final byte IAND        = 0x29;
    private static final byte IOR         = 0x2A;
    private static final byte IXOR        = 0x2B;
    private static final byte IINC        = 0x2C; // 2 operands: u2 var, int delta

    // Type conversions
    private static final byte I2L         = 0x2D;
    private static final byte I2F         = 0x2E;
    private static final byte I2D         = 0x2F;
    private static final byte L2I         = (byte) 0xA0;
    private static final byte L2F         = (byte) 0xA1;
    private static final byte L2D         = (byte) 0xA2;
    private static final byte F2I         = (byte) 0xA3;
    private static final byte F2L         = (byte) 0xA4;
    private static final byte F2D         = (byte) 0xA5;
    private static final byte D2I         = (byte) 0xA6;
    private static final byte D2L         = (byte) 0xA7;
    private static final byte D2F         = (byte) 0xA8;
    private static final byte I2B         = (byte) 0xA9;
    private static final byte I2C         = (byte) 0xAA;
    private static final byte I2S         = (byte) 0xAB;

    // Long arithmetic
    private static final byte LCMP        = (byte) 0xAC;
    private static final byte LADD        = (byte) 0xAD;
    private static final byte LSUB        = (byte) 0xAE;
    private static final byte LMUL        = (byte) 0xAF;
    private static final byte LDIV        = (byte) 0xB0;
    private static final byte LREM        = (byte) 0xB1;
    private static final byte LNEG        = (byte) 0xB2;
    private static final byte LSHL        = (byte) 0xB3;
    private static final byte LSHR        = (byte) 0xB4;
    private static final byte LUSHR       = (byte) 0xB5;
    private static final byte LAND        = (byte) 0xB6;
    private static final byte LOR         = (byte) 0xB7;
    private static final byte LXOR        = (byte) 0xB8;

    // Float/double arithmetic
    private static final byte FADD        = (byte) 0xB9;
    private static final byte FSUB        = (byte) 0xBA;
    private static final byte FMUL        = (byte) 0xBB;
    private static final byte FDIV        = (byte) 0xBC;
    private static final byte FREM        = (byte) 0xBD;
    private static final byte FNEG        = (byte) 0xBE;
    private static final byte DADD        = (byte) 0xBF;
    private static final byte DSUB        = (byte) 0xC0;
    private static final byte DMUL        = (byte) 0xC1;
    private static final byte DDIV        = (byte) 0xC2;
    private static final byte DREM        = (byte) 0xC3;
    private static final byte DNEG        = (byte) 0xC4;
    private static final byte FCMPL       = (byte) 0xC5;
    private static final byte FCMPG       = (byte) 0xC6;
    private static final byte DCMPL       = (byte) 0xC7;
    private static final byte DCMPG       = (byte) 0xC8;

    // Comparison / branches
    private static final byte IFEQ        = 0x30;
    private static final byte IFNE        = 0x31;
    private static final byte IFLT        = 0x32;
    private static final byte IFGE        = 0x33;
    private static final byte IFGT        = 0x34;
    private static final byte IFLE        = 0x35;
    private static final byte IF_ICMPEQ   = 0x36;
    private static final byte IF_ICMPNE   = 0x37;
    private static final byte IF_ICMPLT   = 0x38;
    private static final byte IF_ICMPGE   = 0x39;
    private static final byte IF_ICMPGT   = 0x3A;
    private static final byte IF_ICMPLE   = 0x3B;
    private static final byte IFNULL      = 0x3C;
    private static final byte IFNONNULL   = 0x3D;
    private static final byte IF_ACMPEQ   = 0x3F;
    private static final byte IF_ACMPNE   = (byte) 0xC9;
    private static final byte GOTO        = 0x3E;

    // Stack manipulation
    private static final byte POP         = 0x40;
    private static final byte POP2        = 0x41;
    private static final byte DUP         = 0x42;
    private static final byte DUP_X1      = 0x43;
    private static final byte DUP_X2      = (byte) 0xCA;
    private static final byte DUP2        = (byte) 0xCB;
    private static final byte DUP2_X1     = (byte) 0xCC;
    private static final byte DUP2_X2     = (byte) 0xCD;
    private static final byte SWAP        = 0x44;

    // Field access
    private static final byte GETSTATIC   = 0x50;
    private static final byte PUTSTATIC   = 0x51;
    private static final byte GETFIELD    = 0x52;
    private static final byte PUTFIELD    = 0x53;

    // Method invocation
    private static final byte INVOKEVIRTUAL    = 0x60;
    private static final byte INVOKESPECIAL   = 0x61;
    private static final byte INVOKESTATIC     = 0x62;
    private static final byte INVOKEINTERFACE  = 0x63;

    // Type / new
    private static final byte NEW          = 0x70;
    private static final byte NEWARRAY    = 0x71;
    private static final byte ANEWARRAY    = 0x72;
    private static final byte ARRAYLENGTH  = 0x73;
    private static final byte AALOAD       = 0x74;
    private static final byte AASTORE      = 0x75;
    private static final byte IALOAD       = 0x76;
    private static final byte IASTORE      = 0x77;
    private static final byte BALOAD       = 0x7A;
    private static final byte BASTORE      = 0x7B;
    private static final byte CALOAD       = 0x7C;
    private static final byte CASTORE      = 0x7D;
    private static final byte SALOAD       = 0x7E;
    private static final byte SASTORE      = 0x7F;
    private static final byte CHECKCAST    = 0x78;
    private static final byte INSTANCEOF   = 0x79;

    // Synchronization / exceptions
    private static final byte MONITORENTER = (byte) 0x80;
    private static final byte MONITOREXIT  = (byte) 0x81;
    private static final byte ATHROW       = (byte) 0x82;

    // Returns
    private static final byte IRETURN      = (byte) 0x90;
    private static final byte LRETURN      = (byte) 0x91;
    private static final byte FRETURN      = (byte) 0x92;
    private static final byte DRETURN      = (byte) 0x93;
    private static final byte ARETURN      = (byte) 0x94;
    private static final byte RETURN       = (byte) 0x95;

    // Meta
    private static final byte FRAME        = (byte) 0xF0;
    private static final byte END          = (byte) 0xFF;

    // ---------- Public types ----------

    /** Result of a verification attempt. */
    public static final class VerificationResult {
        /** {@code true} if the two programs are semantically equivalent
         *  (or if equivalence could not be disproved). */
        public final boolean equivalent;
        /** Human-readable explanation when not equivalent. */
        public final String detail;
        /** Number of distinct checks executed during verification. */
        public final int checksRun;

        VerificationResult(boolean equivalent, String detail, int checksRun) {
            this.equivalent = equivalent;
            this.detail = detail;
            this.checksRun = checksRun;
        }
    }

    /** A value on the symbolic stack: either a known concrete {@code int} or unknown. */
    static final class SymbolicValue {
        final boolean concrete;
        final int value;

        SymbolicValue(boolean concrete, int value) {
            this.concrete = concrete;
            this.value = value;
        }

        static SymbolicValue concrete(int v) { return new SymbolicValue(true, v); }
        static SymbolicValue unknown() { return new SymbolicValue(false, 0); }

        @Override
        public String toString() {
            return concrete ? Integer.toString(value) : "?";
        }
    }

    // ---------- Instruction parsing ----------

    /**
     * Represents a single parsed VMP instruction: the opcode, its offset in
     * the byte stream, and for known operand-count instructions the raw operand bytes.
     */
    static final class ParsedInsn {
        final byte opcode;
        final int offset;
        final int operandCount; // number of int operand slots (0, 1, or 2)
        final int op0;          // first 4-byte int operand (or 2-byte u2 for var insns)
        final int op1;          // second 4-byte int operand (LCONST/DCONST/IINC delta)

        ParsedInsn(byte opcode, int offset, int operandCount, int op0, int op1) {
            this.opcode = opcode;
            this.offset = offset;
            this.operandCount = operandCount;
            this.op0 = op0;
            this.op1 = op1;
        }
    }

    /**
     * Returns the number of operand bytes for a given VMP opcode, or -1 if unrecognized.
     *
     * <p>Operand layout (from VmpTranslator.emittedLength):
     * <ul>
     *   <li>0 bytes: most InsnNode ops (IADD, POP, IRETURN, etc.)</li>
     *   <li>2 bytes (u2): ILOAD/ISTORE and other VarInsnNode ops</li>
     *   <li>4 bytes (int): ICONST, FCONST, branches, field, method, type</li>
     *   <li>8 bytes (2 ints): LCONST, DCONST</li>
     *   <li>6 bytes (u2 + int): IINC</li>
     *   <li>8 bytes (2 ints): FRAME (maxLocals, maxStack)</li>
     * </ul>
     */
    static int operandBytes(byte opcode) {
        int op = opcode & 0xFF;
        switch (op) {
            // 0-operand integer arithmetic
            case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
            case 0x26: case 0x27: case 0x28: case 0x29: case 0x2A: case 0x2B:
            // Stack manipulation
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44:
            // Returns
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
            // Monitor / throw
            case 0x80: case 0x81: case 0x82:
            // Array
            case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            // Type conversions (all opcodes in the range)
            case 0x2D: case 0x2E: case 0x2F:
            // Long arithmetic
            case 0xAC: case 0xAD: case 0xAE: case 0xAF: case 0xB0: case 0xB1:
            case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7: case 0xB8:
            // Float/double arithmetic
            case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE:
            case 0xBF: case 0xC0: case 0xC1: case 0xC2: case 0xC3: case 0xC4:
            case 0xC5: case 0xC6: case 0xC7: case 0xC8:
            // acmpne, dup2 variants
            case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD:
            // null const
            case 0x01:
                return 0;

            // VarInsnNode: ILOAD/ALOAD/FLOAD/LLOAD/DLOAD family and store family
            case 0x10: case 0x11: case 0x12: case 0x13: case 0x14:
            case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C:
                return 2;

            // 4-byte operand: ICONST, FCONST, STRING, CLASS, branches, fields, methods, type
            case 0x02: case 0x04: case 0x06: case 0x07:
            case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
            case 0x36: case 0x37: case 0x38: case 0x39: case 0x3A: case 0x3B:
            case 0x3C: case 0x3D: case 0x3E: case 0x3F:
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x60: case 0x61: case 0x62: case 0x63:
            case 0x70: case 0x71: case 0x72: case 0x78: case 0x79:
                return 4;

            // 8-byte operand (2 ints): LCONST, DCONST
            case 0x03: case 0x05:
                return 8;

            // IINC: u2 var + int delta = 6 bytes
            case 0x2C:
                return 6;

            // FRAME: 2 int operands = 8 bytes; END: 0 bytes
            case 0xF0:
                return 8;
            case 0xFF:
                return 0;

            default:
                return -1;
        }
    }

    /**
     * Returns true if the opcode is a terminal instruction (any *RETURN, ATHROW, or END).
     */
    static boolean isTerminal(byte opcode) {
        int op = opcode & 0xFF;
        return (op >= 0x90 && op <= 0x95) || op == 0x82 || op == 0xFF;
    }

    /**
     * Parses a VMP bytecode stream into a list of {@link ParsedInsn} entries.
     * Unknown opcodes are logged and skipped with a best-effort size estimate.
     */
    static java.util.List<ParsedInsn> parse(byte[] code) {
        java.util.List<ParsedInsn> insns = new java.util.ArrayList<>();
        if (code == null || code.length == 0) return insns;

        int i = 0;
        while (i < code.length) {
            byte op = code[i];
            int ob = operandBytes(op);
            if (ob < 0) {
                KBoxLog.warn(TAG, "Unknown opcode 0x" + Integer.toHexString(op & 0xFF)
                        + " at offset " + i + "; skipping 1 byte");
                insns.add(new ParsedInsn(op, i, 0, 0, 0));
                i++;
                continue;
            }

            if (ob == 0) {
                insns.add(new ParsedInsn(op, i, 0, 0, 0));
                i += 1;
            } else if (ob == 2) {
                int operand = readU2(code, i + 1);
                insns.add(new ParsedInsn(op, i, 1, operand, 0));
                i += 3;
            } else if (ob == 4) {
                int operand = readInt(code, i + 1);
                insns.add(new ParsedInsn(op, i, 1, operand, 0));
                i += 5;
            } else if (ob == 6) {
                int var = readU2(code, i + 1);
                int delta = readInt(code, i + 3);
                insns.add(new ParsedInsn(op, i, 2, var, delta));
                i += 7;
            } else if (ob == 8) {
                int hi = readInt(code, i + 1);
                int lo = readInt(code, i + 5);
                insns.add(new ParsedInsn(op, i, 2, hi, lo));
                i += 9;
            }
        }
        return insns;
    }

    // ---------- Symbolic execution engine ----------

    /**
     * Executes a sequence of parsed VMP instructions symbolically on a virtual
     * stack, folding concrete int operations where possible.
     *
     * <p>Execution stops at the first terminal instruction (RETURN/ATHROW/END).
     * The resulting top-of-stack value is returned. If execution encounters any
     * non-concrete operation (method call, field access, branch on unknown),
     * the returned value will be {@link SymbolicValue#unknown()}.
     *
     * @param insns    the parsed instruction list
     * @param maxStack estimated maximum stack depth (used for array sizing)
     * @param maxLocals estimated maximum local count
     * @return the symbolic result on top of stack at termination, or unknown
     */
    static SymbolicValue symbolicExecute(java.util.List<ParsedInsn> insns,
                                         int maxStack, int maxLocals) {
        int stackCap = Math.max(maxStack, 32);
        int localsCap = Math.max(maxLocals, 16);
        SymbolicValue[] stack = new SymbolicValue[stackCap];
        SymbolicValue[] locals = new SymbolicValue[localsCap];
        for (int j = 0; j < localsCap; j++) {
            locals[j] = SymbolicValue.unknown();
        }
        int sp = 0; // stack pointer (next free slot)

        for (int idx = 0; idx < insns.size(); idx++) {
            ParsedInsn p = insns.get(idx);
            byte op = p.opcode;
            int op8 = op & 0xFF;

            // ---- Constants ----
            if (op == ICONST) {
                if (sp < stackCap) stack[sp++] = SymbolicValue.concrete(p.op0);
            } else if (op == LCONST || op == DCONST) {
                // long/double occupy 2 slots -- we cannot concretely execute long ops,
                // mark both slots as unknown.
                if (sp + 1 < stackCap) {
                    stack[sp++] = SymbolicValue.unknown();
                    stack[sp++] = SymbolicValue.unknown();
                }
            } else if (op == FCONST) {
                if (sp < stackCap) stack[sp++] = SymbolicValue.concrete(p.op0);
            } else if (op == ACONST_NULL) {
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op == STRING || op == CLASS) {
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            }

            // ---- Loads ----
            else if (op == ILOAD || op == ALOAD) {
                int var = p.op0 & 0xFFFF;
                if (sp < stackCap && var < localsCap) stack[sp++] = locals[var];
            } else if (op == FLOAD) {
                int var = p.op0 & 0xFFFF;
                if (sp < stackCap && var < localsCap) stack[sp++] = locals[var];
            } else if (op == LLOAD || op == DLOAD) {
                int var = p.op0 & 0xFFFF;
                if (sp + 1 < stackCap && var < localsCap) {
                    stack[sp++] = locals[var];
                    stack[sp++] = SymbolicValue.unknown();
                }
            }

            // ---- Stores ----
            else if (op == ISTORE || op == ASTORE || op == FSTORE) {
                int var = p.op0 & 0xFFFF;
                SymbolicValue v = sp > 0 ? stack[--sp] : SymbolicValue.unknown();
                if (var < localsCap) locals[var] = v;
            } else if (op == LSTORE || op == DSTORE) {
                int var = p.op0 & 0xFFFF;
                if (sp >= 2) { sp -= 2; }
                if (var < localsCap) locals[var] = SymbolicValue.unknown();
            }

            // ---- Integer arithmetic ----
            else if (op == IADD || op == ISUB || op == IMUL || op == IDIV
                    || op == IREM || op == ISHL || op == ISHR || op == IUSHR
                    || op == IAND || op == IOR || op == IXOR) {
                SymbolicValue b = sp > 0 ? stack[--sp] : SymbolicValue.unknown();
                SymbolicValue a = sp > 0 ? stack[--sp] : SymbolicValue.unknown();
                if (a.concrete && b.concrete) {
                    int result = applyIntOp(op, a.value, b.value);
                    if (sp < stackCap) stack[sp++] = SymbolicValue.concrete(result);
                } else {
                    if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
                }
            } else if (op == INEG) {
                SymbolicValue a = sp > 0 ? stack[--sp] : SymbolicValue.unknown();
                if (a.concrete) {
                    if (sp < stackCap) stack[sp++] = SymbolicValue.concrete(-a.value);
                } else {
                    if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
                }
            } else if (op == IINC) {
                int var = p.op0 & 0xFFFF;
                int delta = p.op1;
                if (var < localsCap && locals[var].concrete) {
                    locals[var] = SymbolicValue.concrete(locals[var].value + delta);
                } else if (var < localsCap) {
                    locals[var] = SymbolicValue.unknown();
                }
            }

            // ---- Type conversions (push result, but we can't concretely fold non-int) ----
            else if (op == I2L || op == I2F || op == I2D) {
                if (sp > 0) sp--;
                if (op == I2L || op == I2D) {
                    if (sp + 1 < stackCap) { stack[sp++] = SymbolicValue.unknown(); stack[sp++] = SymbolicValue.unknown(); }
                } else {
                    if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
                }
            } else if (op == L2I || op == F2I || op == D2I
                    || op == I2B || op == I2C || op == I2S) {
                if (op == L2I || op == D2I) {
                    if (sp >= 2) sp -= 2;
                } else {
                    if (sp > 0) sp--;
                }
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op >= 0xA1 && op <= 0xA8) {
                // L2F, L2D, F2L, F2D, D2L, D2F: consume 1-2 slots, produce 1-2 unknowns
                int consume = (op == L2F || op == L2D || op == D2L || op == D2F) ? 2 : 1;
                int produce = (op == L2F || op == F2L || op == D2L) ? 2 : 1;
                if (sp >= consume) sp -= consume;
                if (sp + produce - 1 < stackCap) {
                    for (int j = 0; j < produce; j++) stack[sp++] = SymbolicValue.unknown();
                }
            }

            // ---- Long arithmetic (all produce unknowns) ----
            else if (op == LCMP) {
                if (sp >= 4) sp -= 4;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if ((op >= 0xAD && op <= 0xB2) || (op >= 0xB3 && op <= 0xB8)) {
                if (sp >= 4) sp -= 4;
                if (sp + 1 < stackCap) { stack[sp++] = SymbolicValue.unknown(); stack[sp++] = SymbolicValue.unknown(); }
            }

            // ---- Float/double arithmetic (all produce unknowns) ----
            else if ((op >= 0xB9 && op <= 0xBE) || (op >= 0xBF && op <= 0xC4)
                    || op == FCMPL || op == FCMPG || op == DCMPL || op == DCMPG) {
                int consume = (op == FADD || op == FSUB || op == FMUL || op == FDIV || op == FREM
                        || op == FNEG || op == FCMPL || op == FCMPG) ? 1 : 2;
                int slots = consume == 1 ? 1 : 2;
                if (sp >= slots * 2) sp -= slots * 2;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            }

            // ---- Comparison / branches (unknown target -> mark result unknown) ----
            else if (op == GOTO) {
                // Skip -- the target is an absolute pc; we can't follow it symbolically.
                // Continue linearly (best-effort: assume fall-through target).
            } else if ((op8 >= 0x30 && op8 <= 0x3D) || op == IF_ACMPEQ || op == IF_ACMPNE) {
                // Conditional branch: pop operands and continue linearly.
                int popCount = (op8 >= 0x36 && op8 <= 0x3B) ? 2 : 1;
                if (sp >= popCount) sp -= popCount;
                // Cannot determine which branch is taken -- continue linearly.
            }

            // ---- Stack manipulation ----
            else if (op == POP) {
                if (sp > 0) sp--;
            } else if (op == POP2) {
                if (sp >= 2) sp -= 2;
            } else if (op == DUP) {
                if (sp > 0 && sp < stackCap) {
                    stack[sp] = stack[sp - 1];
                    sp++;
                }
            } else if (op == DUP_X1) {
                if (sp >= 2 && sp < stackCap) {
                    SymbolicValue top = stack[sp - 1];
                    SymbolicValue below = stack[sp - 2];
                    stack[sp] = top;
                    stack[sp - 1] = below;
                    stack[sp - 2] = top;
                    sp++;
                }
            } else if (op == DUP_X2) {
                // DUP_X2: val1,val2,val3 -> val1,val3,val2,val1
                if (sp >= 3 && sp < stackCap) {
                    SymbolicValue top = stack[sp - 1];
                    stack[sp] = top;
                    stack[sp - 1] = stack[sp - 3];
                    stack[sp - 3] = top;
                    sp++;
                }
            } else if (op == DUP2) {
                if (sp >= 2 && sp + 1 < stackCap) {
                    stack[sp] = stack[sp - 2];
                    stack[sp + 1] = stack[sp - 1];
                    sp += 2;
                }
            } else if (op == DUP2_X1) {
                // val1,val2,val3 -> val2,val3,val1,val2
                if (sp >= 3 && sp + 1 < stackCap) {
                    SymbolicValue a = stack[sp - 3];
                    SymbolicValue b = stack[sp - 2];
                    stack[sp] = b;
                    stack[sp + 1] = stack[sp - 1];
                    stack[sp - 1] = b;
                    stack[sp - 2] = a;
                    stack[sp - 3] = b;
                    sp += 2;
                }
            } else if (op == DUP2_X2) {
                // val1,val2,val3,val4 -> val3,val4,val1,val2,val3,val4
                if (sp >= 4 && sp + 1 < stackCap) {
                    SymbolicValue a = stack[sp - 4];
                    SymbolicValue b = stack[sp - 3];
                    stack[sp] = stack[sp - 2];
                    stack[sp + 1] = stack[sp - 1];
                    stack[sp - 1] = a;
                    stack[sp - 2] = b;
                    stack[sp - 3] = stack[sp];
                    stack[sp - 4] = stack[sp + 1];
                    sp += 2;
                }
            } else if (op == SWAP) {
                if (sp >= 2) {
                    SymbolicValue tmp = stack[sp - 1];
                    stack[sp - 1] = stack[sp - 2];
                    stack[sp - 2] = tmp;
                }
            }

            // ---- Field access -> unknown ----
            else if (op == GETSTATIC || op == GETFIELD) {
                if (op == GETFIELD && sp > 0) sp--;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op == PUTSTATIC || op == PUTFIELD) {
                if (sp > 0) sp--;
                if (op == PUTFIELD && sp > 0) sp--;
            }

            // ---- Method invocation -> unknown ----
            else if (op == INVOKEVIRTUAL || op == INVOKESPECIAL
                    || op == INVOKESTATIC || op == INVOKEINTERFACE) {
                // All operands and result become unknown.
                // Pop 1 (object ref) + unknown argument count -- conservatively pop up to what's left.
                // Mark the entire stack as contaminated.
                for (int j = 0; j < sp; j++) stack[j] = SymbolicValue.unknown();
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            }

            // ---- Type / new -> unknown ----
            else if (op == NEW) {
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op == NEWARRAY || op == ANEWARRAY) {
                if (sp > 0) sp--;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op == ARRAYLENGTH) {
                if (sp > 0) sp--;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op == IALOAD || op == BALOAD || op == CALOAD || op == SALOAD) {
                if (sp >= 2) sp -= 2;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op == AALOAD) {
                if (sp >= 2) sp -= 2;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            } else if (op == IASTORE || op == BASTORE || op == CASTORE
                    || op == SASTORE || op == AASTORE) {
                if (sp >= 3) sp -= 3;
            } else if (op == CHECKCAST) {
                // no stack change
            } else if (op == INSTANCEOF) {
                if (sp > 0) sp--;
                if (sp < stackCap) stack[sp++] = SymbolicValue.unknown();
            }

            // ---- Monitor -> no stack effect ----
            else if (op == MONITORENTER) {
                if (sp > 0) sp--;
            } else if (op == MONITOREXIT) {
                if (sp > 0) sp--;
            }

            // ---- Frame / End ----
            else if (op == FRAME) {
                // maxLocals, maxStack metadata -- ignore for execution
            }

            // ---- Terminal ----
            else if (isTerminal(op)) {
                if (op == IRETURN) {
                    SymbolicValue result = sp > 0 ? stack[sp - 1] : SymbolicValue.unknown();
                    return result;
                }
                if (op == RETURN) {
                    return SymbolicValue.unknown();
                }
                if (op == ATHROW) {
                    return SymbolicValue.unknown();
                }
                if (op == END) {
                    SymbolicValue result = sp > 0 ? stack[sp - 1] : SymbolicValue.unknown();
                    return result;
                }
            }
        }

        // Fell off the end -- return whatever is on top of stack.
        return sp > 0 ? stack[sp - 1] : SymbolicValue.unknown();
    }

    /** Applies a binary integer operation to two concrete values. */
    private static int applyIntOp(byte op, int a, int b) {
        int op8 = op & 0xFF;
        switch (op8) {
            case 0x20: return a + b;
            case 0x21: return a - b;
            case 0x22: return a * b;
            case 0x23: return b == 0 ? 0 : a / b;
            case 0x24: return b == 0 ? 0 : a % b;
            case 0x26: return a << (b & 0x1F);
            case 0x27: return a >> (b & 0x1F);
            case 0x28: return a >>> (b & 0x1F);
            case 0x29: return a & b;
            case 0x2A: return a | b;
            case 0x2B: return a ^ b;
            default: return 0;
        }
    }

    // ---------- Byte reading helpers ----------

    private static int readInt(byte[] data, int offset) {
        if (offset + 4 > data.length) return 0;
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    private static int readU2(byte[] data, int offset) {
        if (offset + 2 > data.length) return 0;
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    // ---------- Instruction counting ----------

    /** Counts the number of instructions in a VMP bytecode stream. */
    static int countInstructions(byte[] code) {
        if (code == null || code.length == 0) return 0;
        int count = 0;
        int i = 0;
        while (i < code.length) {
            int ob = operandBytes(code[i]);
            if (ob < 0) { i++; count++; }
            else { i += 1 + ob; count++; }
        }
        return count;
    }

    /** Counts the number of arithmetic/logic operations in a VMP bytecode stream. */
    static int countArithmeticOps(byte[] code) {
        if (code == null || code.length == 0) return 0;
        int count = 0;
        int i = 0;
        while (i < code.length) {
            byte op = code[i];
            int op8 = op & 0xFF;
            if ((op8 >= 0x20 && op8 <= 0x2B) || op == IINC) {
                count++;
            }
            int ob = operandBytes(op);
            if (ob < 0) { i++; } else { i += 1 + ob; }
        }
        return count;
    }

    // ---------- Structural hash ----------

    /**
     * Computes a structural hash of the VMP opcode stream, excluding operand
     * values. Useful for manual comparison of two versions of the same program.
     */
    static int structuralHash(byte[] code) {
        if (code == null || code.length == 0) return 0;
        int hash = 0;
        int i = 0;
        while (i < code.length) {
            byte op = code[i];
            hash = hash * 31 + (op & 0xFF);
            int ob = operandBytes(op);
            if (ob < 0) { i++; } else { i += 1 + ob; }
        }
        return hash;
    }

    // ---------- Public API ----------

    /**
     * Verifies that two VMP bytecode programs are semantically equivalent.
     *
     * <p>Runs the following checks:
     * <ol>
     *   <li><b>Instruction count ratio</b> -- transformed should have >= instructions
     *       than original (obfuscation adds, not removes).</li>
     *   <li><b>Terminal presence</b> -- both programs should have a RETURN-like
     *       instruction.</li>
     *   <li><b>Arithmetic operation count</b> -- transformed should preserve
     *       at least as many arithmetic operations as the original.</li>
     *   <li><b>Symbolic execution</b> -- execute both programs concretely where
     *       possible and compare results.</li>
     *   <li><b>Structural hash</b> -- log hashes for manual review.</li>
     * </ol>
     *
     * <p>All checks are best-effort. The method NEVER throws -- failures are
     * logged and the result marks non-equivalence with a descriptive detail.
     *
     * @param originalCode    original VMP bytecode
     * @param originalCp      original constant pool (reserved for future use)
     * @param transformedCode transformed VMP bytecode
     * @param transformedCp   transformed constant pool (reserved for future use)
     * @return a {@link VerificationResult} describing the outcome
     */
    public static VerificationResult verifyVmpBytecode(
            byte[] originalCode, Object[] originalCp,
            byte[] transformedCode, Object[] transformedCp) {

        int checksRun = 0;
        StringBuilder detail = new StringBuilder();

        KBoxLog.info(TAG, "Starting VMP bytecode verification...");

        // Null / empty guards
        if (originalCode == null || originalCode.length == 0) {
            if (transformedCode == null || transformedCode.length == 0) {
                KBoxLog.info(TAG, "Both original and transformed are null/empty -- vacuously equivalent");
                return new VerificationResult(true, "both empty", 0);
            }
            KBoxLog.warn(TAG, "Original code is null/empty but transformed is not");
            return new VerificationResult(false, "original code is empty", 0);
        }
        if (transformedCode == null || transformedCode.length == 0) {
            KBoxLog.warn(TAG, "Transformed code is null/empty -- likely a translation failure");
            return new VerificationResult(false, "transformed code is empty", 0);
        }

        // Check 1: Instruction count ratio
        checksRun++;
        int origCount = countInstructions(originalCode);
        int transCount = countInstructions(transformedCode);
        KBoxLog.info(TAG, "Instruction count: original=" + origCount + ", transformed=" + transCount);
        if (transCount < origCount) {
            KBoxLog.warn(TAG, "Transformed has fewer instructions than original ("
                    + transCount + " < " + origCount + ") -- possible semantic divergence");
            detail.append("Instruction count decreased (")
                    .append(transCount).append(" < ").append(origCount).append("); ");
        }

        // Check 2: Terminal presence
        checksRun++;
        boolean origHasTerminal = hasTerminal(originalCode);
        boolean transHasTerminal = hasTerminal(transformedCode);
        KBoxLog.info(TAG, "Terminal check: original=" + origHasTerminal + ", transformed=" + transHasTerminal);
        if (origHasTerminal && !transHasTerminal) {
            KBoxLog.warn(TAG, "Original has terminal instruction but transformed does not");
            detail.append("Transformed missing terminal; ");
        }

        // Check 3: Arithmetic operation count
        checksRun++;
        int origArith = countArithmeticOps(originalCode);
        int transArith = countArithmeticOps(transformedCode);
        KBoxLog.info(TAG, "Arithmetic op count: original=" + origArith + ", transformed=" + transArith);
        if (transArith < origArith) {
            KBoxLog.warn(TAG, "Transformed has fewer arithmetic operations than original ("
                    + transArith + " < " + origArith + ")");
            detail.append("Arithmetic operation count diverged (")
                    .append(transArith).append(" < ").append(origArith).append("); ");
        }

        // Check 4: Symbolic execution
        checksRun++;
        java.util.List<ParsedInsn> origInsns = parse(originalCode);
        java.util.List<ParsedInsn> transInsns = parse(transformedCode);

        int maxStack = 64;
        int maxLocals = 32;
        SymbolicValue origResult = symbolicExecute(origInsns, maxStack, maxLocals);
        SymbolicValue transResult = symbolicExecute(transInsns, maxStack, maxLocals);
        KBoxLog.info(TAG, "Symbolic execution results: original=" + origResult
                + ", transformed=" + transResult);

        boolean symEquiv;
        if (!origResult.concrete || !transResult.concrete) {
            KBoxLog.info(TAG, "One or both results are non-concrete -- cannot disprove equivalence, conservatively pass");
            symEquiv = true;
        } else {
            if (origResult.value == transResult.value) {
                KBoxLog.info(TAG, "Concrete results match: " + origResult.value + " == " + transResult.value);
                symEquiv = true;
            } else {
                KBoxLog.warn(TAG, "Concrete results diverge: original=" + origResult.value
                        + ", transformed=" + transResult.value);
                detail.append("Symbolic execution divergence (")
                        .append(origResult.value).append(" != ").append(transResult.value).append("); ");
                symEquiv = false;
            }
        }

        // Check 5: Structural hash
        int origHash = structuralHash(originalCode);
        int transHash = structuralHash(transformedCode);
        KBoxLog.info(TAG, "Structural hashes: original=0x" + Integer.toHexString(origHash)
                + ", transformed=0x" + Integer.toHexString(transHash));
        // Hash divergence is expected after obfuscation, so we only log it.

        // Aggregate result
        boolean equivalent = symEquiv && detail.length() == 0;

        if (equivalent) {
            KBoxLog.info(TAG, "Verification PASSED (" + checksRun + " checks)");
            return new VerificationResult(true, "all checks passed", checksRun);
        } else {
            String d = detail.toString();
            if (d.endsWith("; ")) d = d.substring(0, d.length() - 2);
            KBoxLog.warn(TAG, "Verification FAILED: " + d);
            return new VerificationResult(false, d, checksRun);
        }
    }

    /**
     * Fast equivalence check for two VMP bytecode programs.
     *
     * <p>Parses both, executes symbolically, and compares concrete results.
     * Returns {@code true} if:
     * <ul>
     *   <li>Both produce the same concrete result, OR</li>
     *   <li>Either result is non-concrete (conservative: cannot disprove)</li>
     * </ul>
     *
     * @param code1 first VMP bytecode program
     * @param code2 second VMP bytecode program
     * @return {@code true} if the programs appear equivalent
     */
    public static boolean quickEquivalenceCheck(byte[] code1, byte[] code2) {
        if (code1 == null || code2 == null) return code1 == code2;
        if (code1.length == 0 && code2.length == 0) return true;

        KBoxLog.info(TAG, "quickEquivalenceCheck: len1=" + code1.length + ", len2=" + code2.length);

        java.util.List<ParsedInsn> insns1 = parse(code1);
        java.util.List<ParsedInsn> insns2 = parse(code2);

        SymbolicValue r1 = symbolicExecute(insns1, 64, 32);
        SymbolicValue r2 = symbolicExecute(insns2, 64, 32);

        // Conservative: if either is non-concrete, we cannot disprove equivalence
        if (!r1.concrete || !r2.concrete) {
            KBoxLog.info(TAG, "quickEquivalenceCheck: non-concrete result -- pass (conservative)");
            return true;
        }

        boolean match = r1.value == r2.value;
        KBoxLog.info(TAG, "quickEquivalenceCheck: " + r1.value + " " + (match ? "==" : "!=") + " " + r2.value);
        return match;
    }

    /**
     * Post-pass verification convenience: called after a VMP transformation pass
     * to verify that the output is equivalent to the input.
     *
     * <p>If the check fails, a warning is logged but execution continues
     * (best-effort behaviour matching {@code cfg.isNeverFail()}).
     *
     * @param stage  human-readable stage name (e.g. "FlattenVmp")
     * @param before bytecode before the pass
     * @param after  bytecode after the pass
     * @return a {@link VerificationResult}
     */
    public static VerificationResult verify(String stage, byte[] before, byte[] after) {
        KBoxLog.info(TAG, "Stage '" + stage + "': verifying transformation...");
        VerificationResult result = verifyVmpBytecode(before, null, after, null);
        if (!result.equivalent) {
            KBoxLog.warn(TAG, "Stage '" + stage + "' verification FAILED: " + result.detail
                    + " (checks run: " + result.checksRun + ") -- continuing (neverFail)");
        } else {
            KBoxLog.info(TAG, "Stage '" + stage + "' verification PASSED");
        }
        return result;
    }

    // ---------- Internal helpers ----------

    /** Checks whether a VMP bytecode stream contains a terminal instruction. */
    private static boolean hasTerminal(byte[] code) {
        if (code == null) return false;
        int i = 0;
        while (i < code.length) {
            byte op = code[i];
            if (isTerminal(op)) return true;
            int ob = operandBytes(op);
            if (ob < 0) { i++; } else { i += 1 + ob; }
        }
        return false;
    }
}
