package com.kbox.core.vmp;

/**
 * Compact virtual opcode set used by the KBox VMP interpreter. Each opcode is
 * a single {@code byte}; operands (ints, indices) are stored inline in the
 * instruction stream as little-endian fixed-width fields so the dispatcher can
 * {@code fetch()} them without indirection.
 *
 * <p>The set is intentionally small but sufficient to express any JVM method
 * that survives the JNIC fall-back path (basic arithmetic, control flow, field
 * access, method invocation, monitorenter/exit, athrow). Complex constructs
 * (e.g. {@code invokedynamic}) are not yet supported and will keep their
 * original bytecode — see {@link VmpTranslator}.
 */
public final class VmpOp {

    private VmpOp() {}

    // --- Constants / loads ---
    public static final byte ACONST_NULL   = 0x01;
    public static final byte ICONST        = 0x02; // 1 int operand: value
    public static final byte LCONST        = 0x03; // 2 int operands: hi, lo
    public static final byte FCONST        = 0x04; // 1 float operand (raw int bits)
    public static final byte DCONST        = 0x05; // 2 int operands: hi, lo
    public static final byte STRING        = 0x06; // 1 int operand: cp index (String)
    public static final byte CLASS         = 0x07; // 1 int operand: cp index (Class)

    public static final byte ILOAD         = 0x10;
    public static final byte LLOAD        = 0x11;
    public static final byte FLOAD        = 0x12;
    public static final byte DLOAD        = 0x13;
    public static final byte ALOAD        = 0x14;

    public static final byte ISTORE        = 0x18;
    public static final byte LSTORE        = 0x19;
    public static final byte FSTORE        = 0x1A;
    public static final byte DSTORE        = 0x1B;
    public static final byte ASTORE        = 0x1C;

    // --- Arithmetic (typed variants kept minimal: I + L for our test methods) ---
    public static final byte IADD         = 0x20;
    public static final byte ISUB         = 0x21;
    public static final byte IMUL         = 0x22;
    public static final byte IDIV         = 0x23;
    public static final byte IREM         = 0x24;
    public static final byte INEG         = 0x25;
    public static final byte ISHL         = 0x26;
    public static final byte ISHR         = 0x27;
    public static final byte IUSHR        = 0x28;
    public static final byte IAND         = 0x29;
    public static final byte IOR          = 0x2A;
    public static final byte IXOR         = 0x2B;
    public static final byte IINC         = 0x2C; // 2 operands: varIndex, delta

    // --- Type conversions (no operands) ---
    public static final byte I2L         = 0x2D;
    public static final byte I2F         = 0x2E;
    public static final byte I2D         = 0x2F;
    public static final byte L2I         = (byte) 0xA0;
    public static final byte L2F         = (byte) 0xA1;
    public static final byte L2D         = (byte) 0xA2;
    public static final byte F2I         = (byte) 0xA3;
    public static final byte F2L         = (byte) 0xA4;
    public static final byte F2D         = (byte) 0xA5;
    public static final byte D2I         = (byte) 0xA6;
    public static final byte D2L         = (byte) 0xA7;
    public static final byte D2F         = (byte) 0xA8;
    public static final byte I2B         = (byte) 0xA9;
    public static final byte I2C         = (byte) 0xAA;
    public static final byte I2S         = (byte) 0xAB;

    // --- Long arithmetic (no operands) ---
    public static final byte LCMP        = (byte) 0xAC;
    public static final byte LADD        = (byte) 0xAD;
    public static final byte LSUB        = (byte) 0xAE;
    public static final byte LMUL        = (byte) 0xAF;
    public static final byte LDIV        = (byte) 0xB0;
    public static final byte LREM        = (byte) 0xB1;
    public static final byte LNEG        = (byte) 0xB2;
    public static final byte LSHL        = (byte) 0xB3;
    public static final byte LSHR        = (byte) 0xB4;
    public static final byte LUSHR       = (byte) 0xB5;
    public static final byte LAND        = (byte) 0xB6;
    public static final byte LOR         = (byte) 0xB7;
    public static final byte LXOR        = (byte) 0xB8;

    // --- Float/double arithmetic (no operands) ---
    public static final byte FADD        = (byte) 0xB9;
    public static final byte FSUB        = (byte) 0xBA;
    public static final byte FMUL        = (byte) 0xBB;
    public static final byte FDIV        = (byte) 0xBC;
    public static final byte FREM        = (byte) 0xBD;
    public static final byte FNEG        = (byte) 0xBE;
    public static final byte DADD        = (byte) 0xBF;
    public static final byte DSUB        = (byte) 0xC0;
    public static final byte DMUL        = (byte) 0xC1;
    public static final byte DDIV        = (byte) 0xC2;
    public static final byte DREM        = (byte) 0xC3;
    public static final byte DNEG        = (byte) 0xC4;
    public static final byte FCMPL       = (byte) 0xC5;
    public static final byte FCMPG       = (byte) 0xC6;
    public static final byte DCMPL       = (byte) 0xC7;
    public static final byte DCMPG       = (byte) 0xC8;

    // --- Comparison / branches ---
    public static final byte IFEQ         = 0x30; // 1 int operand: target pc
    public static final byte IFNE         = 0x31;
    public static final byte IFLT         = 0x32;
    public static final byte IFGE         = 0x33;
    public static final byte IFGT         = 0x34;
    public static final byte IFLE         = 0x35;
    public static final byte IF_ICMPEQ    = 0x36;
    public static final byte IF_ICMPNE    = 0x37;
    public static final byte IF_ICMPLT    = 0x38;
    public static final byte IF_ICMPGE    = 0x39;
    public static final byte IF_ICMPGT    = 0x3A;
    public static final byte IF_ICMPLE    = 0x3B;
    public static final byte IFNULL       = 0x3C;
    public static final byte IFNONNULL    = 0x3D;
    public static final byte IF_ACMPEQ    = 0x3F;
    public static final byte IF_ACMPNE    = (byte) 0xC9;
    public static final byte GOTO         = 0x3E; // 1 int operand: target pc

    // --- Stack manipulation ---
    public static final byte POP          = 0x40;
    public static final byte POP2         = 0x41;
    public static final byte DUP          = 0x42;
    public static final byte DUP_X1       = 0x43;
    public static final byte DUP_X2       = (byte) 0xCA;
    public static final byte DUP2         = (byte) 0xCB;
    public static final byte DUP2_X1      = (byte) 0xCC;
    public static final byte DUP2_X2      = (byte) 0xCD;
    public static final byte SWAP         = 0x44;

    // --- Field access: 3 operands: cpOwner, cpName, cpDesc ---
    public static final byte GETSTATIC    = 0x50;
    public static final byte PUTSTATIC    = 0x51;
    public static final byte GETFIELD     = 0x52;
    public static final byte PUTFIELD     = 0x53;

    // --- Method invocation: 3 operands: owner, name, desc ---
    public static final byte INVOKEVIRTUAL   = 0x60;
    public static final byte INVOKESPECIAL  = 0x61;
    public static final byte INVOKESTATIC    = 0x62;
    public static final byte INVOKEINTERFACE = 0x63;

    // --- Type / new ---
    public static final byte NEW          = 0x70; // 1 int operand: cpClass
    public static final byte NEWARRAY    = 0x71; // 1 operand: array type code
    public static final byte ANEWARRAY    = 0x72; // 1 operand: cpClass
    public static final byte ARRAYLENGTH   = 0x73;
    public static final byte AALOAD        = 0x74;
    public static final byte AASTORE       = 0x75;
    public static final byte IALOAD        = 0x76;
    public static final byte IASTORE       = 0x77;
    public static final byte BALOAD        = 0x7A; // load byte/boolean from array
    public static final byte BASTORE       = 0x7B; // store byte/boolean into array
    public static final byte CALOAD        = 0x7C; // load char from array
    public static final byte CASTORE       = 0x7D; // store char into array
    public static final byte SALOAD        = 0x7E; // load short from array
    public static final byte SASTORE       = 0x7F; // store short into array
    public static final byte CHECKCAST     = 0x78; // 1 operand: cpClass
    public static final byte INSTANCEOF   = 0x79; // 1 operand: cpClass

    // --- Synchronization / exceptions ---
    public static final byte MONITORENTER  = (byte) 0x80;
    public static final byte MONITOREXIT   = (byte) 0x81;
    public static final byte ATHROW         = (byte) 0x82;

    // --- Returns ---
    public static final byte IRETURN       = (byte) 0x90;
    public static final byte LRETURN       = (byte) 0x91;
    public static final byte FRETURN       = (byte) 0x92;
    public static final byte DRETURN       = (byte) 0x93;
    public static final byte ARETURN       = (byte) 0x94;
    public static final byte RETURN        = (byte) 0x95;

    // --- Frame entry: declare locals & max stack for sanity ---
    public static final byte FRAME         = (byte) 0xF0; // 2 operands: maxLocals, maxStack

    /** End of method (defensive; control should reach a *RETURN). */
    public static final byte END          = (byte) 0xFF;

    public static String name(int op) {
        switch (op) {
            case ACONST_NULL: return "ACONST_NULL";
            case ICONST: return "ICONST";
            case GOTO: return "GOTO";
            case IFEQ: return "IFEQ";
            case IFNE: return "IFNE";
            case IADD: return "IADD";
            case INVOKEVIRTUAL: return "INVOKEVIRTUAL";
            case INVOKESTATIC: return "INVOKESTATIC";
            case GETFIELD: return "GETFIELD";
            case PUTFIELD: return "PUTFIELD";
            case IRETURN: return "IRETURN";
            case RETURN: return "RETURN";
            case ATHROW: return "ATHROW";
            case END: return "END";
            default: return "OP_" + Integer.toHexString(op & 0xFF);
        }
    }
}
