package com.kbox.core.bfvm.compile;

/**
 * Opcode constants for the compiled JVM-&gt;BF instruction stream.
 *
 * <p>The stream starts with a 16-bit big-endian {@code maxLocals} header, followed by a
 * sequence of instructions. Each instruction is {@code [opcode][payload...]}. Branches
 * carry absolute 32-bit target offsets into the stream.
 *
 * <p>Several opcodes intentionally reuse the raw JVM opcode numeric values (arithmetic,
 * conversions, comparisons, returns, stack shuffles, array loads/stores, ARRAYLENGTH,
 * ATHROW); the rest are assigned dedicated values above 200.
 */
public final class Opcode {
    private Opcode() {
    }

    // ---- extended ops (no direct JVM counterpart / absolute branch targets) ----
    public static final int CONST_INT = 200;
    public static final int CONST_LONG = 201;
    public static final int CONST_FLOAT = 202;
    public static final int CONST_DOUBLE = 203;
    public static final int CONST_STRING = 204;
    public static final int CONST_CLASS = 205;
    public static final int ACONST_NULL = 206;

    public static final int ILOAD = 207;
    public static final int LLOAD = 208;
    public static final int FLOAD = 209;
    public static final int DLOAD = 210;
    public static final int ALOAD = 211;
    public static final int ISTORE = 212;
    public static final int LSTORE = 213;
    public static final int FSTORE = 214;
    public static final int DSTORE = 215;
    public static final int ASTORE = 216;
    public static final int IINC = 217;

    public static final int IFEQ = 218;
    public static final int IFNE = 219;
    public static final int IFLT = 220;
    public static final int IFGE = 221;
    public static final int IFGT = 222;
    public static final int IFLE = 223;
    public static final int IF_ICMPEQ = 224;
    public static final int IF_ICMPNE = 225;
    public static final int IF_ICMPLT = 226;
    public static final int IF_ICMPGE = 227;
    public static final int IF_ICMPGT = 228;
    public static final int IF_ICMPLE = 229;
    public static final int IF_ACMPEQ = 230;
    public static final int IF_ACMPNE = 231;
    public static final int IFNULL = 232;
    public static final int IFNONNULL = 233;
    public static final int GOTO = 234;
    public static final int TABLESWITCH = 235;
    public static final int LOOKUPSWITCH = 236;

    public static final int NEW = 237;
    public static final int NEWARRAY = 238;
    public static final int ANEWARRAY = 239;

    public static final int GETSTATIC = 240;
    public static final int PUTSTATIC = 241;
    public static final int GETFIELD = 242;
    public static final int PUTFIELD = 243;

    public static final int INVOKEVIRTUAL = 244;
    public static final int INVOKESPECIAL = 245;
    public static final int INVOKESTATIC = 246;
    public static final int INVOKEINTERFACE = 247;

    public static final int CHECKCAST = 248;
    public static final int INSTANCEOF = 249;

    // ---- ops whose numeric value intentionally matches the JVM opcode ----
    public static final int NOP = 0;

    public static final int IALOAD = 46;
    public static final int LALOAD = 47;
    public static final int FALOAD = 48;
    public static final int DALOAD = 49;
    public static final int AALOAD = 50;
    public static final int BALOAD = 51;
    public static final int CALOAD = 52;
    public static final int SALOAD = 53;

    public static final int IASTORE = 79;
    public static final int LASTORE = 80;
    public static final int FASTORE = 81;
    public static final int DASTORE = 82;
    public static final int AASTORE = 83;
    public static final int BASTORE = 84;
    public static final int CASTORE = 85;
    public static final int SASTORE = 86;

    public static final int POP = 87;
    public static final int POP2 = 88;
    public static final int DUP = 89;
    public static final int DUP_X1 = 90;
    public static final int DUP_X2 = 91;
    public static final int DUP2 = 92;
    public static final int DUP2_X1 = 93;
    public static final int DUP2_X2 = 94;
    public static final int SWAP = 95;

    public static final int IADD = 96;
    public static final int LADD = 97;
    public static final int FADD = 98;
    public static final int DADD = 99;
    public static final int ISUB = 100;
    public static final int LSUB = 101;
    public static final int FSUB = 102;
    public static final int DSUB = 103;
    public static final int IMUL = 104;
    public static final int LMUL = 105;
    public static final int FMUL = 106;
    public static final int DMUL = 107;
    public static final int IDIV = 108;
    public static final int LDIV = 109;
    public static final int FDIV = 110;
    public static final int DDIV = 111;
    public static final int IREM = 112;
    public static final int LREM = 113;
    public static final int FREM = 114;
    public static final int DREM = 115;
    public static final int INEG = 116;
    public static final int LNEG = 117;
    public static final int FNEG = 118;
    public static final int DNEG = 119;

    public static final int ISHL = 120;
    public static final int LSHL = 121;
    public static final int ISHR = 122;
    public static final int LSHR = 123;
    public static final int IUSHR = 124;
    public static final int LUSHR = 125;

    public static final int IAND = 126;
    public static final int LAND = 127;
    public static final int IOR = 128;
    public static final int LOR = 129;
    public static final int IXOR = 130;
    public static final int LXOR = 131;

    public static final int I2L = 133;
    public static final int I2F = 134;
    public static final int I2D = 135;
    public static final int L2I = 136;
    public static final int L2F = 137;
    public static final int L2D = 138;
    public static final int F2I = 139;
    public static final int F2L = 140;
    public static final int F2D = 141;
    public static final int D2I = 142;
    public static final int D2L = 143;
    public static final int D2F = 144;
    public static final int I2B = 145;
    public static final int I2C = 146;
    public static final int I2S = 147;

    public static final int LCMP = 148;
    public static final int FCMPL = 149;
    public static final int FCMPG = 150;
    public static final int DCMPL = 151;
    public static final int DCMPG = 152;

    public static final int IRETURN = 172;
    public static final int LRETURN = 173;
    public static final int FRETURN = 174;
    public static final int DRETURN = 175;
    public static final int ARETURN = 176;
    public static final int RETURN = 177;

    public static final int ARRAYLENGTH = 190;
    public static final int ATHROW = 191;
}
