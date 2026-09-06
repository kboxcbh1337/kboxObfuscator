package com.kbox.core.bfvm.compile;

/**
 * Serializes a compiled BFVM byte stream into an executable Brainfuck program.
 *
 * <p>Layout of the produced BF program: cell0 = stream length (high byte), cell1 = length
 * (low byte), cells 2..2+len-1 = the stream bytes. Each cell is initialised with the
 * corresponding value using plain {@code +} increments, cells are advanced with
 * {@code >}. Running the program with
 * {@link com.kbox.runtime.bfvm.BfInterpreter#executeToData} recovers the original
 * byte stream.
 */
public final class BfProgramWriter {
    private BfProgramWriter() {
    }

    public static String write(byte[] data) {
        if (data.length > 0xFFFF) {
            throw new IllegalArgumentException("BFVM stream too large: " + data.length
                    + " bytes (max 65535)");
        }
        StringBuilder sb = new StringBuilder(data.length * 8 + 64);
        emit(sb, (data.length >>> 8) & 0xFF);
        sb.append('>');
        emit(sb, data.length & 0xFF);
        for (int i = 0; i < data.length; i++) {
            sb.append('>');
            emit(sb, data[i] & 0xFF);
        }
        return sb.toString();
    }

    private static void emit(StringBuilder sb, int v) {
        for (int i = 0; i < v; i++) {
            sb.append('+');
        }
    }
}
