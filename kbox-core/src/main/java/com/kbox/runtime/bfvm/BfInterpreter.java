package com.kbox.runtime.bfvm;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * A genuine Brainfuck interpreter (full {@code + - > < [ ] . ,} instruction set, unbounded
 * int cells with wraparound, bracket pre-matching, step limit guard).
 *
 * <p>The compiled BFVM programs produced by
 * {@link com.kbox.core.bfvm.compile.BfProgramWriter} are pure data initialisers: running
 * them yields a tape where cell 0/1 hold the length of the embedded stream and cells 2..
 * carry the stream bytes. {@link #executeToData} recovers that stream for the VM.
 */
public final class BfInterpreter {
    public static final int CELLS = 1 << 16;
    public static final long MAX_STEPS = 200_000_000L;

    private BfInterpreter() {
    }

    /** Execute a BF program and return the decoded data region (cells 2..2+len-1). */
    public static byte[] executeToData(String src) {
        int[] tape = run(src, null, null);
        int len = ((tape[0] & 0xFF) << 8) | (tape[1] & 0xFF);
        if (len < 0 || 2 + len > tape.length) {
            throw new BfVmException("bad BF data header len=" + len);
        }
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) {
            data[i] = (byte) tape[2 + i];
        }
        return data;
    }

    /** Execute a BF program and capture its {@code .} output. */
    public static String executeToOutput(String src) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bos, true, StandardCharsets.UTF_8);
        run(src, ps, null);
        ps.flush();
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    /** Execute a BF program and return the final tape. */
    public static int[] run(String src, PrintStream out, InputStream in) {
        int[] tape = new int[CELLS];
        int ptr = 0;
        int[] jump = buildJump(src);
        long steps = 0;
        for (int ip = 0; ip < src.length(); ip++) {
            if (++steps > MAX_STEPS) {
                throw new BfVmException("BF step limit exceeded (possible runaway loop)");
            }
            char c = src.charAt(ip);
            switch (c) {
                case '+':
                    tape[ptr]++;
                    break;
                case '-':
                    tape[ptr]--;
                    break;
                case '>':
                    ptr++;
                    if (ptr >= CELLS) {
                        ptr = 0;
                    }
                    break;
                case '<':
                    ptr--;
                    if (ptr < 0) {
                        ptr = CELLS - 1;
                    }
                    break;
                case '[':
                    if (tape[ptr] == 0) {
                        ip = jump[ip];
                    }
                    break;
                case ']':
                    if (tape[ptr] != 0) {
                        ip = jump[ip];
                    }
                    break;
                case '.':
                    if (out != null) {
                        out.print((char) (tape[ptr] & 0xFF));
                    }
                    break;
                case ',':
                    if (in != null) {
                        int b;
                        try {
                            b = in.read();
                        } catch (java.io.IOException e) {
                            b = -1;
                        }
                        tape[ptr] = (b < 0 ? 0 : b);
                    } else {
                        tape[ptr] = 0;
                    }
                    break;
                default:
                    break;
            }
        }
        return tape;
    }

    private static int[] buildJump(String src) {
        int n = src.length();
        int[] jump = new int[n];
        Deque<Integer> stack = new ArrayDeque<>();
        for (int i = 0; i < n; i++) {
            char c = src.charAt(i);
            if (c == '[') {
                stack.push(i);
            } else if (c == ']') {
                if (stack.isEmpty()) {
                    throw new BfVmException("unbalanced ] at index " + i);
                }
                int open = stack.pop();
                jump[open] = i;
                jump[i] = open;
            }
        }
        if (!stack.isEmpty()) {
            throw new BfVmException("unbalanced [ at index " + stack.peek());
        }
        return jump;
    }
}
