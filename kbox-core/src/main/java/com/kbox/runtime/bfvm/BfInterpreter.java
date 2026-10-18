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

    /**
     * Execute a BF program and return the decoded data region.
     *
     * <p>约定（必须与 {@code BfProgramWriter} 同步）：{@code [0..1]} = payload 长度（大端），
     * {@code [2]} = 编码标志（0 = raw，1 = DEFLATE），{@code [3..]} = payload。
     * DEFLATE 让 BF 程序只物化压缩后的数据，从而突破"BF 源 ≈ 128× stream"的方法体上限。</p>
     */
    public static byte[] executeToData(String src) {
        int[] tape = run(src, null, null);
        int len = ((tape[0] & 0xFF) << 8) | (tape[1] & 0xFF);
        if (len < 1 || 2 + len > tape.length) {
            throw new BfVmException("bad BF data header len=" + len);
        }
        int enc = tape[2] & 0xFF;
        byte[] payload = new byte[len - 1];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) tape[3 + i];
        }
        if (enc == 1) {
            return inflate(payload);
        }
        return payload;
    }

    /** zlib 解压（对应 {@code BfProgramWriter} 的 DEFLATE payload）。 */
    private static byte[] inflate(byte[] packed) {
        try {
            java.util.zip.Inflater inf = new java.util.zip.Inflater();
            inf.setInput(packed);
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(packed.length * 4);
            byte[] buf = new byte[4096];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n <= 0) {
                    if (inf.needsInput() || inf.needsDictionary()) break;
                    continue;
                }
                out.write(buf, 0, n);
            }
            inf.end();
            return out.toByteArray();
        } catch (Exception e) {
            throw new BfVmException("BF payload inflate failed", e);
        }
    }

    /** Execute a BF program and capture its {@code .} output. */
    public static String executeToOutput(String src) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        PrintStream ps;
        try {
            // PrintStream(OutputStream, boolean, Charset) is Java 10+; the
            // String-encoding overload exists since Java 1.1 and encodes
            // identically ("UTF-8" is the canonical name of StandardCharsets.UTF_8).
            ps = new PrintStream(bos, true, StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            throw new BfVmException("UTF-8 unavailable", e);
        }
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
