package com.kbox.runtime;

/**
 * BrainfuckShield runtime tape decoder + anti-instrumentation seam.
 *
 * <p><b>BrainfuckShield = 二次虚拟化</b>：构建期把 VMP 方法的 ChaCha20 密文流
 * （{@code encVmp}）按 per-build/per-method 随机<em>私有方言</em>重编码成「磁带程序」
 * （magic {@code KBFT}）存进 {@code $vmp_<n>} 静态字段。本类在
 * {@code VmpInterpreter.VmpMethod} 构造期把磁带程序逐格回放解码回 {@code encVmp}，
 * 再交给 VMP 解释器执行。磁带程序不是静态指令流——每个码点都被前序已解码字节驱动的
 * 磁带指纹异或，dump 静态字段得到的是密文，dump 运行时 trace 得到的是一次性序列。
 *
 * <p>本类必须与构建期 {@code com.kbox.core.brainfuckshield.BfDialect.decode} 逐字节一致
 * （{@code BfRng}/{@code vmpToCode}/{@code seedTape}/{@code tapeFinger}/
 * {@code applyDecoys}/{@code decodeTape}）。改动任一侧必须同步两侧。
 *
 * <p><b>完整性绑定</b>：磁带程序末尾带 4 字节 FNV-1a trailer。任何对磁带程序字节的
 * 静态补丁（agent 插桩改类字节、十六进制编辑器改常量池）都会使 trailer 校验失败 →
 * 解码返回 {@code null} → VmpMethod 以噪声流 fail-closed，不给出任何检测信号。
 *
 * <p><b>反插桩 / 无声诱饵</b>：{@link #decodeTape} 入口探测 JVM 输入参数中的
 * {@code -javaagent / -agentlib / -Xrun}（agent attach、插桩 trace 工具的标配）。
 * 命中时不报错、不打日志，而是用<em>被破坏的方言种子</em>解码——得到的指令流
 * 「看起来合法」但语义是错的，动态分析者拿到一份自信的错误解读且没有任何反馈信号。
 */
public final class BfInterpreter {

    private BfInterpreter() {}

    /** 磁带程序魔数（小端）。XOR 遮蔽后存储的字节不再是 ASCII "KBFT"，
     *  防止 grep 指纹定位磁带头（坑④）。MUST match BfDialect.MAGIC. */
    public static final int MAGIC = 0x4B424654 ^ 0x5A3C7789;   // masked, not plaintext "KBFT"
    public static final int VERSION = 1;

    /** 磁带单元数（32 位 word）。固定常量保证 build/runtime 一致。 */
    public static final int TAPE_CELLS = 128;
    /** 参与指纹的磁带窗口（固定 64，需 ≤ TAPE_CELLS）。 */
    public static final int NOISE_WINDOW = 64;

    /** 磁带程序头部固定长度。 */
    public static final int HEADER_LEN = 16;
    /** 完整性 trailer 长度（4 字节 FNV-1a）。 */
    public static final int TRAILER_LEN = 4;

    // ------------------------------------------------------------------
    // 反插桩探测（无声诱饵开关）
    // ------------------------------------------------------------------

    private static volatile boolean probeDone;
    private static volatile boolean agentArmed;

    /**
     * 探测 JVM 输入参数中的 {@code -javaagent / -agentlib / -Xrun}。
     * 命中即 armed —— {@link #decodeTape} 进入诱饵路径。线程安全（volatile + 幂等）。
     */
    public static boolean agentProbe() {
        if (!probeDone) {
            synchronized (BfInterpreter.class) {
                if (!probeDone) {
                    agentArmed = detectAgent();
                    probeDone = true;
                }
            }
        }
        return agentArmed;
    }

    private static boolean detectAgent() {
        try {
            for (String a : java.lang.management.ManagementFactory
                    .getRuntimeMXBean().getInputArguments()) {
                if (a == null) continue;
                String s = a.toLowerCase(java.util.Locale.ROOT);
                if (s.startsWith("-javaagent")
                        || s.startsWith("-xrun")
                        || s.contains("agentlib")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            // 探测失败不 armed —— 宁可放行也不误伤正常启动
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 确定性 PRNG（MUST mirror BfDialect.BfRng）
    // ------------------------------------------------------------------

    /** Deterministic splitmix-style PRNG seeded from (key,label). */
    static final class BfRng {
        long s;
        BfRng(byte[] key, String label) {
            long h = 0x243F6A8885A308D3L;
            if (key != null) {
                for (byte b : key) h = ((h ^ (b & 0xFF)) * 0x100000001B3L);
            }
            if (label != null) {
                byte[] lb = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                for (byte b : lb) h = ((h ^ (b & 0xFF)) * 0x100000001B3L);
            }
            s = h;
        }
        long next() {
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27;
            s = s * 0x2545F4914F6CDD1DL;
            s ^= s >>> 32;
            return s;
        }
        int nextInt(int bound) {
            return bound <= 0 ? 0 : (int) Long.remainderUnsigned(next(), bound);
        }
    }

    // ------------------------------------------------------------------
    // 方言表 / 磁带（MUST mirror BfDialect）
    // ------------------------------------------------------------------

    static int[] vmpToCode(byte[] K, int buildSalt) {
        BfRng rng = new BfRng(K, "kbox.bf.dialect." + buildSalt);
        int[] m = new int[256];
        for (int i = 0; i < 256; i++) m[i] = i;
        for (int i = 255; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            int t = m[i]; m[i] = m[j]; m[j] = t;
        }
        return m;
    }

    static int[] codeToVmp(int[] vmpToCode) {
        int[] inv = new int[256];
        for (int i = 0; i < 256; i++) inv[vmpToCode[i]] = i;
        return inv;
    }

    static int[] seedTape(byte[] K, int buildSalt, int cells) {
        BfRng rng = new BfRng(K, "kbox.bf.tape." + buildSalt);
        int[] t = new int[cells];
        for (int i = 0; i < cells; i++) t[i] = (int) rng.next();
        return t;
    }

    static int tapeFinger(int[] tape, int noiseWindow) {
        int h = 0x811c9dc5;
        int limit = Math.min(noiseWindow, tape.length);
        for (int i = 0; i < limit; i++) {
            int w = tape[i];
            h ^= (w & 0xFF);        h *= 0x01000193;
            h ^= ((w >>> 8) & 0xFF);  h *= 0x01000193;
            h ^= ((w >>> 16) & 0xFF); h *= 0x01000193;
            h ^= ((w >>> 24) & 0xFF); h *= 0x01000193;
        }
        return h;
    }

    static int applyDecoys(int[] tape, byte[] K, int buildSalt, int level, long i, int head) {
        if (level <= 0) return head;
        int cells = tape.length;
        BfRng rng = new BfRng(K, "kbox.bf.decoy." + buildSalt + "." + i);
        for (int d = 0; d < level; d++) {
            int op = rng.nextInt(3);
            if (op == 0) {
                int c = rng.nextInt(cells);
                int v = rng.nextInt(0x10000);
                tape[c] = (tape[c] ^ v) & 0xFFFFFFFF;
                tape[c] = (tape[c] ^ v) & 0xFFFFFFFF;   // XOR ⊕ XOR 自抵消
            } else if (op == 1) {
                int c = rng.nextInt(cells);
                int v = rng.nextInt(0x10000);
                tape[c] = (int) ((tape[c] + v) & 0xFFFFFFFFL);
                tape[c] = (int) ((tape[c] - v) & 0xFFFFFFFFL); // ADD − ADD 抵消对
            } else {
                int delta = 1 + rng.nextInt(7);
                head += delta;                            // 磁带头往返
                head -= delta;
            }
            // 把确定性噪声写进指纹窗口：让磁带指纹依赖诱饵，剥离诱饵即破坏解码
            int nc = rng.nextInt(NOISE_WINDOW);
            int noise = rng.nextInt(256);
            tape[nc] = (tape[nc] ^ noise) & 0xFFFFFFFF;
        }
        return head;
    }

    // ------------------------------------------------------------------
    // 解码入口
    // ------------------------------------------------------------------

    /**
     * {@code true} 当 {@code code} 是 BrainfuckShield 磁带程序（KBFT 魔数 + trailer 齐全）。
     */
    public static boolean hasMagic(byte[] code) {
        return code != null && code.length >= HEADER_LEN + TRAILER_LEN
                && readInt(code, 0) == MAGIC;
    }

    /**
     * VmpMethod 构造入口：若 {@code code} 是磁带程序则解码回 {@code encVmp}；
     * 否则原样返回（非 BrainfuckShield 方法向后兼容）。磁带被静态补丁（trailer 不匹配）
     * 或处于 agent 插桩环境时返回 {@code null} 或诱饵流（见 {@link #decodeTape}）。
     */
    public static byte[] decodeIfTape(byte[] code, byte[] K) {
        if (!hasMagic(code)) return code;          // 非磁带程序直接透传
        return decodeTape(code, K);                // 磁带程序：解码或诱饵
    }

    /**
     * 把磁带程序逐格回放还原出 {@code encVmp}。结构必须与
     * {@code BfDialect.decode} 逐字节一致（无 agent 的正常路径）。
     *
     * <p>反插桩：入口先 {@link #agentProbe()}，命中 agent 则用被破坏的方言种子解码
     * —— 返回一条长度相同、结构看似合法但语义全错的指令流（无声诱饵，不打日志）。
     *
     * @return 还原的 encVmp；磁带头部损坏/trailer 不匹配返回 {@code null}。
     */
    public static byte[] decodeTape(byte[] tapeProgram, byte[] K) {
        boolean decoy = agentProbe();
        byte[] kk = K;
        if (decoy && K != null && K.length > 0) {
            // 无声诱饵：破坏一个关键种子字节，方言/磁带全部错位 -> 语义错误但不崩溃检测
            kk = K.clone();
            kk[0] = (byte) (kk[0] ^ 0x5A);
        }
        return decodeTape0(tapeProgram, kk);
    }

    private static byte[] decodeTape0(byte[] tapeProgram, byte[] K) {
        if (tapeProgram == null || tapeProgram.length < HEADER_LEN + TRAILER_LEN) return null;
        if (readInt(tapeProgram, 0) != MAGIC) return null;
        int level = tapeProgram[5] & 0xFF;
        int cells = tapeProgram[6] & 0xFF;
        int noise = tapeProgram[7] & 0xFF;
        int buildSalt = readInt(tapeProgram, 8);
        int n = readInt(tapeProgram, 12);
        if (cells <= 0 || cells > 512) cells = TAPE_CELLS;
        if (noise <= 0 || noise > cells) noise = NOISE_WINDOW;
        if (n < 0 || HEADER_LEN + n + TRAILER_LEN > tapeProgram.length) return null;
        // 完整性绑定：先校验 trailer，任何一个磁带字节被静态补丁都拒绝解码。
        int h = 0x811c9dc5;
        for (int i = 0; i < n; i++) {
            h ^= (tapeProgram[HEADER_LEN + i] & 0xFF); h *= 0x01000193;
        }
        if (readInt(tapeProgram, HEADER_LEN + n) != h) return null;

        int[] inv = codeToVmp(vmpToCode(K, buildSalt));
        int[] tape = seedTape(K, buildSalt, cells);
        int head = 0;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            int fp = tapeFinger(tape, noise) & 0xFF;
            int cp = tapeProgram[HEADER_LEN + i] & 0xFF;
            int v = inv[(cp ^ fp) & 0xFF];
            out[i] = (byte) v;
            tape[head % cells] = (tape[head % cells] ^ v) & 0xFFFFFFFF;
            head++;
            head = applyDecoys(tape, K, buildSalt, level, i, head);
        }
        return out;
    }

    private static int readInt(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }
}
