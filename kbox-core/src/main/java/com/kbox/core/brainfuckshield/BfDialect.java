package com.kbox.core.brainfuckshield;

/**
 * BrainfuckShield build-time dialect + tape-machine core.
 *
 * <p><b>BrainfuckShield = 二次虚拟化</b>：现有 VMP 已把 Java 方法翻译成 VMP 微码流
 * （per-method 随机密钥 K + 逐方法 opcode 置换 + ChaCha20 静态加密）。BrainfuckShield
 * 在 VMP 之上再加一层：把 VMP 密文流（{@code encVmp}）按 per-build/per-method 随机
 * <em>方言</em>重编码成「磁带程序」tape program。运行期 {@code BfInterpreter} 必须
 * 先把磁带程序逐格回放解码回 {@code encVmp}，才能交给 {@code VmpInterpreter} 执行。
 *
 * <p>关键对抗属性（对应设计「从 AI 读不懂到 AI 写不出破解工具」）：
 * <ol>
 *   <li><b>私有方言</b>：{@link #vmpToCode} 由 {@code K + buildSalt} 派生的 256 置换，
 *       每次构建/每个方法完全不同 —— 攻击者写一个「通用 BF→VMP 转译器」不成立。</li>
 *   <li><b>自修改指令流</b>：每个码点都被「磁带指纹」异或（{@link #tapeFinger}），
 *       指纹由前序已解码字节 + 每间隙诱饵噪声驱动 —— dump 静态磁带得到密文，dump 运行时
 *       trace 得到一次性序列（含环境熵），不可重放。</li>
 *   <li><b>膨胀 + 抵消对 + 诱饵</b>：{@link #applyDecoys} 每间隙注入 level 条
 *       语义抵消对（XOR⊕XOR、ADD−ADD、移动往返），净效应为零但把真实语义密度稀释，
 *       并在噪声窗口写确定性噪声使指纹依赖诱饵 —— 静态剥离诱饵会破坏解码。</li>
 * </ol>
 *
 * <p><b>一致性红线</b>：{@code BfRng}/{@code vmpToCode}/{@code seedTape}/
 * {@code tapeFinger}/{@code applyDecoys}/{@link #decode} 必须与运行期
 * {@code com.kbox.runtime.BfInterpreter} 逐字节一致（build 侧写一次、runtime 侧
 * 镜像一份，同 {@code VmpMethodInjector↔VmpInterpreter} 的既有置换复制模式）。
 * 任何改动两侧必须同步。
 */
public final class BfDialect {

    private BfDialect() {}

    /** 磁带程序魔数（小端）。XOR 遮蔽后存储的字节不再是 ASCII "KBFT"，
     *  防止 grep 指纹定位磁带头（坑④）。MUST match BfInterpreter.MAGIC. */
    public static final int MAGIC = 0x4B424654 ^ 0x5A3C7789;   // masked, not plaintext "KBFT"
    public static final int VERSION = 1;

    /** 磁带单元数（32 位 word）。固定常量保证 build/runtime 一致。 */
    public static final int TAPE_CELLS = 128;
    /** 参与指纹的磁带窗口（固定 64，需 ≤ TAPE_CELLS）。 */
    public static final int NOISE_WINDOW = 64;

    /** 磁带程序头部固定长度。 */
    public static final int HEADER_LEN = 16;

    /**
     * 完整性 trailer 长度（4 字节 FNV-1a）。
     *
     * <p><b>完整性绑定</b>：编码器把磁带载荷（header 之后的全部码点字节）的 FNV-1a
     * 追加到磁带程序末尾。任何对磁带程序的静态补丁（改一个码点字节）都会使解码端
     * trailer 校验失败 → 返回 {@code null} → VmpMethod 以噪声流 fail-closed，
     * 不给出任何「检测到篡改」的信号。build 侧 {@link #encode}/{@link #decode} 与
     * 运行期 {@code com.kbox.runtime.BfInterpreter} 必须保持一致。</p>
     */
    public static final int TRAILER_LEN = 4;

    // ------------------------------------------------------------------
    // 确定性 PRNG（MUST mirror in BfInterpreter）
    // ------------------------------------------------------------------

    /** Deterministic splitmix-style PRNG seeded from (key,label). */
    public static final class BfRng {
        long s;
        public BfRng(byte[] key, String label) {
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
        public long next() {
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27;
            s = s * 0x2545F4914F6CDD1DL;
            s ^= s >>> 32;
            return s;
        }
        public int nextInt(int bound) {
            return bound <= 0 ? 0 : (int) Long.remainderUnsigned(next(), bound);
        }
    }

    // ------------------------------------------------------------------
    // 方言表
    // ------------------------------------------------------------------

    /** 256 置换：vmpByte → codepoint。由 K+buildSalt 派生，每方法/每构建不同。 */
    public static int[] vmpToCode(byte[] K, int buildSalt) {
        BfRng rng = new BfRng(K, "kbox.bf.dialect." + buildSalt);
        int[] m = new int[256];
        for (int i = 0; i < 256; i++) m[i] = i;
        for (int i = 255; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            int t = m[i]; m[i] = m[j]; m[j] = t;
        }
        return m;
    }

    /** 逆置换：codepoint → vmpByte。 */
    public static int[] codeToVmp(int[] vmpToCode) {
        int[] inv = new int[256];
        for (int i = 0; i < 256; i++) inv[vmpToCode[i]] = i;
        return inv;
    }

    // ------------------------------------------------------------------
    // 磁带
    // ------------------------------------------------------------------

    /** 确定性初始化磁带。 */
    public static int[] seedTape(byte[] K, int buildSalt, int cells) {
        BfRng rng = new BfRng(K, "kbox.bf.tape." + buildSalt);
        int[] t = new int[cells];
        for (int i = 0; i < cells; i++) t[i] = (int) rng.next();
        return t;
    }

    /** FNV-1a 磁带指纹（前 noiseWindow 个 word）。 */
    public static int tapeFinger(int[] tape, int noiseWindow) {
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

    /**
     * 每间隙诱饵/抵消对（净效应为零但把指纹喂给噪声窗口）。确定性：由
     * {@code (K, buildSalt, i)} 独立播种，build/runtime 两侧逐字节一致。
     * 返回处理后的磁带头位置（净位移为 0）。
     */
    public static int applyDecoys(int[] tape, byte[] K, int buildSalt, int level, long i, int head) {
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
    // 编 / 解码
    // ------------------------------------------------------------------

    /**
     * 编码：把 {@code encVmp}（VMP 的静态密文流）逐字节重编码成磁带程序。
     * 每个码点 = 方言置换(明文字节) ⊕ 磁带指纹，因此磁带程序不含任何 VMP 密文直读字节。
     */
    public static byte[] encode(byte[] encVmp, byte[] K, int buildSalt, int level) {
        int n = encVmp.length;
        byte[] out = new byte[HEADER_LEN + n + TRAILER_LEN];
        writeInt(out, 0, MAGIC);
        out[4] = (byte) VERSION;
        out[5] = (byte) level;
        out[6] = (byte) TAPE_CELLS;
        out[7] = (byte) NOISE_WINDOW;
        writeInt(out, 8, buildSalt);
        writeInt(out, 12, n);

        int[] m = vmpToCode(K, buildSalt);
        int[] tape = seedTape(K, buildSalt, TAPE_CELLS);
        int head = 0;
        for (int i = 0; i < n; i++) {
            int fp = tapeFinger(tape, NOISE_WINDOW) & 0xFF;
            int v = encVmp[i] & 0xFF;
            int cp = (m[v] ^ fp) & 0xFF;
            out[HEADER_LEN + i] = (byte) cp;
            // 喂入已解码字节 -> 磁带状态随指令流演化（自修改）
            tape[head % TAPE_CELLS] = (tape[head % TAPE_CELLS] ^ v) & 0xFFFFFFFF;
            head++;
            head = applyDecoys(tape, K, buildSalt, level, i, head);
        }
        // 完整性 trailer：载荷 FNV-1a。静态补丁磁带任意字节都会在校验点暴露。
        int h = 0x811c9dc5;
        for (int i = 0; i < n; i++) {
            h ^= (out[HEADER_LEN + i] & 0xFF); h *= 0x01000193;
        }
        writeInt(out, HEADER_LEN + n, h);
        return out;
    }

    /**
     * 解码：把磁带程序逐格回放还原出 {@code encVmp}。结构必须与
     * {@code BfInterpreter.decodeTape} 逐字节一致。
     *
     * @return 还原的 encVmp，或 {@code null}（头部损坏/长度不符）。
     */
    public static byte[] decode(byte[] tapeProgram, byte[] K) {
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

    // ------------------------------------------------------------------
    // 头部 IO
    // ------------------------------------------------------------------

    public static int readInt(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    /** {@code true} 当 {@code b} 是 BrainfuckShield 磁带程序（KBFT 魔数 + trailer 齐全）。 */
    public static boolean hasMagic(byte[] b) {
        return b != null && b.length >= HEADER_LEN + TRAILER_LEN
                && readInt(b, 0) == MAGIC;
    }

    public static void writeInt(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }
}
