package com.kbox.core.bfvm.compile;

import java.io.ByteArrayOutputStream;
import java.util.zip.Deflater;

/**
 * Serializes a compiled BFVM byte stream into an executable Brainfuck program.
 *
 * <p>Layout (tape cells): {@code [0..1]} = payload length (big-endian), {@code [2]} =
 * encoding flag (0 = raw, 1 = DEFLATE), {@code [3..]} = payload. Running the program with
 * {@link com.kbox.runtime.bfvm.BfInterpreter#executeToData} recovers the original stream.</p>
 *
 * <h3>为什么改编码</h3>
 * <p>原实现把每个字节写成 {@code v} 个 {@code '+'}（0–255 个），于是 BF 源 ≈ <b>128×</b>
 * 字节流长度；再撞上 {@code CONSTANT_Utf8} 的 65535 上限（{@code MAX_BF_SOURCE=60000}），
 * 可虚拟化的 stream 只有约 470 字节 ⇒ 约 30–80 条 JVM 指令。稍大的业务方法直接
 * "BF program too large" 静默跳过——这就是"BFVM 覆盖天花板"。</p>
 *
 * <p>两处改动：</p>
 * <ol>
 *   <li><b>最短路径</b>：把一个格设为 {@code v} 用 {@code min(v, 256-v)} 个 {@code '+'}/{@code '-'}
 *       （原来固定 {@code v} 个 {@code '+'}）→ 平均 128 字符降到 64；</li>
 *   <li><b>DEFLATE 预压</b>：BF 程序只物化压缩后的 payload，运行期再解压
 *       → 实际膨胀从 ~128× 降到 ~8–20×，方法体上限提升约一个数量级。</li>
 * </ol>
 *
 * <p>读端 {@code runtime/bfvm/BfInterpreter.executeToData} 按同一约定还原，两侧必须同步。</p>
 */
public final class BfProgramWriter {

    /** payload 未压缩。 */
    public static final int ENC_RAW = 0;
    /** payload 为 zlib/DEFLATE 压缩。 */
    public static final int ENC_DEFLATE = 1;

    private BfProgramWriter() {
    }

    public static String write(byte[] data) {
        byte[] packed = deflate(data);
        boolean usePacked = packed != null && packed.length + 1 < data.length + 1;
        byte[] payload = usePacked ? packed : data;
        int len = payload.length + 1;               // +1 = 编码标志字节
        if (len > 0xFFFE) {
            throw new IllegalArgumentException("BFVM payload too large: " + len
                    + " bytes (max 65534 after compression)");
        }
        StringBuilder sb = new StringBuilder(payload.length * 12 + 64);
        emitCell(sb, (len >>> 8) & 0xFF);
        sb.append('>');
        emitCell(sb, len & 0xFF);
        sb.append('>');
        emitCell(sb, usePacked ? ENC_DEFLATE : ENC_RAW);
        for (byte b : payload) {
            sb.append('>');
            emitCell(sb, b & 0xFF);
        }
        return sb.toString();
    }

    /**
     * 用较短的 {@code '+'} / {@code '-'} 序列把当前格设为 {@code v}。
     *
     * <p>读端按 {@code & 0xFF} 取值，因此 {@code -} 造成的负值（例如 -56 = 0xC8）语义等价。</p>
     */
    private static void emitCell(StringBuilder sb, int v) {
        int up = v & 0xFF;
        int down = 256 - up;
        if (down < up) {
            for (int i = 0; i < down; i++) sb.append('-');
        } else {
            for (int i = 0; i < up; i++) sb.append('+');
        }
    }

    /** zlib 压缩；失败或不可用时返回 null（调用方回落到 raw）。 */
    private static byte[] deflate(byte[] data) {
        try {
            Deflater d = new Deflater(Deflater.BEST_COMPRESSION);
            d.setInput(data);
            d.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length / 2));
            byte[] buf = new byte[4096];
            while (!d.finished()) {
                int n = d.deflate(buf);
                if (n <= 0) break;
                out.write(buf, 0, n);
            }
            d.end();
            return out.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }
}
