package com.kbox.core.brainfuckshield;

import com.kbox.core.log.KBoxLog;

/**
 * BrainfuckShield per-method build-side injector（二次虚拟化磁带化网关）。
 *
 * <p>在 VMP 之上再加一层：把每个 VMP 方法的 ChaCha20 密文流 {@code encVmp} 按
 * per-build/per-method 随机<em>私有方言</em>重编码成「磁带程序」，替换掉 {@code $vmp_<n>}
 * 字段中原本的直存密文。运行期 {@code com.kbox.runtime.BfInterpreter} 必须先把磁带程序
 * 逐格回放解码回 {@code encVmp} 才能交给 {@code VmpInterpreter} 执行。
 *
 * <p>对应设计「从 AI 读不懂到 AI 写不出破解工具」：
 * <ol>
 *   <li><b>私有方言（对抗"写通用转译器"）</b>：{@link BfDialect#vmpToCode} 由
 *       方法密钥 {@code K} + 每构建随机 {@code buildSalt} 派生 256 置换。每次构建、
 *       每个方法的方言都不同——攻击者写一个「通用 BF→VMP 转译器」不成立，
 *       破解工具从一次性 O(1) 变成每次构建 O(n)。</li>
 *   <li><b>自修改指令流（对抗 trace 重放）</b>：每个码点都被磁带指纹异或，指纹由
 *       前序已解码字节 + 每间隙诱饵噪声驱动。dump 静态字段得到密文；dump 运行时
 *       trace 得到一次性序列，不可重放。</li>
 *   <li><b>膨胀 + 抵消对 + 诱饵（对抗局部注意力）</b>：{@link BfDialect#applyDecoys}
 *       每间隙注入 level 条语义抵消对（XOR⊕XOR、ADD−ADD、移动往返），净效应为零但把
 *       真实语义密度稀释，并在噪声窗口写确定性噪声使指纹依赖诱饵——静态剥离诱饵即破坏解码。</li>
 *   <li><b>完整性绑定（对抗插桩 dump）</b>：磁带程序末尾带 FNV-1a trailer；任何对
 *       磁带字节的静态补丁都会使运行期解码返回 {@code null}，方法以噪声流 fail-closed，
 *       无任何检测信号（见 {@link BfDialect#TRAILER_LEN}）。</li>
 * </ol>
 */
public final class BfMethodInjector {

    private static final String TAG = "bfshield";
    private static final java.security.SecureRandom RNG = new java.security.SecureRandom();

    private BfMethodInjector() {}

    /**
     * 每构建随机 buildSalt。同一个构建内的所有方法共用它（与每方法 K 共同派生方言，
     * 保证方法间方言各异、构建间方言全异）。该值被写进磁带程序 header（offset 8），
     * 运行期从 header 读回，无需任何跨进程共享的稳定键。
     */
    public static int newBuildSalt() {
        return RNG.nextInt();
    }

    /**
     * 磁带化：把 VMP 的 {@code encVmp}（ChaCha20 密文流）重编码成磁带程序。
     *
     * @param encVmp    VMP 静态密文流（已做 opcode 置换 + twin + ChaCha20）
     * @param K         该方法 32 字节密钥（已 wrap，仅构建期可见）
     * @param buildSalt 每构建随机盐
     * @param level     BrainfuckShield 强度 0..3（诱饵密度；写入磁带 header）
     * @return 磁带程序（KBFT 头 + 码点流 + FNV-1a trailer），可直接存入 {@code $vmp_<n>}
     */
    public static byte[] shield(byte[] encVmp, byte[] K, int buildSalt, int level) {
        return BfDialect.encode(encVmp, K, buildSalt, level);
    }

    /**
     * 构建期自检：对 {@code encVmp} 执行 encode→decode 回环，必须逐字节还原。
     * 这是 build/runtime 两侧（{@code BfDialect} ↔ {@code BfInterpreter}）镜像
     * 一致性的回归护栏。
     */
    public static boolean verifyRoundTrip(byte[] encVmp, byte[] K, int buildSalt, int level) {
        try {
            byte[] tape = BfDialect.encode(encVmp, K, buildSalt, level);
            if (!BfDialect.hasMagic(tape)) return false;
            byte[] back = BfDialect.decode(tape, K);
            if (back == null || back.length != encVmp.length) return false;
            for (int i = 0; i < encVmp.length; i++) {
                if (back[i] != encVmp[i]) return false;
            }
            // 篡改护栏：翻转载荷一个字节，解码必须失败（trailer 生效）
            byte[] patched = tape.clone();
            patched[HEADER_PATCH_OFF(patched)] ^= 0x01;
            if (BfDialect.decode(patched, K) != null) return false;
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** 载荷区（header 之后）的末字节，翻转它应触发 trailer 失败。 */
    private static int HEADER_PATCH_OFF(byte[] tape) {
        int n = BfDialect.readInt(tape, 12);
        int payload = BfDialect.HEADER_LEN;
        return payload + Math.max(0, n - 1);
    }

    /** 统计信息：记录本次构建每个方法的磁带化结果（膨胀率）。 */
    public static void log(int idx, byte[] encVmp, byte[] tape, String key) {
        if (System.getProperty("kbox.bf.dump") == null) return;
        KBoxLog.info(TAG, "tape method[" + idx + "] " + key
                + " enc=" + encVmp.length + " tape=" + tape.length
                + " ratio=" + (tape.length * 100 / Math.max(encVmp.length, 1)) + "%");
    }
}
