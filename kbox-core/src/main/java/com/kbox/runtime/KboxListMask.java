package com.kbox.runtime;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * 清单文件（{@code META-INF/kbox/jnic-classes.list} / {@code method_epd.bin} 等）的轻量遮蔽。
 *
 * <p>这些清单本身不含密钥，但<b>明文躺平</b>会把"哪些类/哪些方法被重保护"直接告诉逆向者
 * ——v3.0.1 强度测试报告的 P0-3 正是此处的 827 条方法与 100 条类名清单。</p>
 *
 * <p>遮蔽方式：用构建种子（{@code META-INF/kbox/seed.bin}，每构建唯一）派生的
 * SHA-256 keystream 做 XOR。XOR 自反，因此编码与解码是同一个函数；没有种子时
 * 原样返回（调用方据此回落到明文兼容路径）。</p>
 */
public final class KboxListMask {

    private KboxListMask() {}

    /** XOR 遮蔽/还原（同一函数）。{@code seed} 为空时原样返回。 */
    public static byte[] mask(byte[] data, byte[] seed) {
        if (data == null || data.length == 0) return data;
        if (seed == null || seed.length == 0) return data;
        byte[] out = new byte[data.length];
        byte[] ks = null;
        int ki = 0;
        int counter = 0;
        for (int i = 0; i < data.length; i++) {
            if (ks == null || ki == ks.length) {
                ks = block(seed, counter++);
                ki = 0;
            }
            out[i] = (byte) (data[i] ^ ks[ki++]);
        }
        return out;
    }

    /**
     * 还原一个被遮蔽的清单：先 XOR，再做"看起来像清单吗"的健全性检查。
     *
     * <p>不能要求存在 {@code '/'}：默认包（无名包）里的类名就是 {@code l}、{@code a$b}
     * 这种形式，不含包分隔符。早先按"必须含 '/'"判定会把合法清单判为无效，调用方
     * 回落到明文解析、把密文当类名，JNIC 类因此从不触发 {@code RegisterNatives}
     * （实测报 {@code UnsatisfiedLinkError: 'int l.y(int)'}）。现在改为逐行校验
     * "整行是合法的内部类名"，既能接受默认包类，也能拒绝二进制垃圾。</p>
     */
    public static String unmaskText(byte[] data, byte[] seed) {
        byte[] plain = mask(data, seed);
        for (byte b : plain) {
            if (b == '\n' || b == '\r' || b == '\t') continue;
            if (b < 0x20 || b > 0x7e) return null;
        }
        String text = new String(plain, StandardCharsets.UTF_8);
        if (text.isEmpty()) return null;
        int lines = 0;
        for (String line : text.split("\n")) {
            line = line.trim();
            if (line.isEmpty()) continue;
            if (!isInternalClassLine(line)) return null;
            lines++;
        }
        return lines == 0 ? null : text;
    }

    /** 单行是否为合法的内部类名（允许默认包，即不含任何 '/'）。 */
    private static boolean isInternalClassLine(String s) {
        boolean segStart = true;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '/') {
                if (segStart) return false;   // 空包段
                segStart = true;
                continue;
            }
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '$';
            if (!ok) return false;
            segStart = false;
        }
        return !segStart;   // 不能以 '/' 结尾
    }

    private static byte[] block(byte[] seed, int counter) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(seed);
            md.update((byte) (counter >>> 24));
            md.update((byte) (counter >>> 16));
            md.update((byte) (counter >>> 8));
            md.update((byte) counter);
            return md.digest();
        } catch (Exception e) {
            return new byte[32];
        }
    }
}
