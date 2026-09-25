package com.kbox.core.shield;

/**
 * Bin — 小端字节序读写工具（kboXShield 移植版）。
 *
 * <p>C++ 侧全部为 packed 结构与原生小端访问；Java 侧统一经此类完成，
 * 偏移与宽度与 include/kbox_format.h、pe_image.h 严格一致。</p>
 */
public final class Bin {

    private Bin() {
    }

    // ---- 读 ----

    public static int u8(byte[] b, int off) {
        return b[off] & 0xFF;
    }

    public static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    public static int i32(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }

    public static long i64(byte[] b, int off) {
        return (i32(b, off) & 0xFFFFFFFFL) | ((long) i32(b, off + 4) << 32);
    }

    /** 读取 u32 并以无符号 long 返回（用于地址/大小比较）。 */
    public static long u32(byte[] b, int off) {
        return i32(b, off) & 0xFFFFFFFFL;
    }

    // ---- 写 ----

    public static void w8(byte[] b, int off, int v) {
        b[off] = (byte) v;
    }

    public static void w16(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
    }

    public static void w32(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }

    public static void w64(byte[] b, int off, long v) {
        w32(b, off, (int) v);
        w32(b, off + 4, (int) (v >>> 32));
    }

    // ---- 追加写（动态缓冲用） ----

    public static void a32(java.io.ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >>> 8) & 0xFF);
        o.write((v >>> 16) & 0xFF);
        o.write((v >>> 24) & 0xFF);
    }

    public static void a16(java.io.ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >>> 8) & 0xFF);
    }

    // ---- 子区间 ----

    public static byte[] slice(byte[] src, int off, int len) {
        byte[] r = new byte[len];
        System.arraycopy(src, off, r, 0, len);
        return r;
    }

    /** ASCII 字符串（'\0' 结尾），用于节名与 DLL 名。 */
    public static String cstr(byte[] b, int off, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < max && off + i < b.length; i++) {
            int c = b[off + i] & 0xFF;
            if (c == 0) {
                break;
            }
            sb.append((char) c);
        }
        return sb.toString();
    }

    /** 节名：8 字节定长，'\0' 结尾或占满。 */
    public static String sectionName(byte[] b, int off) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            int c = b[off + i] & 0xFF;
            if (c == 0) {
                break;
            }
            sb.append((char) c);
        }
        return sb.toString();
    }

    /** 对齐到 align（align 为 2 的幂）。 */
    public static int alignUp(int v, int align) {
        return (v + align - 1) & ~(align - 1);
    }

    public static long alignUp(long v, long align) {
        return (v + align - 1) & ~(align - 1);
    }

    /** 字符串按 ASCII 编码，带 '\0' 结尾。 */
    public static byte[] asciiZ(String s) {
        byte[] raw = s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] r = new byte[raw.length + 1];
        System.arraycopy(raw, 0, r, 0, raw.length);
        return r;
    }
}
