package com.kbox.core.packaging;

import com.kbox.core.log.KBoxLog;

/**
 * ELF / Mach-O 结构加固（so / dylib 的“适配加壳”）。
 *
 * <p><b>为什么需要它</b>：KBNL（DEFLATE + ChaCha20）保证产物 jar 里没有明文原生库，但
 * {@code NativeLoader} 在运行期会把解密后的库**落盘到临时文件**再 {@code System.load}。
 * 落盘/被 dump 的瞬间，一个未处理的 {@code .so}/{@code .dylib} 仍带着**完整的符号表与节名**
 * （函数名、变量名、`.comment` 编译器指纹）——这是逆向者最容易的入口。</p>
 *
 * <p><b>本类做什么（真实性边界）</b>：对 ELF/Mach-O 做**结构性去元数据**，使解密落盘后的镜像
 * 不再包含可直接读取的符号/节名；随后仍走 KBNL 加密。它<em>不是</em> PE 侧的“函数级虚拟化壳”——
 * 本仓库的 shell/engine 资产是 PE 专用的手写汇编 blob，为 ELF/Mach-O 实现等价的加载器 stub
 * 需要按格式+架构重写并在 Linux/macOS 上端到端验证，本环境不具备，故**明确不做空头承诺**。</p>
 *
 * <h3>ELF</h3>
 * 装载器运行期只用 program header（{@code PT_LOAD}/{@code PT_DYNAMIC}）与动态段 DT_*，
 * **不使用** section header table。因此可安全地把节头表整段清零并置 {@code e_shoff=e_shnum=e_shstrndx=0}：
 * 符号表、字符串表、`.comment` 的**名字与索引**随之消失。
 *
 * <h3>Mach-O（thin）</h3>
 * dyld 使用 LC_SEGMENT/LC_DYLD_INFO/导出 trie，**不使用** LC_SYMTAB 指向的 nlist/字符串表。
 * 因而把 LC_SYMTAB 的符号表与字符串表区间清零即可（等价于激进的 strip），头与 load commands 保持不变。
 *
 * <p>两类改写都**只**触碰上述非装载元数据区间，头与装载相关字节保持逐字节不变；改写后
 * 由 {@link #validateElf}/{@link #validateMachO} 自检。</p>
 */
public final class NativeBinaryHardener {

    private static final String TAG = "bin-harden";

    private NativeBinaryHardener() {
    }

    /** 加固结果：字节 + 说明（用于覆盖报告）。 */
    public static final class Result {
        public final byte[] bytes;
        public final String note;
        Result(byte[] bytes, String note) { this.bytes = bytes; this.note = note; }
    }

    /** 按格式分派；不适用时返回 {@code null}（调用方降级为纯加密）。 */
    public static Result harden(String ext, byte[] in) {
        if (in == null || in.length < 64) return null;
        try {
            if ("so".equals(ext)) return hardenElf(in);
            if ("dylib".equals(ext)) return hardenMachO(in);
        } catch (Throwable t) {
            KBoxLog.warn(TAG, "harden(" + ext + ") failed: " + t);
        }
        return null;
    }

    // ------------------------------------------------------------------
    // ELF
    // ------------------------------------------------------------------

    /** @return 加固后的 ELF，或 {@code null}（非 ELF / 结构不满足安全前提）。 */
    public static Result hardenElf(byte[] in) {
        if (in.length < 0x40) return null;
        if ((in[0] & 0xFF) != 0x7F || in[1] != 'E' || in[2] != 'L' || in[3] != 'F') return null;
        int eiClass = in[4] & 0xFF;   // 1 = 32-bit, 2 = 64-bit
        int eiData = in[5] & 0xFF;    // 1 = LE, 2 = BE
        if (eiData != 1 && eiData != 2) return null;
        boolean be = eiData == 2;
        if (eiClass != 1 && eiClass != 2) return null;

        long shoff;
        int shentsize, shnum, shstrndx;
        if (eiClass == 2) {                       // ELF64
            shoff = rd64(in, 0x28, be);
            shentsize = rd16(in, 0x3A, be);
            shnum = rd16(in, 0x3C, be);
            shstrndx = rd16(in, 0x3E, be);
        } else {                                  // ELF32
            shoff = rd32(in, 0x20, be);
            shentsize = rd16(in, 0x2E, be);
            shnum = rd16(in, 0x30, be);
            shstrndx = rd16(in, 0x32, be);
        }
        // 仅在没有节头表或结构异常时跳过（此时无可去的元数据）。
        if (shoff <= 0 || shnum <= 0 || shentsize < 40) return null;
        long end = shoff + (long) shnum * shentsize;
        if (shoff >= in.length || end > in.length) return null;

        byte[] out = in.clone();
        // 清零节头表（符号表/节名/编译器指纹的索引随之不可解析）。
        java.util.Arrays.fill(out, (int) shoff, (int) end, (byte) 0);
        // 置空节表指针。
        if (eiClass == 2) {
            wr64(out, 0x28, 0, be);
            wr16(out, 0x3C, 0, be);
            wr16(out, 0x3E, 0, be);
        } else {
            wr32(out, 0x20, 0, be);
            wr16(out, 0x30, 0, be);
            wr16(out, 0x32, 0, be);
        }
        if (!validateElf(in, out)) return null;
        return new Result(out, "elf: section-header-table removed (shoff=" + shoff
                + ", shnum=" + shnum + ", entries=" + (shnum * shentsize) + "B zeroed, shstrndx=" + shstrndx + ")");
    }

    /** 自检：仅节头表区间与其指针变化，其余（含 program headers）逐字节一致。 */
    static boolean validateElf(byte[] before, byte[] after) {
        if (before.length != after.length) return false;
        boolean be = (before[5] & 0xFF) == 2;
        int eiClass = before[4] & 0xFF;
        long shoff;
        int shentsize, shnum;
        if (eiClass == 2) {
            shoff = rd64(before, 0x28, be);
            shentsize = rd16(before, 0x3A, be);
            shnum = rd16(before, 0x3C, be);
        } else {
            shoff = rd32(before, 0x20, be);
            shentsize = rd16(before, 0x2E, be);
            shnum = rd16(before, 0x30, be);
        }
        long end = shoff + (long) shnum * shentsize;
        for (int i = 0; i < before.length; i++) {
            boolean inTable = i >= shoff && i < end;
            boolean inPtrs = pointerField(eiClass, i);
            if (inTable || inPtrs) continue;
            if (before[i] != after[i]) return false;
        }
        // 节表区间必须已清零。
        for (int i = (int) shoff; i < end; i++) if (after[i] != 0) return false;
        return true;
    }

    private static boolean pointerField(int eiClass, int off) {
        if (eiClass == 2) return off >= 0x28 && off < 0x30 || off >= 0x3C && off < 0x40;
        return off >= 0x20 && off < 0x24 || off >= 0x30 && off < 0x34;
    }

    // ------------------------------------------------------------------
    // Mach-O (thin)
    // ------------------------------------------------------------------

    /** @return 加固后的 Mach-O，或 {@code null}（非 thin Mach-O / 无可去符号）。 */
    public static Result hardenMachO(byte[] in) {
        if (in.length < 32) return null;
        int m = ((in[0] & 0xFF) << 24) | ((in[1] & 0xFF) << 16) | ((in[2] & 0xFF) << 8) | (in[3] & 0xFF);
        boolean le = (m == 0xCEFAEDFE || m == 0xCFFAEDFE);   // 磁盘：LE 32 / LE 64
        boolean be = (m == 0xFEEDFACE || m == 0xFEEDFACF);   // 磁盘：BE 32 / BE 64
        if (!le && !be) return null;                          // FAT/other: skip
        boolean is64 = (m == 0xCFFAEDFE || m == 0xFEEDFACF);
        int headerSize = is64 ? 32 : 28;
        if (in.length < headerSize) return null;
        int ncmds = (int) rd32m(in, 16, le);
        int sizeofcmds = (int) rd32m(in, 20, le);
        if (ncmds <= 0 || sizeofcmds <= 0 || headerSize + sizeofcmds > in.length) return null;

        byte[] out = in.clone();
        long removed = 0;
        int off = headerSize;
        for (int i = 0; i < ncmds && off + 8 <= headerSize + sizeofcmds; i++) {
            int cmd = (int) rd32m(in, off, le);
            int cmdsize = (int) rd32m(in, off + 4, le);
            if (cmdsize < 8 || off + cmdsize > in.length) break;
            if (cmd == 0x2) {   // LC_SYMTAB: symoff(8) nsyms(12) stroff(16) strsize(20)
                long symoff = rd32m(in, off + 8, le) & 0xFFFFFFFFL;
                long nsyms = rd32m(in, off + 12, le) & 0xFFFFFFFFL;
                long stroff = rd32m(in, off + 16, le) & 0xFFFFFFFFL;
                long strsize = rd32m(in, off + 20, le) & 0xFFFFFFFFL;
                removed += zeroRange(out, symoff, nsyms * 16L);   // nlist_64 = 16B
                removed += zeroRange(out, stroff, strsize);
            }
            off += cmdsize;
        }
        if (removed == 0) return null;   // 没有符号表可去
        if (!validateMachO(in, out, headerSize, ncmds, sizeofcmds, le)) return null;
        return new Result(out, "macho: LC_SYMTAB tables zeroed (" + removed + "B)");
    }

    /** 自检：header + load commands 区间逐字节不变。 */
    static boolean validateMachO(byte[] before, byte[] after, int headerSize, int ncmds, int sizeofcmds, boolean le) {
        if (before.length != after.length) return false;
        int end = headerSize + sizeofcmds;
        for (int i = 0; i < end; i++) if (before[i] != after[i]) return false;
        return true;
    }

    private static long zeroRange(byte[] b, long off, long len) {
        if (off <= 0 || len <= 0) return 0;
        long end = off + len;
        if (end > b.length) return 0;
        java.util.Arrays.fill(b, (int) off, (int) end, (byte) 0);
        return len;
    }

    // ------------------------------------------------------------------
    // little/big-endian header readers
    // ------------------------------------------------------------------

    private static int rd16(byte[] b, int o, boolean be) {
        int a = b[o] & 0xFF, c = b[o + 1] & 0xFF;
        return be ? (a << 8) | c : a | (c << 8);
    }

    private static long rd32(byte[] b, int o, boolean be) {
        long a = b[o] & 0xFF, c = b[o + 1] & 0xFF, d = b[o + 2] & 0xFF, e = b[o + 3] & 0xFF;
        return be ? (a << 24) | (c << 16) | (d << 8) | e : a | (c << 8) | (d << 16) | (e << 24);
    }

    private static long rd64(byte[] b, int o, boolean be) {
        long v = 0;
        if (be) for (int i = 0; i < 8; i++) v = (v << 8) | (b[o + i] & 0xFF);
        else for (int i = 7; i >= 0; i--) v = (v << 8) | (b[o + i] & 0xFF);
        return v;
    }

    private static void wr16(byte[] b, int o, int v, boolean be) {
        if (be) { b[o] = (byte) (v >>> 8); b[o + 1] = (byte) v; }
        else { b[o] = (byte) v; b[o + 1] = (byte) (v >>> 8); }
    }

    private static void wr32(byte[] b, int o, int v, boolean be) {
        if (be) { for (int i = 0; i < 4; i++) b[o + i] = (byte) (v >>> (24 - 8 * i)); }
        else { for (int i = 0; i < 4; i++) b[o + i] = (byte) (v >>> (8 * i)); }
    }

    private static void wr64(byte[] b, int o, long v, boolean be) {
        if (be) { for (int i = 0; i < 8; i++) b[o + i] = (byte) (v >>> (56 - 8 * i)); }
        else { for (int i = 0; i < 8; i++) b[o + i] = (byte) (v >>> (8 * i)); }
    }

    /** Mach-O 头字段读取（le 表示磁盘字节序为小端）。 */
    private static long rd32m(byte[] b, int o, boolean le) {
        long a = b[o] & 0xFF, c = b[o + 1] & 0xFF, d = b[o + 2] & 0xFF, e = b[o + 3] & 0xFF;
        return le ? a | (c << 8) | (d << 16) | (e << 24) : (a << 24) | (c << 16) | (d << 8) | e;
    }
}
