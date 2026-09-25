package com.kbox.core.shield;

/**
 * BlobLayout — stub blob 内的符号偏移（由 stub 构建脚本生成的
 * stub_layout_x64.h / stub_layout_x86.h 移植）。
 *
 * <p>blob 布局契约（见 {@link KboxFormat}）：
 * [0x000..0x100) KboxConfig（packer 填充）→ [0x100...) 入口代码与数据 →
 * 页对齐的 .iat 段（loader 回填 stub 自身 IAT）。</p>
 *
 * <p>这些偏移由 MSYS2 mingw-w64 binutils 对 stub_x64.S / stub_x86.S 汇编后
 * 取符号 VMA 得出，禁止手改。</p>
 */
public final class BlobLayout {

    private BlobLayout() {
    }

    /** x86-64 (PE32+) stub 布局。 */
    public static final class X64 {
        private X64() {
        }

        /** AddressOfEntryPoint = stub_rva + 此值。 */
        public static final int BLOB_ENTRY_OFF = 256;
        /** kbox_chacha 内部例程。 */
        public static final int BLOB_CHACHA_OFF = 2099;
        /** stub 自身 IAT（loader 回填目标）。 */
        public static final int BLOB_IAT_OFF = 24576;
        /** secA（代码，RX）/ secB（数据，RWX）切分点。 */
        public static final int BLOB_CODE_END_OFF = 20480;
        /** kbox_vm_dispatch（虚拟化函数跳转目标）。 */
        public static final int BLOB_DISPATCH_OFF = 1800;
        /** G2：防御字符串池起始偏移。 */
        public static final int BLOB_STRPOOL_OFF = 13457;
        /** G2：防御字符串池结束偏移。 */
        public static final int BLOB_DEFENSE_END_OFF = 13706;
        /** 方案A：配置区加密种子槽偏移。 */
        public static final int BLOB_CFGROOT_OFF = 1792;
        /** 方案E：随机填充区起始。 */
        public static final int BLOB_JUNK_START_OFF = 13712;
        /** 方案E：随机填充区结束。 */
        public static final int BLOB_JUNK_END_OFF = 19856;
        /** blob 总字节数（payload 紧随其后）。 */
        public static final int BLOB_SIZE = 28672;
    }

    /** x86 (PE32) stub 布局。 */
    public static final class X86 {
        private X86() {
        }

        public static final int BLOB_ENTRY_OFF = 256;
        public static final int BLOB_CHACHA_OFF = 3825;
        public static final int BLOB_IAT_OFF = 24576;
        /** secA（代码，RX）/ secB（数据，RWX）切分点。 */
        public static final int BLOB_CODE_END_OFF = 20480;
        /** x86 stub 未导出独立 dispatch 桩（与原始构建一致）。 */
        public static final int BLOB_DISPATCH_OFF = 0;
        public static final int BLOB_STRPOOL_OFF = 3576;
        public static final int BLOB_DEFENSE_END_OFF = 3825;
        public static final int BLOB_CFGROOT_OFF = 1336;
        public static final int BLOB_JUNK_START_OFF = 12704;
        public static final int BLOB_JUNK_END_OFF = 18848;
        public static final int BLOB_SIZE = 28672;
    }

    // ---- 按架构取值的辅助入口 ----

    public static int entryOff(boolean is64) {
        return is64 ? X64.BLOB_ENTRY_OFF : X86.BLOB_ENTRY_OFF;
    }

    public static int iatOff(boolean is64) {
        return is64 ? X64.BLOB_IAT_OFF : X86.BLOB_IAT_OFF;
    }

    /** secA（代码节）/ secB（数据节）的切分偏移（= 代码段字节数）。 */
    public static int codeEndOff(boolean is64) {
        return is64 ? X64.BLOB_CODE_END_OFF : X86.BLOB_CODE_END_OFF;
    }

    public static int dispatchOff(boolean is64) {
        return is64 ? X64.BLOB_DISPATCH_OFF : X86.BLOB_DISPATCH_OFF;
    }

    public static int strpoolOff(boolean is64) {
        return is64 ? X64.BLOB_STRPOOL_OFF : X86.BLOB_STRPOOL_OFF;
    }

    public static int defenseEndOff(boolean is64) {
        return is64 ? X64.BLOB_DEFENSE_END_OFF : X86.BLOB_DEFENSE_END_OFF;
    }

    public static int cfgRootOff(boolean is64) {
        return is64 ? X64.BLOB_CFGROOT_OFF : X86.BLOB_CFGROOT_OFF;
    }

    public static int junkStartOff(boolean is64) {
        return is64 ? X64.BLOB_JUNK_START_OFF : X86.BLOB_JUNK_START_OFF;
    }

    public static int junkEndOff(boolean is64) {
        return is64 ? X64.BLOB_JUNK_END_OFF : X86.BLOB_JUNK_END_OFF;
    }

    public static int blobSize(boolean is64) {
        return is64 ? X64.BLOB_SIZE : X86.BLOB_SIZE;
    }

    public static int chachaOff(boolean is64) {
        return is64 ? X64.BLOB_CHACHA_OFF : X86.BLOB_CHACHA_OFF;
    }
}
