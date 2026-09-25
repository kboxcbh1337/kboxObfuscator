package com.kbox.core.shield;

/**
 * VmKs — VM 镜像 keystream 生成（builder 与 engine 共享）。
 * 由 packer/vm/vm_ks.cpp 移植。
 */
public final class VmKs {

    private VmKs() {
    }

    /**
     * 按绝对偏移生成 64 字节 keystream 块：counter = pos&gt;&gt;6，块内偏移 pos&amp;63。
     *
     * @param k8      8 个 u32 组成的 256 位密钥（小端展平）
     * @param counter 块计数
     * @param out     长度至少 64
     */
    public static void vmKsBlock(int[] k8, int counter, byte[] out, int outOff) {
        byte[] key = new byte[32];
        for (int i = 0; i < 8; i++) {
            Bin.w32(key, 4 * i, k8[i]);
        }
        byte[] nonce = new byte[12];
        ChaCha20 cc = new ChaCha20();
        cc.init(key, 0, nonce, 0, counter);
        cc.keystream(out, outOff, 64);
    }

    public static void vmKsBlock(int[] k8, int counter, byte[] out) {
        vmKsBlock(k8, counter, out, 0);
    }
}
