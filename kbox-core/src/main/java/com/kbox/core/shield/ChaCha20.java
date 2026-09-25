package com.kbox.core.shield;

/**
 * ChaCha20 — 流密码（RFC 8439 布局：32 位块计数器 + 96 位 nonce）。
 * 由 packer/chacha20.cpp 移植；与 stub 中的汇编实现保持逐字节一致的输出。
 */
public final class ChaCha20 {

    private final int[] state = new int[16];
    private final byte[] block = new byte[64];
    private int counter;
    private int blockPos = 64;

    /**
     * @param key     32 字节密钥
     * @param nonce   12 字节 nonce（RFC 8439 96 位）
     * @param counter 32 位起始块计数
     */
    public void init(byte[] key, int keyOff, byte[] nonce, int nonceOff, int counter) {
        state[0] = 0x61707865;
        state[1] = 0x3320646E;
        state[2] = 0x79622D32;
        state[3] = 0x6B206574;
        for (int i = 0; i < 8; i++) {
            state[4 + i] = Bin.i32(key, keyOff + 4 * i);
        }
        // RFC 8439：state[12] = 32 位计数器，state[13..15] = 96 位 nonce
        state[12] = counter;
        state[13] = Bin.i32(nonce, nonceOff);
        state[14] = Bin.i32(nonce, nonceOff + 4);
        state[15] = Bin.i32(nonce, nonceOff + 8);
        this.counter = counter;
        this.blockPos = 64; // 强制首轮重新生成
    }

    public void init(byte[] key, byte[] nonce, int counter) {
        init(key, 0, nonce, 0, counter);
    }

    /** 当前块计数（生成 len 字节后 = 起始计数 + len/64）。 */
    public int counter() {
        return counter;
    }

    private static int rotl(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    private static void quarterRound(int[] w, int a, int b, int c, int d) {
        w[a] += w[b];
        w[d] ^= w[a];
        w[d] = rotl(w[d], 16);
        w[c] += w[d];
        w[b] ^= w[c];
        w[b] = rotl(w[b], 12);
        w[a] += w[b];
        w[d] ^= w[a];
        w[d] = rotl(w[d], 8);
        w[c] += w[d];
        w[b] ^= w[c];
        w[b] = rotl(w[b], 7);
    }

    private void nextBlock() {
        int[] ws = new int[16];
        System.arraycopy(state, 0, ws, 0, 16);
        for (int i = 0; i < 10; i++) {
            quarterRound(ws, 0, 4, 8, 12);
            quarterRound(ws, 1, 5, 9, 13);
            quarterRound(ws, 2, 6, 10, 14);
            quarterRound(ws, 3, 7, 11, 15);
            quarterRound(ws, 0, 5, 10, 15);
            quarterRound(ws, 1, 6, 11, 12);
            quarterRound(ws, 2, 7, 8, 13);
            quarterRound(ws, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) {
            Bin.w32(block, 4 * i, ws[i] + state[i]);
        }
        // 递增 32 位块计数（RFC 8439：回绕不清零 nonce，与 stub 汇编一致）
        state[12]++;
        counter++;
    }

    /** 仅生成 keystream。 */
    public void keystream(byte[] out, int outOff, int len) {
        int pos = 0;
        while (pos < len) {
            if (blockPos == 64) {
                nextBlock();
                blockPos = 0;
            }
            int take = 64 - blockPos;
            if (take > len - pos) {
                take = len - pos;
            }
            System.arraycopy(block, blockPos, out, outOff + pos, take);
            blockPos += take;
            pos += take;
        }
    }

    /** 生成 keystream 并 XOR 到 dst（与 in 相同则原地加密）。 */
    public void crypt(byte[] dst, int dstOff, byte[] in, int inOff, int len) {
        int pos = 0;
        while (pos < len) {
            if (blockPos == 64) {
                nextBlock();
                blockPos = 0;
            }
            int take = 64 - blockPos;
            if (take > len - pos) {
                take = len - pos;
            }
            for (int i = 0; i < take; i++) {
                dst[dstOff + pos + i] = (byte) (in[inOff + pos + i] ^ block[blockPos + i]);
            }
            blockPos += take;
            pos += take;
        }
    }
}
