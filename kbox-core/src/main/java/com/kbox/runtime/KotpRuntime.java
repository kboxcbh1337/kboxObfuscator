package com.kbox.runtime;

/**
 * K-OTP — Native-Seeded One-Time Program runtime.
 *
 * <p>构建期 {@code OtpMethodInjector} 把每个选中的方法体编译成 BFVM 指令流 {@code P}，
 * 然后用**只在原生库里存在的构建种子**派生的 keystream 计算 share：</p>
 *
 * <pre>
 *   A = P XOR ks(seed, site, epoch=0, chain=chain0)
 * </pre>
 *
 * <p>类文件里只保留 {@code A} 与状态 {@code long[]{epoch, chain}}，不含 {@code P}、
 * 也不含 {@code seed}（种子由 JNIC 原生库导出，原生库本身再做 KBNL + kboXShield 加壳）。
 * 静态分析即使拿到 A，也需要原生种子才能还原 P。</p>
 *
 * <p>每次调用结束后本类用 {@code nanoTime/线程 id/参数指纹} 重定密钥，并**就地重写 A**
 * （self-re-keying one-time program）：磁盘/内存中不存在一份稳定的、可反复反编译的程序，
 * 任何一次 dump 得到的 A 只对应一个已经结束的 epoch。</p>
 *
 * <p>线程安全：同一 site 的 share 数组作为监视器；Java 监视器可重入，因此递归方法安全。</p>
 */
public final class KotpRuntime {

    private KotpRuntime() {}

    /** 原生种子（由 JNIC 原生库的 registerNatives0 绑定）。 */
    private static native long nativeSeed();

    private static volatile long SEED;
    private static volatile boolean SEED_READY;
    private static volatile boolean SEED_FAILED;

    /** 取原生构建种子；失败抛错（K-OTP 明确依赖 JNIC 原生库）。 */
    public static long seed() {
        if (SEED_READY) return SEED;
        synchronized (KotpRuntime.class) {
            if (SEED_READY) return SEED;
            if (SEED_FAILED) throw new IllegalStateException("K-OTP native seed unavailable");
            try {
                // non-BF products put the JNIC lib in native.bin; BF products
                // put the BF decoder there and the JNIC lib in jnic.bin.
                try { NativeLoader.load(); } catch (Throwable ignored) { }
                try { NativeLoader.loadJnic(); } catch (Throwable ignored) { }
                // Bind nativeSeed() through the same RegisterNatives path JNIC uses
                // (works for classes defined by the guard / BF loader).
                java.lang.reflect.Method reg = NativeLoader.class
                        .getDeclaredMethod("registerNatives0", Class.class);
                reg.invoke(null, KotpRuntime.class);
                long s = nativeSeed();
                if (s == 0L) throw new UnsatisfiedLinkError("K-OTP seed is zero");
                SEED = s;
                SEED_READY = true;
                return s;
            } catch (Throwable t) {
                SEED_FAILED = true;
                throw new IllegalStateException("K-OTP native seed unavailable", t);
            }
        }
    }

    /**
     * Invoked by every K-OTP-transformed method body.
     *
     * @param site  per-build site id (also mixed into the keystream)
     * @param share current ciphertext share (mutated in place: next epoch's share)
     * @param st    {epoch, chain} — mutated in place
     */
    public static Object invoke(int site, byte[] share, long[] st,
                                Class<?> owner, Object self, Object[] args) {
        if (share == null || st == null || st.length < 2) {
            throw new IllegalStateException("K-OTP state missing");
        }
        Object[] a = args == null ? new Object[0] : args;
        ClassLoader loader = pickLoader(owner, self, a);
        long seed = seed();
        byte[] prog;
        // Decrypt + immediately re-key under the per-site lock, then release it
        // BEFORE running user code. This keeps the plaintext window minimal and
        // avoids nested monitor acquisition (method A -> method B -> method A)
        // deadlocking across threads when two threads traverse in opposite order.
        synchronized (share) {
            long epoch = st[0];
            long chain = st[1];
            prog = new byte[share.length];
            long x = initialState(seed, site, epoch, chain);
            for (int i = 0; i < prog.length; i++) {
                prog[i] = (byte) (share[i] ^ byteOf(x));
                x = advance(x);
            }
            // A_{epoch+1} = P XOR ks(seed, site, epoch+1, chain')
            long ne = epoch + 1;
            long nch = mixChain(chain, site, ne, System.nanoTime(),
                    Thread.currentThread().getId(), argFingerprint(a));
            long nx = initialState(seed, site, ne, nch);
            for (int i = 0; i < share.length; i++) {
                share[i] = (byte) (prog[i] ^ byteOf(nx));
                nx = advance(nx);
            }
            st[0] = ne;
            st[1] = nch;
        }
        try {
            return com.kbox.runtime.bfvm.VmCore.execute(prog, owner, self, a, loader);
        } finally {
            java.util.Arrays.fill(prog, (byte) 0);
        }
    }

    // ---- keystream (shared verbatim by the build-time injector) ----

    /** Build-time expansion of the raw native constant (mirrored in the generated C). */
    public static long expand(long raw) {
        long s = raw;
        return s ^ (s >>> 33) ^ 0xA24BAED4963EE407L;
    }

    /** Decode ISO-8859-1 chunks emitted by {@code OtpMethodInjector} into a byte[]. */
    public static byte[] decode(String[] parts) {
        int n = 0;
        for (String p : parts) n += p.length();
        byte[] b = new byte[n];
        int o = 0;
        for (String p : parts) {
            for (int i = 0; i < p.length(); i++) b[o++] = (byte) p.charAt(i);
        }
        return b;
    }

    /** Initial xorshift64* state for one invocation. */
    public static long initialState(long seed, int site, long epoch, long chain) {
        long x = seed
                ^ (site * 0x9E3779B97F4A7C15L)
                ^ mix64(epoch + 0x165667B19E3779F9L)
                ^ mix64(chain + 0x27D4EB2F165667C5L);
        return x == 0 ? 0x9E3779B97F4A7C15L : x;
    }

    /** Next keystream byte for the current state (does not advance it). */
    public static byte byteOf(long x) {
        return (byte) ((x * 0x2545F4914F6CDD1DL) >>> 56);
    }

    /** Advance the xorshift64* state after emitting the byte. */
    public static long advance(long x) {
        x ^= x >>> 12;
        x ^= x << 25;
        x ^= x >>> 27;
        return x;
    }

    /** Materialise the full keystream (build-time convenience). */
    public static byte[] keystream(long seed, int site, long epoch, long chain, int len) {
        byte[] out = new byte[len];
        long x = initialState(seed, site, epoch, chain);
        for (int i = 0; i < len; i++) {
            out[i] = byteOf(x);
            x = advance(x);
        }
        return out;
    }

    private static long mix64(long z) {
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    private static long mixChain(long chain, int site, long epoch, long nano, long tid, int argHash) {
        long h = mix64(chain ^ 0x243F6A8885A308D3L);
        h = mix64(h + site);
        h = mix64(h + epoch);
        h = mix64(h ^ nano);
        h = mix64(h ^ tid);
        h = mix64(h ^ argHash);
        return h;
    }

    private static int argFingerprint(Object[] a) {
        int h = 0x811C9DC5;
        for (int i = 0; i < a.length; i++) {
            Object v = a[i];
            h = (h ^ (v == null ? 0 : v.hashCode())) * 0x01000193;
        }
        return h;
    }

    private static ClassLoader pickLoader(Class<?> owner, Object self, Object[] args) {
        if (owner != null && owner.getClassLoader() != null) return owner.getClassLoader();
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl != null) return cl;
        if (self != null && self.getClass().getClassLoader() != null) {
            return self.getClass().getClassLoader();
        }
        for (Object a : args) {
            if (a != null && a.getClass().getClassLoader() != null) {
                return a.getClass().getClassLoader();
            }
        }
        ClassLoader own = KotpRuntime.class.getClassLoader();
        return own != null ? own : ClassLoader.getSystemClassLoader();
    }
}
