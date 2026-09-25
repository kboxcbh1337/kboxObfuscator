package com.kbox.core.shield;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.kbox.core.log.KBoxLog;

/**
 * ShieldPacker — kboXShield 打包主程序（由 packer/main.cpp 逐行移植）。
 *
 * <p>原文件头注释（main.cpp）：</p>
 * <pre>
 * 用法: kbox_packer &lt;input.exe&gt; &lt;output.exe&gt;
 *
 * 流程:
 *   1. 解析输入 PE（PE32/PE32+）
 *   2. 生成会话密钥（/dev/urandom）
 *   3. 用 ChaCha20 全量加密各节 raw 区（每节独立 nonce + counter=0）
 *   4. 构建载荷 payload（明文）:
 *        [KboxPayloadHdr][SectionRec×n][ImpDll+entries×m][reloc][字符串区]
 *      字符串区置于 reloc 之后（stub 通过跳过定长记录定位 reloc，字符串不干扰）
 *   5. 加密 payload（config 的 key/nonce, counter=0）
 *   6. 组装 stub 节:
 *        [KboxConfig][blob][pad][加密 payload][pad][合成导入表][pad]
 *        [VM 镜像][pad][运行期汇编引擎 blob]
 *   7. 重建 PE 头: 追加新节、入口指向 stub、Import→合成导入表、
 *      BaseReloc/Security/TLS/LoadConfig/CLR 目录清零
 *
 * 运行期由 stub 完成: 取基址→VM 自检(汇编引擎)→解密 payload→解密各节
 *                     →重建 IAT→重定位→跳 OEP
 * </pre>
 *
 * <h3>随机数（PRNG）复刻依据</h3>
 * <p>逐行核对 packer/main.cpp 后确认：<b>main.cpp 内不存在 {@code std::mt19937} /
 * {@code std::uniform_int_distribution}／{@code std::shuffle}</b>。全部随机性来自两处：</p>
 * <ol>
 *   <li>{@code random_bytes(uint8_t*, size_t)}（main.cpp:88-109）：首选读取
 *       {@code /dev/urandom}；打不开时退化为 <b>64 位 LCG</b>
 *       {@code s = s * 6364136223846793005ull + 1442695040888963407ull}，
 *       取 {@code (uint8_t)(s >> 33)} 作字节（种子 {@code 0x9E3779B9_7F4A7C15}）；
 *       读满不足时按 {@code s = 种子 ^ (got+1)} 续填（防御性分支）。
 *       Java 侧对应实现见 {@link #randomBytes(byte[], int, int)}
 *       （主路径 {@link java.security.SecureRandom}，异常时走同参数 LCG
 *       {@link #lcgBytes(byte[], int, int, long)}，long 溢出即 2^64 回绕、
 *       与 C++ {@code uint64_t} 语义逐位一致）。</li>
 *   <li>配置区加密流（main.cpp:859-863）：<b>32 位截断 LCG</b>
 *       {@code st = st * 1664525u + 1013904223u}，密钥字节 {@code (uint8_t)(st >> 16)}，
 *       逐字节 XOR {@code [0,0x100)}；该流与 stub 的 {@code .Lcfg_loop} 必须逐字节一致，
 *       故必须以 int（32 位回绕）精确复刻——见配置区加密块内联实现。</li>
 * </ol>
 * <p>{@code std::mt19937} 仅出现于 packer/vm/vm_builder.cpp（VM handler 多态随机化），
 * 已由本工程 {@code VmBuilder.java} 内部私有复刻，本类不重复实现亦不依赖其内部实现。</p>
 *
 * <p>移植说明（类型/接口映射）：{@code std::vector&lt;uint8_t&gt;} → 本类私有 {@link Vec}
 * （支持 {@code resize(n,0)} 增长清零与顺序 {@code insert}，与 C++ 语义一致）；
 * offset/size 一律 int（0..2^31-1），无符号比较用 {@link Integer#compareUnsigned}，
 * uint64_t → long 且逻辑右移用 {@code >>>}；{@code _binary_*_start/_end} 二进制资产
 * 改为 classpath 资源 {@code /shield/*.bin}（{@link #loadAsset(String)}）。</p>
 */
public final class ShieldPacker {

    private ShieldPacker() {
    }

    private static final String TAG = "kbox_packer";

    // ================= 可编程入口 =================

    /**
     * 打包入口（对应 C++ {@code int main(int argc, char** argv)} 的参数解析部分）。
     *
     * @param args 命令行参数（不含程序名）：{@code <input.exe> <output.exe>}；{@code -h/--help} 打印用法
     * @return 进程退出码：0 成功；1 打包失败；2 参数错误
     */
    public static int run(String[] args) {
        if (args != null && args.length == 1
                && ("--help".equals(args[0]) || "-h".equals(args[0]))) {
            usage(System.out);
            return 0;
        }
        if (args == null || args.length != 2) {
            usage(System.err);
            return 2;
        }
        StringBuilder log = new StringBuilder();
        return packCore(args[0], args[1], new ShieldOptions(), log);
    }

    /**
     * 可编程打包入口（便于与混淆器 CLI 集成）。
     *
     * @param inPath  输入 PE
     * @param outPath 输出 PE（打壳后）
     * @param log     可选；追加全部日志行（成功与失败）
     * @return true 表示打包成功
     */
    public static boolean pack(String inPath, String outPath, StringBuilder log) {
        return pack(inPath, outPath, new ShieldOptions(), log);
    }

    /**
     * 可编程打包入口（带选项）。GUI / 其他进程可据此控制架构偏好与运行期防御参数。
     *
     * @param opts 选项（{@code null} → 使用与原始 C++ 一致的默认值）
     * @return true 表示打包成功
     */
    public static boolean pack(String inPath, String outPath, ShieldOptions opts, StringBuilder log) {
        StringBuilder local = new StringBuilder();
        int rc = packCore(inPath, outPath, opts == null ? new ShieldOptions() : opts, local);
        if (log != null) {
            log.append(local);
        }
        return rc == 0;
    }

    /** 对应 C++ {@code fprintf(stderr, "usage: kbox_packer <input.exe> <output.exe>\n")}。 */
    private static void usage(java.io.PrintStream out) {
        out.println("usage: kbox_packer <input.exe> <output.exe>");
    }

    private static void info(StringBuilder log, String msg) {
        if (log != null) {
            log.append(msg).append('\n');
        }
        KBoxLog.info(TAG, msg);
    }

    private static void error(StringBuilder log, String msg) {
        if (log != null) {
            log.append(msg).append('\n');
        }
        KBoxLog.error(TAG, msg);
    }

    /** 对应 C++ 的 {@code if (err) *err = msg;}（err 可为 null）。 */
    private static void setErr(StringBuilder err, String msg) {
        if (err != null) {
            err.setLength(0);
            err.append(msg);
        }
    }

    /**
     * 变异 → 平坦化 → 编译（双族）→ 构建 VM 镜像。
     *
     * <p>每次调用独立生成随机种子（指令变异与镜像构建共用），保证每个构建的
     * 产物指纹不同。失败返回 null（由调用方记录日志并跳过该函数）。</p>
     */
    private static VmFunc buildVmImage(Ir.IrFunc fn, ShieldOptions opts, StringBuilder log) {
        byte[] seedBuf = new byte[4];
        randomBytes(seedBuf, 0, 4);
        int seed = Bin.i32(seedBuf, 0);
        seed |= 1;                          // 避免全 0 种子

        // 指令变异（代数恒等式重写，每构建随机选型）
        if (opts.irMutation > 0) {
            IrMutate.mutate(fn, seed, opts.irMutation);
        }
        // 控制流平坦化（块号帧槽 + switch 派发器；不适用时原样保留）
        boolean flattened = opts.cfgFlatten && IrFlatten.flatten(fn);

        // 双族编译：Family B（寄存器式）不支持时回退 Family A（栈式）
        IrCompile.CompileResult cr = IrCompile.irCompile(fn);
        if (!cr.ok) {
            return null;
        }
        IrCompile.CompileResultB cb = IrCompile.irCompileB(fn);

        VmBuilder.VmBuildOpt opt = new VmBuilder.VmBuildOpt();
        opt.seed = seed;
        byte[] coin = new byte[1];
        randomBytes(coin, 0, 1);
        opt.dispatch = ((coin[0] & 1) != 0) ? VmIsa.DISPATCH_SWITCH : VmIsa.DISPATCH_TABLE;
        opt.variantCap = VmIsa.VM_VARIANTS;     // handler 多变体（汇编引擎已全部实现）
        // 多族：每函数随机分配 VM 家族。Family B 无 handler 变体，且仅 x86-64 引擎实现。
        byte[] famCoin = new byte[1];
        randomBytes(famCoin, 0, 1);
        final boolean useB = ((famCoin[0] & 1) != 0) && cb.ok;
        VmBuilder.VmBuildResult b = useB
                ? VmBuilder.vmBuildB(cb.program, opt)
                : VmBuilder.vmBuild(cr.program, opt);
        if (!b.ok) {
            return null;
        }
        VmFunc vf = new VmFunc();
        vf.image = b.image;
        StringBuilder d = new StringBuilder();
        d.append("family=").append(useB ? "B/reg" : "A/stack");
        d.append(" dispatch=").append(opt.dispatch == VmIsa.DISPATCH_SWITCH ? "switch" : "table");
        d.append(" mut=").append(opts.irMutation);
        if (flattened) {
            d.append(" flat");
        }
        vf.desc = d.toString();
        return vf;
    }

    private static String hx(int v) {
        return "0x" + Integer.toHexString(v);            // "%x"
    }

    private static String hx8(int v) {
        return String.format("0x%08x", v);               // "%08x"
    }

    // ================= 文件读写（对应 read_file / write_file） =================

    /** 对应 {@code bool read_file(const char* path, std::vector<uint8_t>* out, std::string* err)}。 */
    private static boolean readFile(String path, Vec out, StringBuilder err) {
        try {
            byte[] b = Files.readAllBytes(Paths.get(path));
            if (b.length <= 0) {
                setErr(err, "empty file");
                return false;
            }
            out.resize(b.length);
            out.copyInto(0, b, 0, b.length);
            return true;
        } catch (Throwable t) {
            setErr(err, "cannot open " + path);
            return false;
        }
    }

    /** 对应 {@code bool write_file(const char* path, const std::vector<uint8_t>& data, std::string* err)}。 */
    private static boolean writeFile(String path, Vec data, StringBuilder err) {
        FileOutputStream f = null;
        try {
            f = new FileOutputStream(path);              // trunc
            f.write(data.array(), 0, data.size());
            f.close();
            return true;
        } catch (Throwable t) {
            if (f != null) {
                try {
                    f.close();
                } catch (Throwable ignore) {
                    // ignore
                }
            }
            setErr(err, "cannot write " + path);
            return false;
        }
    }

    // ================= 随机源（对应 random_bytes） =================

    /** 对应 C++ 的 {@code FILE* f = std::fopen("/dev/urandom", "rb")} 成功路径。 */
    private static final SecureRandom URANDOM = new SecureRandom();

    /**
     * 对应 {@code void random_bytes(uint8_t* dst, size_t n)}。
     *
     * <p>主路径等价于读取 /dev/urandom；失败时退化为 main.cpp 中同参数的 64 位 LCG
     * （种子 {@code 0x9E3779B97F4A7C15}）。</p>
     */
    private static void randomBytes(byte[] dst, int off, int n) {
        if (n <= 0) {
            return;
        }
        try {
            byte[] tmp = new byte[n];
            URANDOM.nextBytes(tmp);
            System.arraycopy(tmp, 0, dst, off, n);
            return;
        } catch (Throwable t) {
            // 兜底：确定性伪随机（仅在无法读取 urandom 时）
        }
        lcgBytes(dst, off, n, 0x9E3779B97F4A7C15L);
    }

    /** 对应 random_bytes 的 LCG 兜底分支：{@code s = s*6364136223846793005 + 1442695040888963407}，取 {@code s>>33}。 */
    private static void lcgBytes(byte[] dst, int off, int n, long s) {
        for (int i = 0; i < n; ++i) {
            s = s * 6364136223846793005L + 1442695040888963407L;
            dst[off + i] = (byte) (int) (s >>> 33);
        }
    }

    // ================= CRC32（IEEE 802.3） =================

    // CRC32（IEEE 802.3，与 stub 内 .Ld_crc32 / .Lcr_crc32 完全一致，表无关）
    private static int crc32Ieee(byte[] data, int off, int len) {
        int crc = 0xFFFFFFFF;
        for (int i = 0; i < len; ++i) {
            crc ^= (data[off + i] & 0xFF);
            for (int k = 0; k < 8; ++k) {
                crc = ((crc & 1) != 0) ? ((crc >>> 1) ^ 0xEDB88320) : (crc >>> 1);
            }
        }
        return ~crc;
    }

    // ================= 小端写入辅助 =================
    // 对应 C++ 的 w16/w32/w64/r16/r32（std::vector<uint8_t>& 版本；offset 由上层保证合法）

    private static void w16(Vec d, int off, int v) {
        d.ensure(off + 2);
        Bin.w16(d.array(), off, v);
    }

    private static void w32(Vec d, int off, int v) {
        d.ensure(off + 4);
        Bin.w32(d.array(), off, v);
    }

    private static void w64(Vec d, int off, long v) {
        d.ensure(off + 8);
        Bin.w64(d.array(), off, v);
    }

    private static int r32(Vec d, int off) {
        return Bin.i32(d.array(), off);
    }

    private static int r16(Vec d, int off) {
        return Bin.u16(d.array(), off);
    }

    // ================= 二进制资产（对应 _binary_*_bin_start/_end） =================

    /**
     * 从 classpath 读入二进制 blob 资产（替代 C++ 的 {@code _binary_*_bin_start}
     * 到 {@code _binary_*_bin_end} 符号区间；C++ 侧区间长度即资源长度）。
     */
    private static byte[] loadAsset(String res) {
        InputStream in = null;
        try {
            in = ShieldPacker.class.getResourceAsStream(res);
            if (in == null) {
                throw new RuntimeException("missing classpath resource " + res);
            }
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) > 0) {
                o.write(buf, 0, r);
            }
            in.close();
            return o.toByteArray();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("cannot read classpath resource " + res + ": " + e.getMessage(), e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignore) {
                    // ignore
                }
            }
        }
    }

    // ================= 原生层多态：随机节名 =================

    // 原生层多态：为 stub 节生成随机节名（避开既有节名；<=7 字符故以 NUL 结尾）
    private static String makeSectionName(PeImage img) {
        final String ds =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
        for (;;) {
            byte[] r = new byte[6];
            randomBytes(r, 0, r.length);
            StringBuilder s = new StringBuilder(".");
            for (int i = 0; i < 6; ++i) {
                s.append(ds.charAt((r[i] & 0xFF) % ds.length()));
            }
            boolean clash = false;
            for (PeImage.SectionInfo sec : img.sections()) {
                if (s.toString().equals(sec.name)) {
                    clash = true;
                    break;
                }
            }
            if (!clash) {
                return s.toString();
            }
        }
    }

    // ================= 合成导入表 =================

    // 构建 stub 自身合成导入表（仅 kernel32: LoadLibraryA/GetProcAddress/VirtualProtect）
    // 返回字节块；rva 偏移记录在 off 字段（相对块起始），供回填
    private static final class ImpDirBuild {
        Vec bytes = new Vec();
        int oftOff = 0;     // OFT thunk 数组偏移
        int nameOff = 0;    // "kernel32.dll" 偏移
        int descOff = 0;    // 导入描述符偏移（目录指向处）
    }

    private static final int SIZEOF_IMPORT_DESCRIPTOR = 20;

    private static ImpDirBuild buildStubImportDir(int iatRva, int ptrSize) {
        ImpDirBuild b = new ImpDirBuild();
        Vec v = b.bytes;
        // 导入描述符（1 + 1 终止）
        b.descOff = v.size();
        v.resize(v.size() + 2 * SIZEOF_IMPORT_DESCRIPTOR);
        // OFT thunk 数组（3 + 1 终止）
        b.oftOff = v.size();
        v.resize(v.size() + 4 * ptrSize);
        // hint/name 表：LoadLibraryA / GetProcAddress / VirtualProtect
        final String[] kFuncs = {"LoadLibraryA", "GetProcAddress", "VirtualProtect"};
        int[] hnOff = new int[3];
        for (int i = 0; i < 3; ++i) {
            hnOff[i] = v.size();
            v.resize(v.size() + 2 + kFuncs[i].length() + 1);
            v.set(hnOff[i], 0);
            v.set(hnOff[i] + 1, 0);      // hint
            byte[] nm = Bin.asciiZ(kFuncs[i]);
            v.copyInto(hnOff[i] + 2, nm, 0, nm.length);
        }
        // kernel32.dll
        b.nameOff = v.size();
        byte[] kK32 = Bin.asciiZ("kernel32.dll");
        v.append(kK32, 0, kK32.length);
        // 回填 OFT thunk -> hint/name（相对块偏移，最后统一加 impdir_rva）
        for (int i = 0; i < 3; ++i) {
            int t = b.oftOff + i * ptrSize;
            long target = hnOff[i] & 0xFFFFFFFFL;
            if (ptrSize == 8) {
                w64(v, t, target);
            } else {
                w32(v, t, (int) target);
            }
        }
        // 描述符字段：OFT / Name（相对块偏移，最后统一加 impdir_rva）；FirstThunk = iat_rva
        w32(v, b.descOff + 0, b.oftOff);
        w32(v, b.descOff + 12, b.nameOff);
        w32(v, b.descOff + 16, iatRva);
        // 终止描述符全 0
        return b;
    }

    // ================= 内部计划/上下文类型 =================

    /** 对应 C++ 匿名命名空间的 struct StubAsset。 */
    private static final class StubAsset {
        byte[] blob;            // start..end
        byte[] engine;          // eng_start..eng_end（入口在偏移 0）
        int iatOff;             // kbox_iat 在 blob 内偏移
        int codeEnd;            // secA（代码）/ secB（数据）切分偏移
        int entryOff;           // 入口在 blob 内偏移（= 0x100）
        int ptrSize;            // 指针宽度
        int strpoolOff;         // G2：防御字符串池起始偏移
        int defenseEnd;         // G2：防御字符串池结束偏移
        int cfgrootOff;         // 方案A：配置区加密种子槽偏移
        int junkStart;          // 方案E：随机填充区起始
        int junkEnd;            // 方案E：随机填充区结束
    }

    /** 对应 C++ {@code struct VmFunc}。 */
    private static final class VmFunc {
        int targetRva = 0;      // 被虚拟化函数 RVA（0 = 内置自检镜像）
        int entryRaw = 0;       // 函数首字节在文件内的偏移
        int trampRva = 0;       // 该函数的 trampoline RVA
        byte[] image;           // VM 镜像
        String desc = "";       // 日志描述（family/dispatch/变异/平坦化）
    }

    /** 对应 C++ {@code struct DllCtx}。 */
    private static final class DllCtx {
        String name = "";
        int dllOff = 0;                       // KboxImpDll 在 pay 内偏移
        List<Integer> entOff = new ArrayList<Integer>(); // 各 entry 偏移
    }

    // ================= 主流程 =================

    /** 完整打包流程（对应 C++ 的 main 主体）。返回 0 成功 / 1 失败。 */
    private static int packCore(String inPath, String outPath, ShieldOptions opts, StringBuilder log) {
        // ---- 读入输入文件 ----
        Vec file = new Vec();
        StringBuilder err = new StringBuilder();
        if (!readFile(inPath, file, err)) {
            error(log, "kbox_packer: " + err);
            return 1;
        }
        PeImage img = new PeImage();
        if (!img.parse(file.array(), file.size(), err)) {
            error(log, "kbox_packer: parse: " + err);
            return 1;
        }
        final boolean is64 = img.is64Bit();
        // 架构偏好校验：stub/engine blob 是架构专属的，无法跨架构加壳，
        // 因此这里只做「仅允许某一架构」的约束，不匹配则明确失败。
        if (opts.arch == ShieldOptions.ARCH_X64 && !is64) {
            error(log, "kbox_packer: 输入为 PE32，但选项要求 x64-only");
            return 1;
        }
        if (opts.arch == ShieldOptions.ARCH_X86 && is64) {
            error(log, "kbox_packer: 输入为 PE32+，但选项要求 x86-only");
            return 1;
        }
        info(log, "  arch-preference=" + opts.archName()
                + "  detected=" + (is64 ? "x64" : "x86"));

        // ---- G3：现代镜像的 LoadConfig 兼容（Win11 24H2 加载器对 sv>=7 强制校验 SecurityCookie）----
        // 实测：sv>=7（或 sv==6 且 minor>=3）的主 EXE 若 LoadConfig 目录为空，LdrpInitializeProcess
        // 在入口 stub 运行前即返回 STATUS_INVALID_IMAGE_FORMAT(0xC000007B)。
        // 修复：注入明文 LoadConfig（Size + SecurityCookie 指向 stub 明文节），并清除 ASLR 标志
        // （DYNAMIC_BASE/HIGH_ENTROPY_VA），使镜像固定装载于 ImageBase，cookie VA 无需重定位。
        final boolean needLoadConfig =
                img.majorSubsystemVersion() > 7
                        || img.majorSubsystemVersion() == 7
                        || (img.majorSubsystemVersion() == 6 && img.minorSubsystemVersion() >= 3);
        if (needLoadConfig) {
            info(log, "  sv=" + img.majorSubsystemVersion() + "."
                    + img.minorSubsystemVersion()
                    + " -> 注入 LoadConfig+SecurityCookie（清 ASLR 标志）");
        }

        // ---- 选择架构相关资产 ----
        StubAsset sa = new StubAsset();
        sa.blob = loadAsset(is64 ? "/shield/blob_x64.bin" : "/shield/blob_x86.bin");
        sa.engine = loadAsset(is64 ? "/shield/engine_x64.bin" : "/shield/engine_x86.bin");
        sa.iatOff = BlobLayout.iatOff(is64);
        sa.codeEnd = BlobLayout.codeEndOff(is64);
        sa.entryOff = BlobLayout.entryOff(is64);
        sa.ptrSize = is64 ? 8 : 4;
        sa.strpoolOff = BlobLayout.strpoolOff(is64);
        sa.defenseEnd = BlobLayout.defenseEndOff(is64);
        sa.cfgrootOff = BlobLayout.cfgRootOff(is64);
        sa.junkStart = BlobLayout.junkStartOff(is64);
        sa.junkEnd = BlobLayout.junkEndOff(is64);
        final int blobSize = sa.blob.length;            // = sa.end - sa.start
        final int engineSize = sa.engine.length;        // = sa.eng_end - sa.eng_start

        // ---- 会话密钥 ----
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        randomBytes(key, 0, key.length);
        randomBytes(nonce, 0, nonce.length);

        // ---- 解析导入 / 抓取重定位（必须在加密各节之前，否则读到密文）----
        List<PeImage.ImportDll> imports = new ArrayList<PeImage.ImportDll>();
        if (!img.parseImports(imports, err)) {
            error(log, "kbox_packer: imports: " + err);
            return 1;
        }
        ByteArrayOutputStream relocRaw = new ByteArrayOutputStream();
        if (!img.relocRaw(relocRaw)) {
            error(log, "kbox_packer: reloc: " + err);
            return 1;
        }
        byte[] reloc = relocRaw.toByteArray();

        // ---- TLS 回调（第 6 项）----
        // DIR_TLS 随后会被清零（否则 loader 会在节仍为密文时调用回调），故此处
        // 记录原回调 RVA 序列；解壳完成后由 stub 代跑（reason=DLL_PROCESS_ATTACH）。
        List<Integer> tlsCbs = new ArrayList<Integer>();
        if (img.hasDirectory(PeImage.DIR_TLS)
                && Integer.compareUnsigned(img.directorySize(PeImage.DIR_TLS), 24) >= 0) {
            int[] to = new int[1];
            if (img.rvaToOffset(img.directoryRva(PeImage.DIR_TLS), to)
                    && to[0] + 24 <= file.size()) {
                int toff = to[0];
                int cbField = is64 ? 24 : 12;
                long cbVa;
                if (is64) {
                    cbVa = Bin.i64(file.array(), toff + cbField);
                } else {
                    cbVa = Bin.u32(file.array(), toff + cbField);
                }
                long ib = img.imageBase();
                int esz = img.pointerSize();
                int[] co = new int[1];
                if (Long.compareUnsigned(cbVa, ib) >= 0
                        && img.rvaToOffset((int) (cbVa - ib), co)) {
                    int coff = co[0];
                    for (int i = 0; i < 64; ++i) {
                        if ((long) coff + (long) (i + 1) * esz > file.size()) {
                            break;
                        }
                        long p;
                        if (esz == 8) {
                            p = Bin.i64(file.array(), coff + i * esz);
                        } else {
                            p = Bin.u32(file.array(), coff + i * esz);
                        }
                        if (p == 0 || Long.compareUnsigned(p, ib) < 0) {
                            break;
                        }
                        tlsCbs.add((int) (p - ib));
                    }
                }
            }
        }

        // ---- 代码虚拟化（x64）：函数级（.pdata 逐函数）＋ .textvm* 标记节整节回退 ----
        // 必须在加密各节之前完成：入口改写针对明文机器码，且改写后的节随后
        // 一并加密；`E9 rel32` 为位置无关跳转，运行期无需重定位。
        //
        // 函数级：解析 .pdata 的 RUNTIME_FUNCTION 表，逐个函数提升为独立 VM 镜像
        // （可提升者虚拟化，不可提升者保留原生，天然实现函数粒度部分覆盖）；
        // 入口改写为 `jmp rel32` → trampoline，原函数体保留在节内作诱饵（随后加密）。
        // 每个被虚拟化函数获得一个 15 字节 trampoline（blob 之后、payload 之前），
        // 其 RVA 只依赖 blob 大小（打包早期已知），故入口改写可在此阶段完成；
        // trampoline 内的镜像 RVA 依赖后续布局，留到组装 stub 节时回填。
        final int secAlign = img.sectionAlignment();
        // stub 置于镜像最前（首个节，通常 RVA 0x1000 起）：安全软件行为监控要求
        // 进程入口点与代码执行都位于首个节；stub 若在末尾会被静默终止（退出码 0）。
        final int stubRva = Bin.alignUp(img.sizeOfHeaders(), secAlign);
        final int kTrampSize = 15;             // push imm32 ×2 + jmp rel32
        List<VmFunc> vms = new ArrayList<VmFunc>();
        final int blobAligned = Bin.alignUp(blobSize, 16);
        final int epRva = img.entryRva();
        // 已被虚拟化的函数区间（防御：EP 原始字节保存不得落入）
        List<int[]> vmRanges = new ArrayList<int[]>();
        // 函数入口改写补丁（[文件偏移, 原 RVA, trampRva]）：E9 rel32 的 rel 依赖
        // origShift（运行期函数实际 RVA = 原 RVA + origShift），故延迟到 origShift
        // 已知后统一回填（见「确定新节 RVA/文件偏移」之后）。
        List<int[]> entryPatches = new ArrayList<int[]>();

        if (!is64) {
            info(log, "  vm: x86 输入仅做加壳（虚拟化管线为 x64）");
        } else if (!opts.virtualizeMarkedSections && !opts.virtualizeFunctions) {
            info(log, "  vm: 已按选项关闭虚拟化，仅做加壳");
        } else {
            // 定位 .textvm* 标记节（整节回退用）
            List<PeImage.SectionInfo> marked = new ArrayList<PeImage.SectionInfo>();
            for (PeImage.SectionInfo s : img.sections()) {
                if (s.name.startsWith(".textvm")) {
                    marked.add(s);
                }
            }

            // 解析 .pdata（函数级虚拟化的函数边界）
            List<PeImage.RfEntry> rfs = new ArrayList<PeImage.RfEntry>();
            boolean pdataOk = true;
            if (opts.virtualizeFunctions || !marked.isEmpty()) {
                StringBuilder perr = new StringBuilder();
                pdataOk = img.parseRuntimeFunctions(rfs, perr);
                if (!pdataOk) {
                    error(log, "  vm: .pdata 解析失败（" + perr + "）→ 仅 .textvm 整节回退");
                }
            }

            // ---- 函数级：逐函数提升 ----
            if (pdataOk && !rfs.isEmpty()) {
                int lastEnd = 0;
                int vmFuncCount = 0;
                int skipCount = 0;
                for (PeImage.RfEntry rf : rfs) {
                    // 非法/过短（入口改写需 5 字节 jmp）跳过
                    final int len = PeImage.rfLength(rf);
                    if (len < 5 || Integer.compareUnsigned(rf.begin, rf.end) >= 0) {
                        continue;
                    }
                    if (Integer.compareUnsigned(rf.begin, lastEnd) < 0) {
                        continue;               // 与前一函数重叠（异常表防御）
                    }
                    lastEnd = rf.end;
                    // 所在节：函数级虚拟化只作用于可执行节；.textvm 标记节也允许
                    PeImage.SectionInfo s = img.sectionByRva(rf.begin);
                    if (s == null || !s.hasRaw()) {
                        continue;
                    }
                    final boolean inMarked = s.name.startsWith(".textvm");
                    final boolean inExec = (s.characteristics & PeImage.SCN_MEM_EXECUTE) != 0;
                    if (!(opts.virtualizeFunctions && inExec)
                            && !(opts.virtualizeMarkedSections && inMarked)) {
                        continue;
                    }
                    // 入口点函数不虚拟化（进程启动时 stub 尚未运行，VM 引擎未就绪）
                    if (img.rfContains(rf, epRva)) {
                        continue;
                    }
                    int[] off = new int[1];
                    if (!img.rvaToOffset(rf.begin, off)
                            || Integer.compareUnsigned(off[0] + len, file.size()) > 0) {
                        continue;
                    }
                    Ir.IrDiag diag = new Ir.IrDiag();
                    Ir.IrFunc fn = LiftX64.liftX64Func(file.array(), off[0], len, diag);
                    if (!diag.ok) {
                        ++skipCount;
                        continue;
                    }
                    VmFunc vf = buildVmImage(fn, opts, log);
                    if (vf == null) {
                        ++skipCount;
                        continue;
                    }
                    vf.targetRva = rf.begin;
                    vf.entryRaw = off[0];
                    vf.trampRva = stubRva + blobAligned + vms.size() * kTrampSize;
                    // 入口改写为 `jmp rel32` → trampoline（位置无关；rel 待 origShift 回填）
                    entryPatches.add(new int[] { off[0], rf.begin, vf.trampRva });
                    vmRanges.add(new int[] { rf.begin, rf.end });
                    vms.add(vf);
                    ++vmFuncCount;
                    info(log, "  vm: func rva=" + hx(vf.targetRva)
                            + " len=" + len
                            + " ir=" + fn.insns.size()
                            + " frame=" + fn.frameSlots
                            + " " + vf.desc);
                }
                if (vmFuncCount != 0) {
                    info(log, "  vm: 函数级虚拟化 " + vmFuncCount
                            + " 个函数，跳过 " + skipCount + "（不可提升/重叠）");
                }
            }

            // ---- .textvm* 标记节整节回退（节内无任何函数被虚拟化时） ----
            for (PeImage.SectionInfo s : marked) {
                boolean covered = false;
                final int span = s.virtualSize != 0 ? s.virtualSize : s.rawSize;
                for (int[] r : vmRanges) {
                    if (Integer.compareUnsigned(r[0], s.virtualAddress) >= 0
                            && Integer.compareUnsigned(r[0], s.virtualAddress + span) < 0) {
                        covered = true;
                        break;
                    }
                }
                if (covered) {
                    continue;
                }
                if (s.rawSize == 0
                        || Integer.compareUnsigned(s.rawPtr + s.rawSize, file.size()) > 0) {
                    continue;
                }
                if (Integer.compareUnsigned(epRva, s.virtualAddress) >= 0
                        && Integer.compareUnsigned(epRva, s.virtualAddress + span) < 0) {
                    error(log, "  vm: " + s.name
                            + " 含入口点且无函数级覆盖，整节回退跳过（EP=0x" + hx(epRva) + "）");
                    continue;
                }
                Ir.IrDiag diag = new Ir.IrDiag();
                Ir.IrFunc fn = LiftX64.liftX64Func(file.array(), s.rawPtr, s.rawSize, diag);
                if (!diag.ok) {
                    error(log, "  vm: " + s.name + " 提升失败（bad_off=" + diag.badOff + "）→ 跳过");
                    continue;
                }
                VmFunc vf = buildVmImage(fn, opts, log);
                if (vf == null) {
                    error(log, "  vm: " + s.name + " 编译/镜像构建失败 → 跳过");
                    continue;
                }
                vf.targetRva = s.virtualAddress;
                vf.entryRaw = s.rawPtr;
                vf.trampRva = stubRva + blobAligned + vms.size() * kTrampSize;
                // 入口改写为 `jmp rel32` → trampoline（位置无关；rel 待 origShift 回填）
                entryPatches.add(new int[] { vf.entryRaw, vf.targetRva, vf.trampRva });
                vmRanges.add(new int[] { vf.targetRva, vf.targetRva + s.rawSize });
                vms.add(vf);
                info(log, "  vm: " + s.name
                        + " 虚拟化 rva=" + hx(vf.targetRva)
                        + " tramp=" + hx(vf.trampRva)
                        + " ir=" + fn.insns.size()
                        + " frame=" + fn.frameSlots
                        + " " + vf.desc);
            }
        }

        // ---- 入口 trampoline：使 EP 保持在首个节（.text） ----
        // 安全软件行为监控要求进程入口点位于第一个节；加壳产物入口若指向 stub 节
        // （位于节表末尾）会在执行前被静默终止（退出码 0）。故在原入口写 5 字节
        // `jmp stub_entry`（E9 rel32，位置无关），原始 5 字节存入配置区 CFG_EP_PATCH；
        // stub 解壳后（恢复节权限前，.text 仍为 RWX）写回原始字节，再跳 OEP。
        int[] epOffArr = new int[1];
        PeImage.SectionInfo epSec = null;
        int epPatchOffInSec = 0;
        if (img.rvaToOffset(img.entryRva(), epOffArr)) {
            for (PeImage.SectionInfo s : img.sections()) {
                long rel = (img.entryRva() & 0xFFFFFFFFL) - (s.virtualAddress & 0xFFFFFFFFL);
                if (rel >= 0 && rel < s.rawSize) {
                    epSec = s;
                    epPatchOffInSec = (int) rel;
                    break;
                }
            }
        }
        byte[] epOrig = new byte[5];
        if (epSec == null || epOffArr[0] + 5 > file.size()) {
            error(log, "kbox_packer: 入口点所在节无法写入 5 字节 trampoline（EP=0x"
                    + hx(img.entryRva()) + "）");
            return 1;
        }
        for (int[] r : vmRanges) {
            if (Integer.compareUnsigned(epRva, r[0]) >= 0
                    && Integer.compareUnsigned(epRva, r[1]) < 0) {
                error(log, "kbox_packer: 入口点位于虚拟化函数内，无法保存 EP 原始字节（EP=0x"
                        + hx(img.entryRva()) + "）");
                return 1;
            }
        }
        System.arraycopy(file.array(), epOffArr[0], epOrig, 0, 5);
        // trampoline 的实际写入推迟到「各节加密之后」（此处加密会把明文一起加密掉）
        info(log, "  ep: trampoline @" + hx(img.entryRva())
                + " -> stub " + hx(stubRva + sa.entryOff)
                + "（原始字节已存 CFG_EP_PATCH）");

        // ---- 加密各节 raw 区（每节独立 nonce, counter=0）----
        // 资源节例外：进程创建阶段（CSR / LdrpInitializeProcess）会解析映像的
        // 资源目录以建立应用清单（manifest）激活上下文，早于入口点执行；若资源
        // 仍为密文，CreateProcess 会以 ERROR_BAD_EXE_FORMAT(193) 失败。故资源节
        // 标记 PAYLOAD_FLAG_SKIP_DECRYPT 并保持明文（stub 依该标记跳过解密）。
        final int resDirRva = img.hasDirectory(PeImage.DIR_RESOURCE)
                ? img.directoryRva(PeImage.DIR_RESOURCE) : 0;
        List<byte[]> secRecs = new ArrayList<byte[]>();
        byte[] secNonceBuf = new byte[12];
        for (PeImage.SectionInfo s : img.sections()) {
            if (!s.hasRaw()) {
                continue;
            }
            int secSpan = s.virtualSize != 0 ? s.virtualSize : s.rawSize;
            boolean isResSection = resDirRva != 0
                    && Integer.compareUnsigned(resDirRva, s.virtualAddress) >= 0
                    && Integer.compareUnsigned(resDirRva,
                            s.virtualAddress + secSpan) < 0;
            byte[] rec = new byte[KboxFormat.SECTION_REC_SIZE];
            Bin.w32(rec, KboxFormat.SR_RVA, s.virtualAddress);
            Bin.w32(rec, KboxFormat.SR_RAW_SIZE, s.rawSize);
            Bin.w32(rec, KboxFormat.SR_CHACHA_BLOCK, 0);
            int id = secRecs.size();
            randomBytes(secNonceBuf, 4, 8);
            Bin.w32(secNonceBuf, 0, id);
            System.arraycopy(secNonceBuf, 0, rec, KboxFormat.SR_NONCE, 12);
            Bin.w32(rec, KboxFormat.SR_PERMS, PeImage.sectionPermissions(s));
            Bin.w32(rec, KboxFormat.SR_FLAGS,
                    isResSection ? KboxFormat.PAYLOAD_FLAG_SKIP_DECRYPT : 0);
            if (isResSection) {
                info(log, String.format("  sec[%s] 资源节保持明文（SKIP_DECRYPT）",
                        s.name));
            }
            // 加密延后：需先确定 origShift（原节 VA 后移量）并修正各节内部 RVA，
            // 加密必须作用于修正后的明文。
            secRecs.add(rec);
        }

        // ---- 构建 payload 明文 ----
        Vec pay = new Vec();
        pay.resize(KboxFormat.PAYLOAD_HDR_SIZE);
        // 节记录
        for (byte[] r : secRecs) {
            pay.append(r, 0, r.length);
        }
        final int secCount = secRecs.size();
        // 导入区：ImpDll + entries（name_rva 暂以 0 占位，字符串区构建后回填）
        List<DllCtx> dllCtx = new ArrayList<DllCtx>();
        int impTotal = 0;
        for (PeImage.ImportDll d : imports) {
            if (d.entries.isEmpty()) {
                continue;
            }
            DllCtx dc = new DllCtx();
            dc.name = d.name;
            dc.dllOff = pay.size();
            byte[] kd = new byte[KboxFormat.IMP_DLL_SIZE];
            Bin.w32(kd, KboxFormat.ID_NAME_RVA, 0);
            Bin.w32(kd, KboxFormat.ID_IAT_RVA, d.iatRva);
            Bin.w32(kd, KboxFormat.ID_COUNT, d.entries.size());
            pay.append(kd, 0, kd.length);
            for (PeImage.ImportEntry e : d.entries) {
                dc.entOff.add(Integer.valueOf(pay.size()));
                byte[] ke = new byte[KboxFormat.IMP_ENTRY_SIZE];
                Bin.w16(ke, KboxFormat.IE_ORDINAL, e.ordinal);
                Bin.w16(ke, KboxFormat.IE_HINT, e.hint);
                Bin.w32(ke, KboxFormat.IE_NAME_RVA, 0);
                pay.append(ke, 0, ke.length);
                impTotal++;
            }
            dllCtx.add(dc);
        }
        final int impDllCount = dllCtx.size();
        // reloc 原始字节（加密前已抓取）
        int relocSize = 0;
        if (reloc.length != 0) {
            relocSize = reloc.length;
            pay.append(reloc, 0, reloc.length);
        }
        // 字符串区（reloc 之后）: DLL 名 + 函数名
        // 记录每个字符串相对 pay 的偏移，随后回填 name_rva（= payload_rva + off）
        for (DllCtx dc : dllCtx) {
            int nameOff = strOffOf(pay, dc.name);
            w32(pay, dc.dllOff + KboxFormat.ID_NAME_RVA, nameOff); // KboxImpDll.name_rva
        }
        {
            int di = 0;
            for (PeImage.ImportDll d : imports) {
                if (d.entries.isEmpty()) {
                    continue;
                }
                int ei = 0;
                for (PeImage.ImportEntry e : d.entries) {
                    if (e.ordinal == 0) {
                        int noff = strOffOf(pay, e.name);
                        int ent = dllCtx.get(di).entOff.get(ei).intValue();
                        w32(pay, ent + KboxFormat.IE_NAME_RVA, noff); // KboxImpEntry.name_rva
                    }
                    ++ei;
                }
                ++di;
            }
        }
        // 回填 hdr
        byte[] hdr = new byte[KboxFormat.PAYLOAD_HDR_SIZE];
        Bin.w32(hdr, KboxFormat.PH_MAGIC, KboxFormat.PAYLOAD_MAGIC);
        Bin.w32(hdr, KboxFormat.PH_SECTION_COUNT, secCount);
        Bin.w32(hdr, KboxFormat.PH_IMP_DLL_COUNT, impDllCount);
        Bin.w32(hdr, KboxFormat.PH_IMP_TOTAL, impTotal);
        Bin.w32(hdr, KboxFormat.PH_RELOC_SIZE, relocSize);
        pay.copyInto(0, hdr, 0, hdr.length);
        final int payloadPlainSize = pay.size();

        // ---- VM 镜像（无标记节时回退到内置自检镜像）----
        // 该镜像由 x64/x86 两侧共用；x86 引擎只实现 v0 变体，故置 variant_cap=1
        // 强制全 v0（各变体语义等价，x64 侧同样正确）。
        if (vms.isEmpty()) {
            List<VmIsa.Insn> prog = VmTranslate.vmTranslateMix();
            VmBuilder.VmBuildOpt opt = new VmBuilder.VmBuildOpt();
            byte[] seedBuf = new byte[4];
            randomBytes(seedBuf, 0, 4);
            opt.seed = Bin.i32(seedBuf, 0);
            opt.seed |= 1;                  // 避免全 0 种子
            byte[] coin = new byte[1];
            randomBytes(coin, 0, 1);
            opt.dispatch = ((coin[0] & 1) != 0) ? VmIsa.DISPATCH_SWITCH : VmIsa.DISPATCH_TABLE;
            opt.variantCap = 1;              // 见上：内置镜像两侧共用
            VmBuilder.VmBuildResult res = VmBuilder.vmBuild(prog, opt);
            if (!res.ok) {
                error(log, "kbox_packer: vm_build failed: err=" + res.err);
                return 1;
            }
            VmFunc vf = new VmFunc();
            vf.image = res.image;
            info(log, "  vm: 内置自检镜像 size=" + vf.image.length
                    + " dispatch=" + opt.dispatch + " seed=" + hx8(opt.seed));
            vms.add(vf);
        }

        // ---- 各镜像 16 字节对齐顺序排布，并预演各自的自检期望值 ----
        // 4.4 嵌套虚拟化：每个内层镜像紧随其后放置一份外层 Meta 镜像，并回填
        // 内层镜像头 reserved[0]（Meta 相对字节增量）/ reserved[1]（Meta 字节数）。
        // 运行期 kbox_vm_run 据此定位并进入外层 Meta VM，由"被编译成 Meta 字节码
        // 的内层解释器"执行内层镜像——内层 native 解释器不再存在（x64/x86 一致）。
        // Meta 镜像与宿主指针宽度无关，x86 与 x64 共享同一生成器。
        byte[] metaImg;
        {
            byte[] mseedBuf = new byte[4];
            randomBytes(mseedBuf, 0, 4);
            int mseed = Bin.i32(mseedBuf, 0);
            mseed |= 1;
            VmMeta.MetaBuildResult mb = MetaInner.vmBuildInnerMeta(mseed);
            if (!mb.ok) {
                error(log, "kbox_packer: vm_build_inner_meta failed: err=" + mb.err);
                return 1;
            }
            metaImg = mb.image;
            info(log, "  vm-meta: nested size=" + metaImg.length + " seed=" + hx8(mseed));
        }
        int[] vmImgOff = new int[vms.size()];
        byte[][] vmBlobs = new byte[vms.size()][];
        int vmTotal = 0;
        for (int i = 0; i < vms.size(); ++i) {
            final int innerSz = vms.get(i).image.length;
            Vec blob = new Vec();
            blob.append(vms.get(i).image, 0, innerSz);
            int unit = innerSz;
            if (metaImg.length != 0) {
                final int metaOff = Bin.alignUp(innerSz, 16);   // Meta 相对增量
                final int msz = metaImg.length;
                blob.resize(metaOff);
                blob.append(metaImg, 0, msz);
                // 回填内层镜像头 reserved[0]/reserved[1]（header 为明文）
                w32(blob, 48, metaOff);
                w32(blob, 52, msz);
                unit = metaOff + msz;
            }
            vmImgOff[i] = vmTotal;
            vmTotal += Bin.alignUp(unit, 16);
            vmBlobs[i] = blob.toArray();
        }
        // 自检输入随机化；期望值由 C++ 引擎预演（运行期汇编引擎须与其一致）
        int[] vmIn = new int[vms.size()];
        int[] vmExpect = new int[vms.size()];
        {
            for (int i = 0; i < vms.size(); ++i) {
                byte[] inBuf = new byte[4];
                randomBytes(inBuf, 0, 4);
                vmIn[i] = Bin.i32(inBuf, 0);
                long[] gprs = new long[VmIsa.VM_MACH_GPRS];
                gprs[VmIsa.GPR_RAX] = vmIn[i] & 0xFFFFFFFFL;   // 自检约定：输入置于虚拟 rax
                int[] out = new int[1];
                final int rc = VmEngine.vmExecMach(vms.get(i).image,
                        vms.get(i).image.length, gprs, out, null);
                if (rc != VmIsa.VM_OK) {
                    error(log, "kbox_packer: vm_exec self-check failed: err=" + rc);
                    return 1;
                }
                vmExpect[i] = out[0];
                info(log, "  vm[" + i + "]: size=" + vms.get(i).image.length
                        + " in=" + hx8(vmIn[i]) + " expect=" + hx8(vmExpect[i])
                        + " target=" + hx(vms.get(i).targetRva));
            }
        }
        final int vmAligned = vmTotal;
        // trampoline 仅服务于被虚拟化的标记函数（内置自检镜像无入口可改写）
        int trampCount = 0;
        for (VmFunc v : vms) {
            if (v.targetRva != 0) {
                ++trampCount;
            }
        }
        final int trampAligned = Bin.alignUp(trampCount * kTrampSize, 16);
        final int recsAligned = Bin.alignUp(vms.size() * KboxFormat.VM_REC_SIZE, 16);
        final int engineAligned = Bin.alignUp(engineSize, 16);

        // ---- 组装 stub 节 ----
        // 布局: [KboxConfig 0x100 | blob 其余][pad][每函数 trampoline][pad]
        //       [payload 密文][pad][合成导入表][pad][VM 镜像组][pad]
        //       [运行期汇编引擎][pad][KboxVmRec 数组][pad]
        // 注意: blob[0,0x100) 本身即配置区（stub_x86/x64.S 以 .space 0x100 预留），
        //       故节内不得再额外前置 0x100，否则入口点与配置区双双错位。
        // trampoline 紧随 blob：其 RVA 只依赖 blob 大小，故虚拟化阶段即可定位。
        final int payAligned = Bin.alignUp(payloadPlainSize, 16);
        // 合成导入表（iat_rva 依赖 stub_rva，先占位构建，最后统一修正）
        ImpDirBuild impdir = buildStubImportDir(0, sa.ptrSize);
        final int impdirSize = impdir.bytes.size();
        final int impdirAligned = Bin.alignUp(impdirSize, 16);
        final int trampOff = blobAligned;
        final int payOff = trampOff + trampAligned;
        final int impdirOff = payOff + payAligned;
        final int vmOff = impdirOff + impdirAligned;
        final int engineOff = vmOff + vmAligned;
        final int recsOff = engineOff + engineAligned;
        // 运行期防御报告块（KboxDefenseReport，运行期写入；用于可观测性）
        final int reportOff = recsOff + recsAligned;
        final int reportAligned = Bin.alignUp(KboxFormat.DEFENSE_REPORT_SIZE, 16);
        // TLS 回调 RVA 数组（0 结尾）
        final int tlsOff = reportOff + reportAligned;
        final int tlsBytes = Bin.alignUp((tlsCbs.size() + 1) * 4, 16);
        // G3：LoadConfig + SecurityCookie 槽（sv>=7 时 loader 强制校验；明文置于 stub 节 B 末尾）
        final int lcfgSize = is64 ? 0x78 : 0x48;          // IMAGE_LOAD_CONFIG_DIRECTORY{64,32} Win10 尺寸
        final int lcfgCookieOfs = is64 ? 0x58 : 0x3C;     // SecurityCookie 字段偏移
        final int lcfgCookieLen = is64 ? 8 : 4;
        final int lcfgOff = tlsOff + tlsBytes;
        final int lcfgCookieSlot = lcfgOff + lcfgSize;
        final int lcfgBlock = Bin.alignUp(lcfgSize + lcfgCookieLen, 16);
        final int stubSize = needLoadConfig ? (lcfgOff + lcfgBlock) : (tlsOff + tlsBytes);

        // ---- 确定新节 RVA/文件偏移（sec_align / stub_rva 已在虚拟化阶段求得）----
        // 方案D 节拆分：代码节 = blob[0, iat_off)（文件态 RX，stub 运行期临时置 RWX、
        // 跳 OEP 前恢复 RX）；其余 = 数据节 RWX（loader 回填 IAT、payload 就地解密、
        // VM 引擎执行、防御报告运行期写入）。iat_off 为 4096 对齐，与 sec_align 兼容，
        // 两节虚拟地址连续，stub 的 config 相对寻址不受影响。
        final int fileAlign = img.fileAlignment();
        final int secALen = sa.codeEnd;                    // 代码节字节数（RX 部分）
        final int secAVsize = Bin.alignUp(secALen, secAlign);
        final int secBVsize = Bin.alignUp(stubSize - secALen, secAlign);
        final int secARawSize = Bin.alignUp(secALen, fileAlign);
        final int secBRawSize = Bin.alignUp(stubSize - secALen, fileAlign);
        // stub 置于节 0（RVA 0x1000 起）→ 原节整体后移 origShift，镜像尺寸随之增大。
        final int origShift = secAVsize + secBVsize;
        final int newImageSize = Bin.alignUp(img.sizeOfImage() + origShift, secAlign);
        final int stubRawPtr = Bin.alignUp(file.size(), fileAlign);
        final int stubBRawPtr = stubRawPtr + secARawSize;

        // ---- 函数入口改写（E9 rel32 → trampoline）：rel 依赖 origShift，此处回填 ----
        // 被虚拟化函数运行期的实际 RVA = 原 RVA + origShift（原节整体后移）；trampoline
        // 位于首个节（不后移）。故 rel = trampRva - (原RVA + origShift + 5)。若按未加
        // shift 的 RVA 计算，运行期跳转目标会落在 trampRva+origShift（payload/VM 区乱码）
        // → 0xC0000005。
        for (int[] p : entryPatches) {
            int rel = (int) ((long) p[2] - ((long) p[1] + origShift + 5));
            file.set(p[0], 0xE9);
            file.ensure(p[0] + 5);
            Bin.w32(file.array(), p[0] + 1, rel);
        }

        // ---- 原节 VA 后移后的内部 RVA 修正（stub 前置）----
        // 原节在节表中的 VA 整体 +origShift（见 PE 重建），其内部所有「镜像内 RVA」
        // 引用必须同步，否则 stub 解密/重定位、loader 解析资源/异常展开都会错位。
        // (a) payload 节记录 SR_RVA
        for (int i = 0; i < secCount; ++i) {
            int ro = KboxFormat.PAYLOAD_HDR_SIZE + i * KboxFormat.SECTION_REC_SIZE;
            w32(pay, ro + KboxFormat.SR_RVA,
                    r32(pay, ro + KboxFormat.SR_RVA) + origShift);
        }
        // (b) 导入条目 IAT RVA
        for (DllCtx dc : dllCtx) {
            w32(pay, dc.dllOff + KboxFormat.ID_IAT_RVA,
                    r32(pay, dc.dllOff + KboxFormat.ID_IAT_RVA) + origShift);
        }
        // (c) reloc 块页 RVA（payload 内，紧随导入区）
        {
            int ro = KboxFormat.PAYLOAD_HDR_SIZE
                    + secCount * KboxFormat.SECTION_REC_SIZE
                    + impDllCount * KboxFormat.IMP_DLL_SIZE
                    + impTotal * KboxFormat.IMP_ENTRY_SIZE;
            int rem = relocSize;
            while (rem >= 8) {
                int blkSize = r32(pay, ro + 4);
                if (blkSize < 8 || blkSize > rem) {
                    break;
                }
                w32(pay, ro, r32(pay, ro) + origShift);
                ro += blkSize;
                rem -= blkSize;
            }
        }
        // (d) 重定位目标值 + 原节内部 RVA（.pdata/.rsrc/.edata）——须在加密前
        shiftImageInternals(img, file, reloc, origShift, err);
        // (e) 加密各节 raw 区（每节独立 nonce, counter=0）。
        //     必须整节「连续」加密：stub 端是整节一次性解密，若此处为保留入口
        //     trampoline 而拆成两段并把 keystream 跳过 5 字节，两侧流就错位
        //     （表现为该节自入口起全部解成乱码）。trampoline 改为在加密**之后**
        //     写入（见下），其原始 5 字节由 stub 在解壳末尾写回。
        {
            int recIdx = 0;
            for (PeImage.SectionInfo s : img.sections()) {
                if (!s.hasRaw()) {
                    continue;
                }
                byte[] rec = secRecs.get(recIdx++);
                boolean res = (Bin.i32(rec, KboxFormat.SR_FLAGS)
                        & KboxFormat.PAYLOAD_FLAG_SKIP_DECRYPT) != 0;
                if (res) {
                    continue;
                }
                byte[] nb = new byte[12];
                System.arraycopy(rec, KboxFormat.SR_NONCE, nb, 0, 12);
                ChaCha20 cc = new ChaCha20();
                cc.init(key, 0, nb, 0, 0);
                cc.crypt(file.array(), s.rawPtr, file.array(), s.rawPtr, s.rawSize);
            }
        }
        // 注：EP 已直接指向 stub（节 0），无需在原入口写跳转 trampoline。
        //     原入口所在节被整节连续加密，其入口处 5 字节解密后为乱码，由 stub
        //     在解壳末尾用 CFG_EP_PATCH 保存的原始字节写回（见 stub .Lno_reloc 后）。

        final int payloadRva = stubRva + payOff;
        final int impdirRva = stubRva + impdirOff;
        final int vmBaseRva = stubRva + vmOff;
        final int vmEngineRva = stubRva + engineOff;
        final int recsRva = stubRva + recsOff;
        final int reportRva = stubRva + reportOff;
        final int iatRva = stubRva + sa.iatOff;
        final int lcfgRva = stubRva + lcfgOff;                      // G3：LoadConfig（sv>=7 注入）

        // ---- 修正 payload 明文内字符串 RVA（+ payload_rva；必须加密前完成）----
        {
            int di = 0;
            for (PeImage.ImportDll d : imports) {
                if (d.entries.isEmpty()) {
                    continue;
                }
                int dlOff = dllCtx.get(di).dllOff;
                w32(pay, dlOff + KboxFormat.ID_NAME_RVA,
                        r32(pay, dlOff + KboxFormat.ID_NAME_RVA) + payloadRva);
                int ei = 0;
                for (PeImage.ImportEntry e : d.entries) {
                    if (e.ordinal == 0) {
                        int ent = dllCtx.get(di).entOff.get(ei).intValue();
                        w32(pay, ent + KboxFormat.IE_NAME_RVA,
                                r32(pay, ent + KboxFormat.IE_NAME_RVA) + payloadRva);
                    }
                    ++ei;
                }
                ++di;
            }
        }

        // ---- 加密 payload ----
        byte[] payCipher = new byte[payloadPlainSize];
        {
            ChaCha20 cc = new ChaCha20();
            cc.init(key, 0, nonce, 0, 0);
            cc.crypt(payCipher, 0, pay.array(), 0, payloadPlainSize);
        }

        // ---- 修正合成导入表 RVA ----
        w32(impdir.bytes, impdir.descOff + 0, impdirRva + impdir.oftOff);
        w32(impdir.bytes, impdir.descOff + 12, impdirRva + impdir.nameOff);
        w32(impdir.bytes, impdir.descOff + 16, iatRva); // FirstThunk = kbox_iat
        for (int i = 0; i < 3; ++i) {
            int t = impdir.oftOff + i * sa.ptrSize;
            if (sa.ptrSize == 8) {
                long target = Bin.i64(impdir.bytes.array(), t);
                w64(impdir.bytes, t, target + (impdirRva & 0xFFFFFFFFL));
            } else {
                int tv = Bin.i32(impdir.bytes.array(), t);
                w32(impdir.bytes, t, tv + impdirRva);
            }
        }

        // ---- 组装 stub 节内容 ----
        Vec stubSec = new Vec();
        stubSec.append(sa.blob, 0, sa.blob.length);                 // blob（含配置区）
        // 每函数 trampoline：push 镜像大小; push 镜像 RVA; jmp kbox_vm_dispatch
        // （pushq imm32 = 68 id；jmp rel32 = E9 cd，共 15 字节）
        stubSec.resize(trampOff);                                   // pad
        {
            final int dispRva = stubRva + BlobLayout.dispatchOff(is64);
            int ti = 0;
            for (int vi = 0; vi < vms.size(); ++vi) {
                VmFunc v = vms.get(vi);
                if (v.targetRva == 0) {
                    continue;
                }
                final int trampRva = stubRva + trampOff + ti * kTrampSize;
                final int imgRva = vmBaseRva + vmImgOff[vi];
                final int imgSize = v.image.length;
                final int rel = (int) ((long) dispRva - ((long) trampRva + kTrampSize));
                byte[] t = new byte[kTrampSize];
                t[0] = 0x68;
                Bin.w32(t, 1, imgSize);
                t[5] = 0x68;
                Bin.w32(t, 6, imgRva);
                t[10] = (byte) 0xE9;
                Bin.w32(t, 11, rel);
                stubSec.append(t, 0, kTrampSize);
                ++ti;
            }
        }
        stubSec.resize(payOff);                                     // pad
        stubSec.append(payCipher, 0, payCipher.length);
        stubSec.resize(impdirOff);                                  // pad
        stubSec.append(impdir.bytes.array(), 0, impdirSize);
        stubSec.resize(vmOff);                                      // pad
        for (int i = 0; i < vms.size(); ++i) {                      // VM 镜像组
            stubSec.resize(vmOff + vmImgOff[i]);
            stubSec.append(vmBlobs[i], 0, vmBlobs[i].length);
        }
        stubSec.resize(engineOff);                                  // pad
        stubSec.append(sa.engine, 0, engineSize);                   // 运行期汇编引擎
        stubSec.resize(recsOff);                                    // pad
        // KboxVmRec 数组
        byte[] vmRecs = new byte[vms.size() * KboxFormat.VM_REC_SIZE];
        for (int i = 0; i < vms.size(); ++i) {
            int ro = i * KboxFormat.VM_REC_SIZE;
            Bin.w32(vmRecs, ro + KboxFormat.VMR_IMAGE_RVA, vmBaseRva + vmImgOff[i]);
            Bin.w32(vmRecs, ro + KboxFormat.VMR_IMAGE_SIZE, vms.get(i).image.length);
            Bin.w32(vmRecs, ro + KboxFormat.VMR_TARGET_RVA,
                    vms.get(i).targetRva == 0 ? 0 : vms.get(i).targetRva + origShift);
            Bin.w32(vmRecs, ro + KboxFormat.VMR_SELF_IN, vmIn[i]);
            Bin.w32(vmRecs, ro + KboxFormat.VMR_SELF_EXPECT, vmExpect[i]);
        }
        if (vmRecs.length != 0) {
            stubSec.append(vmRecs, 0, vmRecs.length);
        }
        stubSec.resize(stubSize);                                   // pad
        if (!tlsCbs.isEmpty()) {                                    // TLS 回调 RVA 表
            for (int i = 0; i < tlsCbs.size(); ++i) {
                w32(stubSec, tlsOff + i * 4, tlsCbs.get(i).intValue() + origShift);
            }
        }

        // ---- 原生层多态（G2）：填充区随机化 ----
        // stub 代码本身是静态的，但节内各对齐填充、配置尾部未用区可随机化，
        // 使「节字节指纹」不再跨构建恒定。
        fillRand(stubSec, KboxFormat.CONFIG_SIZE, 0x100);           // 配置尾部未用
        fillRand(stubSec, blobSize, trampOff);
        fillRand(stubSec, trampOff + trampAligned, payOff);
        fillRand(stubSec, payOff + payloadPlainSize, impdirOff);
        fillRand(stubSec, impdirOff + impdirSize, vmOff);
        fillRand(stubSec, vmOff + vmAligned, engineOff);
        fillRand(stubSec, engineOff + engineSize, recsOff);
        fillRand(stubSec, recsOff + vms.size() * KboxFormat.VM_REC_SIZE, reportOff);
        fillRand(stubSec, reportOff + KboxFormat.DEFENSE_REPORT_SIZE, tlsOff);
        fillRand(stubSec, tlsOff + (tlsCbs.size() + 1) * 4, stubSize);
        // stub 自身 IAT 页非零化（关键）：若 IAT 所在页在文件中全为 0，Windows
        // loader 的 IAT 回填对进程视图不可见（该页以共享零页映射），stub 首条指令
        // 取到空指针即跳 .Ldead。整页随机化（含 3 个槽位——loader 解析后会覆盖）
        // 可确保回填生效；实测：页全 0 时 IAT 恒为 0，页非 0 时回填正常。
        fillRand(stubSec, sa.iatOff, sa.iatOff + 0x1000);
        fillRand(stubSec, sa.junkStart, sa.junkEnd);                 // 方案E：随机填充区

        // ---- G3：写入 LoadConfig + SecurityCookie（sv>=7 镜像；须在 fillRand 之后覆写明文）----
        // 布局: [IMAGE_LOAD_CONFIG_DIRECTORY 全 0][cookie 槽]
        // SecurityCookie 字段 = ImageBase + cookieSlotRva。因下方 PE 重建会清除 ASLR 标志
        // （DYNAMIC_BASE/HIGH_ENTROPY_VA），镜像固定装载于 ImageBase，故该绝对 VA 无需重定位。
        // cookie 槽初值 = 0x2B992DDFA232（MSVC 初始安全 cookie 魔数；loader 校验后随机化覆写）。
        if (needLoadConfig) {
            // 整块清零（fillRand 已填入随机字节；LoadConfig 除 Size/SecurityCookie 外必须全 0，
            // 否则 GuardFlags 等随机字段会被 loader 当作 CFG/CET 启用，读取随机表指针 →
            // STATUS_NO_MEMORY 拒绝装载）。
            for (int i = lcfgOff; i < lcfgOff + lcfgBlock; ++i) {
                stubSec.set(i, (byte) 0);
            }
            final int cookieSlotRva = stubRva + lcfgCookieSlot;
            w32(stubSec, lcfgOff, lcfgSize);                     // LoadConfig.Size
            if (is64) {
                w64(stubSec, lcfgOff + lcfgCookieOfs,
                        img.imageBase() + cookieSlotRva);
                w64(stubSec, lcfgCookieSlot, 0x2B992DDFA232L);   // 初始 cookie 魔数
            } else {
                w32(stubSec, lcfgOff + lcfgCookieOfs,
                        (int) (img.imageBase() + cookieSlotRva));
                w32(stubSec, lcfgCookieSlot, 0x0DDFA232);     // 32 位初始 cookie（魔数低半）
            }
        }

        // ---- 原生层多态（G2）：防御字符串池 XOR 加密 ----
        // 以每构建随机单字节键异或 [strpool, defense_end)，键写入 def_reserved[0]；
        // stub 在防御检查前就地还原（见 stub_x{64,86}.S），故完整性 CRC 仍成立。
        int strpoolKey = 0;
        if (Integer.compareUnsigned(sa.defenseEnd, sa.strpoolOff) > 0
                && Integer.compareUnsigned(sa.strpoolOff, sa.entryOff) >= 0
                && Integer.compareUnsigned(sa.defenseEnd, stubSec.size()) <= 0) {
            byte[] kb = new byte[1];
            do {
                randomBytes(kb, 0, 1);
            } while (kb[0] == 0);
            strpoolKey = kb[0] & 0xFF;
            for (int i = sa.strpoolOff; i < sa.defenseEnd; ++i) {
                stubSec.set(i, stubSec.get(i) ^ strpoolKey);
            }
        }

        // ---- 填充 KboxConfig ----
        {
            byte[] cfg = new byte[KboxFormat.CONFIG_SIZE];
            Bin.w32(cfg, KboxFormat.CFG_MAGIC, KboxFormat.KBOX_MAGIC);
            Bin.w32(cfg, KboxFormat.CFG_VERSION, KboxFormat.KBOX_VERSION);
            Bin.w32(cfg, KboxFormat.CFG_FLAGS, 0);
            Bin.w32(cfg, KboxFormat.CFG_IS64, is64 ? 1 : 0);
            Bin.w32(cfg, KboxFormat.CFG_STUB_RVA, stubRva);
            Bin.w32(cfg, KboxFormat.CFG_OEP_RVA, img.entryRva() + origShift);
            Bin.w32(cfg, KboxFormat.CFG_IMG_LO, (int) img.imageBase());
            Bin.w32(cfg, KboxFormat.CFG_IMG_HI, (int) (img.imageBase() >>> 32));
            Bin.w32(cfg, KboxFormat.CFG_PAY_RVA, payloadRva);
            Bin.w32(cfg, KboxFormat.CFG_PAY_SIZE, payloadPlainSize);
            System.arraycopy(key, 0, cfg, KboxFormat.CFG_KEY, 32);
            System.arraycopy(nonce, 0, cfg, KboxFormat.CFG_NONCE, 12);
            // VM 元数据：镜像表 + 运行期汇编引擎
            Bin.w32(cfg, KboxFormat.CFG_VM_COUNT, vms.size());
            Bin.w32(cfg, KboxFormat.CFG_VM_RECS_RVA, recsRva);
            Bin.w32(cfg, KboxFormat.CFG_VM_FLAGS, KboxFormat.VM_FLAG_PRESENT);
            Bin.w32(cfg, KboxFormat.CFG_VM_ENGINE_RVA, vmEngineRva);
            // ---- 运行期防御（第 5 项）：x64 / x86 两侧同一套检查与响应 ----
            // 完整性覆盖区 = blob 代码区 [entry_off, iat_off)：不含配置区（packer 写）
            // 与 stub 自身 IAT（loader 写），运行期不得被修改。
            Bin.w32(cfg, KboxFormat.CFG_DEF_FLAGS, opts.defFlags); // 运行期检测位掩码
            Bin.w32(cfg, KboxFormat.CFG_DEF_POLICY, opts.defPolicy); // 分级响应策略位
            Bin.w32(cfg, KboxFormat.CFG_DEF_REPORT_RVA, reportRva);
            Bin.w32(cfg, KboxFormat.CFG_DEF_INTEG_RVA, stubRva + sa.entryOff);
            Bin.w32(cfg, KboxFormat.CFG_DEF_INTEG_SIZE, sa.iatOff - sa.entryOff);
            Bin.w32(cfg, KboxFormat.CFG_DEF_INTEG_CRC, 0);      // 稍后基于最终 stub_sec 计算（见方案A 块）
            Bin.w32(cfg, KboxFormat.CFG_DEF_DECOY_RVA, 0);      // 使用内置诱饵
            Bin.w32(cfg, KboxFormat.CFG_DEF_DELAY, opts.defDelayLoops);
            Bin.w32(cfg, KboxFormat.CFG_DEF_TICKS, opts.defTimingTicks);
            // ---- TLS 回调（第 6 项）----
            Bin.w32(cfg, KboxFormat.CFG_TLS_CB_COUNT, tlsCbs.size());
            Bin.w32(cfg, KboxFormat.CFG_TLS_CB_RVA,
                    tlsCbs.isEmpty() ? 0 : (stubRva + tlsOff));
            Bin.w32(cfg, KboxFormat.CFG_DEF_RES0, strpoolKey);  // G2：字符串池 XOR 键（0 = 未加密）
            // 入口 trampoline 原始字节（stub 恢复节权限前写回 OEP）
            System.arraycopy(epOrig, 0, cfg, KboxFormat.CFG_EP_PATCH, 5);
            if (!tlsCbs.isEmpty()) {
                info(log, "  tls: " + tlsCbs.size()
                        + " callback(s) recorded (stub-invoked at OEP)");
            }
            stubSec.copyInto(0, cfg, 0, cfg.length);
        }

        // ---- 方案A：配置区加密 + 完整性期望值回填 ----
        // 顺序：写入最终 code 区（含种子槽）→ 据最终字节计算 CRC → 写回配置 → 加密配置区。
        // 配置区 [0,0x100) 在产物中为密文；仅在 stub 入口就地解密（stub_x{64,86}.S）。
        {
            // 1) 每构建随机 32-bit 流密钥种子，写入 kbox_cfg_root 槽
            byte[] seedBuf = new byte[4];
            randomBytes(seedBuf, 0, 4);
            int seed = Bin.i32(seedBuf, 0);
            if (seed == 0) {
                seed = 0x9E3779B9;
            }
            if (Integer.compareUnsigned(sa.cfgrootOff, sa.entryOff) >= 0
                    && (long) sa.cfgrootOff + 4 <= stubSec.size()) {
                w32(stubSec, sa.cfgrootOff, seed);
            }
            // 2) 基于最终字节计算完整性 CRC，写回配置（此时配置仍为明文）
            //    注意：stub 运行期会先还原字符串池，故 CRC 必须按「运行期视图」
            //    计算——先临时把字符串池解回明文，算完再重新加密。
            final boolean haveSp = strpoolKey != 0
                    && Integer.compareUnsigned(sa.defenseEnd, sa.strpoolOff) > 0;
            if (haveSp) {
                for (int i = sa.strpoolOff; i < sa.defenseEnd; ++i) {
                    stubSec.set(i, stubSec.get(i) ^ strpoolKey);
                }
            }
            final int crc = crc32Ieee(stubSec.array(), sa.entryOff, sa.iatOff - sa.entryOff);
            if (haveSp) {
                for (int i = sa.strpoolOff; i < sa.defenseEnd; ++i) {
                    stubSec.set(i, stubSec.get(i) ^ strpoolKey);
                }
            }
            w32(stubSec, KboxFormat.CFG_DEF_INTEG_CRC, crc);    // CFG_DEF_INTEG_CRC
            // 3) 用 LCG 流密钥加密配置区 [0,0x100)（与 stub 的 .Lcfg_loop 逐字节一致）
            int st = seed;
            for (int i = 0; i < 0x100; ++i) {
                st = st * 1664525 + 1013904223;                  // 32 位回绕
                stubSec.set(i, stubSec.get(i) ^ ((st >>> 16) & 0xFF));
            }
        }

        // ---- 重建 PE 头 ----
        final int eLfanew = Bin.i32(file.array(), 0x3C);
        final int nt = eLfanew;
        final int fh = nt + 4;
        final int optSize = r16(file, fh + 16);
        final int opt = fh + 20;
        final int dirOff = opt + (is64 ? 112 : 96);
        final int secTbl = opt + optSize;
        final int secCountOld = r16(file, fh + 2);

        // 重建节表：stub 前置为节 0/节 1，原节后移 2 项且 VA 整体 +origShift
        // （节表必须按 VA 递增；stub 位于最前 → 入口点与代码执行均在首个节，
        //  满足安全软件行为监控对「进程入口/代码须在首节」的要求）。
        byte[] oldTbl = new byte[secCountOld * 40];
        System.arraycopy(file.array(), secTbl, oldTbl, 0, oldTbl.length);
        for (int i = 0; i < secCountOld; ++i) {
            int vo = i * 40;
            int va = Bin.i32(oldTbl, vo + 12);
            Bin.w32(oldTbl, vo + 12, va + origShift);
            file.copyInto(secTbl + (i + 2) * 40, oldTbl, vo, 40);
        }

        // 节 A（代码）：blob[0, iat_off)，文件态 RX；stub 运行期临时 RWX 后恢复 RX
        byte[] shA = new byte[40];
        final String secAName = makeSectionName(img);      // G2：随机节名
        writeSectionName(shA, secAName);
        Bin.w32(shA, 8, secAVsize);                        // VirtualSize
        Bin.w32(shA, 12, stubRva);                         // VirtualAddress
        Bin.w32(shA, 16, secARawSize);                     // SizeOfRawData
        Bin.w32(shA, 20, stubRawPtr);                      // PointerToRawData
        Bin.w32(shA, 36, 0x60000020);                      // CNT_CODE|CNT_INITIALIZED|MEM_EXECUTE|MEM_READ（RX）
        file.copyInto(secTbl, shA, 0, 40);

        // 节 B（数据）：blob[iat_off, stub_size)，RWX（loader 回填 IAT、payload 就地解密）
        byte[] shB = new byte[40];
        final String secBName = makeSectionName(img);      // G2：随机节名
        writeSectionName(shB, secBName);
        Bin.w32(shB, 8, secBVsize);
        Bin.w32(shB, 12, stubRva + secAVsize);
        Bin.w32(shB, 16, secBRawSize);
        Bin.w32(shB, 20, stubBRawPtr);
        Bin.w32(shB, 36, 0xE0000040);                      // CNT_CODE|CNT_INITIALIZED|MEM_EXECUTE|MEM_READ|MEM_WRITE
        file.copyInto(secTbl + 40, shB, 0, 40);
        w16(file, fh + 2, secCountOld + 2);

        // 入口 / SizeOfImage
        // 入口 = stub（节 0 内）：满足「入口点须位于首个节」的行为监控要求。
        w32(file, opt + 16, stubRva + sa.entryOff);
        w32(file, opt + 56, newImageSize);

        // 数据目录
        w32(file, dirOff + PeImage.DIR_IMPORT * 8, impdirRva);
        w32(file, dirOff + PeImage.DIR_IMPORT * 8 + 4, impdirSize);
        // 以下目录清零（数据已被加密，loader 不得直接读取）
        final int[] clearDirs = {
                PeImage.DIR_SECURITY, PeImage.DIR_BASERELOC, PeImage.DIR_TLS,
                PeImage.DIR_LOADCONFIG, PeImage.DIR_BOUNDIMPORT, PeImage.DIR_IAT,
                PeImage.DIR_DELAYIMPORT, PeImage.DIR_CLR};
        for (int d : clearDirs) {
            w32(file, dirOff + d * 8, 0);
            w32(file, dirOff + d * 8 + 4, 0);
        }
        // 保留目录的 RVA 随原节整体后移（资源/异常/导出/调试等）
        for (int d = 0; d < 16; ++d) {
            if (d == PeImage.DIR_IMPORT) {
                continue;
            }
            boolean cleared = false;
            for (int c : clearDirs) {
                if (c == d) {
                    cleared = true;
                    break;
                }
            }
            if (cleared) {
                continue;
            }
            int rva = r32(file, dirOff + d * 8);
            if (rva != 0) {
                w32(file, dirOff + d * 8, rva + origShift);
            }
        }
        // G3：sv>=7 镜像——注入明文 LoadConfig 目录 + 清除 ASLR 标志
        // （Win11 24H2 loader 强制校验 SecurityCookie；固定基址装载使 cookie VA 无需重定位）
        if (needLoadConfig) {
            w32(file, dirOff + PeImage.DIR_LOADCONFIG * 8, lcfgRva);
            w32(file, dirOff + PeImage.DIR_LOADCONFIG * 8 + 4, lcfgSize);
            int dc = r16(file, opt + 70);
            w16(file, opt + 70, dc & ~(0x0040 | 0x0020));   // 清 DYNAMIC_BASE + HIGH_ENTROPY_VA
        }

        // ---- 写出（两节各自写自己的 raw 区）----
        file.resize(stubBRawPtr + secBRawSize);
        System.arraycopy(stubSec.array(), 0, file.array(), stubRawPtr, secALen);
        System.arraycopy(stubSec.array(), secALen, file.array(), stubBRawPtr,
                stubSize - secALen);
        if (!writeFile(outPath, file, err)) {
            error(log, "kbox_packer: " + err);
            return 1;
        }
        info(log, "kbox_packer: " + inPath + " -> " + outPath);
        info(log, "  arch=" + (is64 ? "x64" : "x86")
                + " stub_rva=" + hx(stubRva)
                + " entry=" + hx(stubRva + sa.entryOff)
                + " payload=" + hx(payloadRva) + "+" + hx(payloadPlainSize)
                + " secs=" + secCount + " imps=" + impDllCount + " reloc=" + relocSize);
        info(log, "  vm images=" + vms.size()
                + " at=" + hx(vmBaseRva) + "+" + hx(vmAligned)
                + " tramp=" + trampCount
                + " recs=" + hx(recsRva)
                + " engine=" + hx(vmEngineRva) + "+" + hx(engineSize));
        // ---- 加壳产物自检（PE 结构 + KboxConfig 可解密性） ----
        // 目的：把「能写出但 Windows 直接拒载」这类问题在打包阶段就暴露出来。
        try {
            ShieldVerify.Report rep = ShieldVerify.verify(outPath, opts);
            for (String line : rep.toText().split("\n")) {
                info(log, line);
            }
        } catch (Throwable t) {
            error(log, "  [verify] 自检异常（不影响产物）: " + t);
        }
        return 0;
    }

    // ================= 辅助 =================

    /** lambda {@code str_off_of}：字符串写入字符串区，返回其相对 pay 的偏移（含 '\0' 结尾）。 */
    private static int strOffOf(Vec pay, String s) {
        int o = pay.size();
        byte[] raw = s.getBytes(StandardCharsets.US_ASCII);
        pay.append(raw, 0, raw.length);
        pay.append(new byte[]{0}, 0, 1);
        return o;
    }

    /** lambda {@code fill_rand}：随机化 [lo, hi)（hi 越界或 hi <= lo 时不动）。 */
    private static void fillRand(Vec v, int lo, int hi) {
        if (hi > lo && Integer.compareUnsigned(hi, v.size()) <= 0) {
            randomBytes(v.array(), lo, hi - lo);
        }
    }

    /** {@code memcpy(sh.Name, name.c_str(), name.size())}（8 字节定长，含 NUL）。 */
    private static void writeSectionName(byte[] sh, String name) {
        byte[] raw = name.getBytes(StandardCharsets.US_ASCII);
        int n = Math.min(raw.length, 8);
        System.arraycopy(raw, 0, sh, 0, n);
    }

    /**
     * 原节 VA 整体后移 origShift 后，修正节内「镜像内 RVA」引用。
     * 重定位目标值、.pdata（异常展开表）、.rsrc（资源目录树）、.edata（导出表）
     * 中的 RVA 均须 +origShift，否则 stub 重定位、loader 解析资源、异常展开、
     * GetProcAddress 都会错位。必须在节加密之前调用。
     */
    private static void shiftImageInternals(PeImage img, Vec file, byte[] reloc,
                                            int shift, StringBuilder err) {
        int[] off = new int[1];
        // 1) 重定位目标值：stored = imageBase + origRVA；+shift 使 stub 的
        //    delta = 实际基址 - imageBase 语义不变（页面 RVA 已在 payload 内 +shift）。
        {
            int pos = 0;
            while (pos + 8 <= reloc.length) {
                int blkRva = Bin.i32(reloc, pos);
                int blkSize = Bin.i32(reloc, pos + 4);
                if (blkSize < 8 || pos + blkSize > reloc.length) {
                    break;
                }
                int n = (blkSize - 8) / 2;
                for (int i = 0; i < n; ++i) {
                    int ent = Bin.u16(reloc, pos + 8 + i * 2);
                    int type = ent >>> 12;
                    int delta = ent & 0xFFF;
                    if (type == 3) {                          // HIGHLOW
                        if (img.rvaToOffset(blkRva + delta, off)) {
                            long v = Bin.u32(file.array(), off[0]);
                            Bin.w32(file.array(), off[0], (int) (v + shift));
                        }
                    } else if (type == 10) {                  // DIR64
                        if (img.rvaToOffset(blkRva + delta, off)) {
                            long v = Bin.i64(file.array(), off[0]);
                            Bin.w64(file.array(), off[0], v + shift);
                        }
                    }
                }
                pos += blkSize;
            }
        }
        // 2) .pdata：RUNTIME_FUNCTION 的 Begin/End/UnwindInfo 均为镜像内 RVA
        if (img.hasDirectory(PeImage.DIR_EXCEPTION)) {
            int dirRva = img.directoryRva(PeImage.DIR_EXCEPTION);
            for (PeImage.SectionInfo s : img.sections()) {
                if (Integer.compareUnsigned(dirRva, s.virtualAddress) >= 0
                        && Integer.compareUnsigned(dirRva,
                                s.virtualAddress + s.rawSize) < 0) {
                    int cnt = (s.rawSize / 12) * 12;
                    for (int o = 0; o < cnt; o += 12) {
                        for (int k = 0; k < 12; k += 4) {
                            long v = Bin.u32(file.array(), s.rawPtr + o + k);
                            Bin.w32(file.array(), s.rawPtr + o + k, (int) (v + shift));
                        }
                    }
                    break;
                }
            }
        }
        // 3) .rsrc：资源目录树叶子数据项的 OffsetToData（RVA）与
        //    IMAGE_RESOURCE_DATA_ENTRY.OffsetToData（RVA）
        if (img.hasDirectory(PeImage.DIR_RESOURCE)) {
            int dirRva = img.directoryRva(PeImage.DIR_RESOURCE);
            for (PeImage.SectionInfo s : img.sections()) {
                if (Integer.compareUnsigned(dirRva, s.virtualAddress) >= 0
                        && Integer.compareUnsigned(dirRva,
                                s.virtualAddress + s.rawSize) < 0) {
                    int base = s.rawPtr + (dirRva - s.virtualAddress);
                    java.util.HashSet<Integer> visited = new java.util.HashSet<Integer>();
                    walkResourceDir(img, file, s, base, dirRva, dirRva, shift, visited);
                    break;
                }
            }
        }
        // 4) .edata（DLL 导出）：目录内 RVA 字段 + 函数/名字 RVA 数组
        if (img.hasDirectory(PeImage.DIR_EXPORT)) {
            int dirRva = img.directoryRva(PeImage.DIR_EXPORT);
            for (PeImage.SectionInfo s : img.sections()) {
                if (Integer.compareUnsigned(dirRva, s.virtualAddress) >= 0
                        && Integer.compareUnsigned(dirRva,
                                s.virtualAddress + s.rawSize) < 0) {
                    int eo = s.rawPtr + (dirRva - s.virtualAddress);
                    if (eo + 40 > file.size()) {
                        break;
                    }
                    int nFunc = (int) Bin.u32(file.array(), eo + 20);
                    int nNames = (int) Bin.u32(file.array(), eo + 24);
                    // 先按「原始 RVA」定位函数/名字表并整体加 shift（img 为原始镜像，
                    // 必须用未加 shift 的 RVA 才能解析到文件偏移）。
                    int funcRva0 = Bin.i32(file.array(), eo + 28);
                    if (funcRva0 != 0 && img.rvaToOffset(funcRva0, off)) {
                        for (int i = 0; i < nFunc; ++i) {
                            int v = Bin.i32(file.array(), off[0] + i * 4);
                            if (v != 0) {
                                Bin.w32(file.array(), off[0] + i * 4, v + shift);
                            }
                        }
                    }
                    int namesRva0 = Bin.i32(file.array(), eo + 32);
                    if (namesRva0 != 0 && img.rvaToOffset(namesRva0, off)) {
                        for (int i = 0; i < nNames; ++i) {
                            int v = Bin.i32(file.array(), off[0] + i * 4);
                            if (v != 0) {
                                Bin.w32(file.array(), off[0] + i * 4, v + shift);
                            }
                        }
                    }
                    // 最后修正目录内 RVA 字段：Name@12、AddressOfFunctions@28、
                    // AddressOfNames@32、AddressOfNameOrdinals@36。
                    // 注意：Base@16、NumberOfFunctions@20、NumberOfNames@24
                    // 是标量（基序号/计数），加 shift 会把计数改成 0xD000+ 的巨值，
                    // 导致 GetProcAddress 的二分查找按错误的计数与地址行走
                    // （实测 .edata 解密后 NumNames=0xD003、AddrNames=0x8034 → 直接越界）。
                    int[] rvaFields = {12, 28, 32, 36};
                    for (int k = 0; k < rvaFields.length; ++k) {
                        int f = rvaFields[k];
                        int v = Bin.i32(file.array(), eo + f);
                        if (v != 0) {
                            Bin.w32(file.array(), eo + f, v + shift);
                        }
                    }
                    break;
                }
            }
        }
    }

    /** 递归修正资源目录树（rootRva 为资源根目录 RVA，子目录偏移相对资源根）。 */
    private static void walkResourceDir(PeImage img, Vec file, PeImage.SectionInfo rs,
                                        int base, int rootRva, int curRva, int shift,
                                        java.util.HashSet<Integer> visited) {
        if (!visited.add(Integer.valueOf(curRva))) {
            return;
        }
        int dirOff = base + (curRva - rootRva);
        if (dirOff + 16 > file.size()) {
            return;
        }
        int numNamed = Bin.u16(file.array(), dirOff + 12);
        int numId = Bin.u16(file.array(), dirOff + 14);
        int total = numNamed + numId;
        for (int i = 0; i < total; ++i) {
            int eo = dirOff + 16 + i * 8;
            if (eo + 8 > file.size()) {
                break;
            }
            int offData = Bin.i32(file.array(), eo + 4);
            if ((offData & 0x80000000) != 0) {
                // 子目录：低 31 位为相对资源根的偏移
                int subRva = rootRva + (offData & 0x7FFFFFFF);
                walkResourceDir(img, file, rs, base, rootRva, subRva, shift, visited);
            } else if (offData != 0) {
                // 叶子：OffsetToData 为相对资源根的偏移（非 RVA）；
                // IMAGE_RESOURCE_DATA_ENTRY.OffsetToData 才是镜像内 RVA（+shift）
                int deOff = base + offData;
                if (deOff + 4 <= file.size()) {
                    long o = Bin.u32(file.array(), deOff);
                    if (o != 0) {
                        Bin.w32(file.array(), deOff, (int) (o + shift));
                    }
                }
            }
        }
    }

    // ================= 可变字节缓冲（对应 std::vector<uint8_t>） =================

    /**
     * 对应 {@code std::vector<uint8_t>} 的 Java 替身：支持 {@code resize(n, 0)}（增长清零 /
     * 截断）、顺序 {@code insert}（{@link #append}）与按偏移直写（{@link #set}/{@link #ensure}）。
     */
    private static final class Vec {
        private byte[] a;
        private int n;

        Vec() {
            this(64);
        }

        Vec(int cap) {
            a = new byte[cap < 0 ? 0 : cap];
        }

        int size() {
            return n;
        }

        byte[] array() {
            return a;
        }

        /** 保证底层容量至少 end（不改变 size）。 */
        void ensure(int end) {
            if (end <= a.length) {
                return;
            }
            int cap = a.length == 0 ? 64 : a.length;
            while (cap < end && cap < (1 << 30)) {
                cap <<= 1;
            }
            if (cap < end) {
                cap = end;
            }
            byte[] na = new byte[cap];
            System.arraycopy(a, 0, na, 0, n);
            a = na;
        }

        void resize(int newSize) {
            resize(newSize, 0);
        }

        void resize(int newSize, int fill) {
            if (newSize < 0) {
                throw new IllegalArgumentException("resize " + newSize);
            }
            ensure(newSize);
            if (newSize > n) {
                Arrays.fill(a, n, newSize, (byte) fill);
            }
            n = newSize;
        }

        int get(int i) {
            return a[i] & 0xFF;
        }

        void set(int i, int v) {
            ensure(i + 1);
            a[i] = (byte) v;
        }

        void append(byte[] src, int off, int len) {
            if (len <= 0) {
                return;
            }
            ensure(n + len);
            System.arraycopy(src, off, a, n, len);
            n += len;
        }

        /** 按绝对偏移写入源字节（对应 {@code std::memcpy(d.data()+off, ...)}，不改变 size）。 */
        void copyInto(int dstOff, byte[] src, int srcOff, int len) {
            if (len <= 0) {
                return;
            }
            ensure(dstOff + len);
            System.arraycopy(src, srcOff, a, dstOff, len);
        }

        byte[] toArray() {
            byte[] r = new byte[n];
            System.arraycopy(a, 0, r, 0, n);
            return r;
        }
    }
}
