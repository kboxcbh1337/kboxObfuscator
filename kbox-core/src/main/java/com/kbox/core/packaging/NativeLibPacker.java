package com.kbox.core.packaging;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.log.KBoxLog;
import com.kbox.core.shield.ShieldOptions;
import com.kbox.core.shield.ShieldPacker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * NativeLibPacker — jar 内自带原生库（.dll/.so/.dylib）加壳打包（protectNativeLibs）。
 *
 * <p>混淆时自动扫描输入 jar 的<b>全部目录</b>（经由 {@link ClassGraph#getResources()}，
 * 非 class 非 META-INF/kbox 条目均在列），对每个原生库条目：</p>
 * <ul>
 *   <li>{@code .dll}（PE）→ 提取后经 {@link ShieldPacker} <b>完整加壳</b>：全节
 *       ChaCha20 加密 + 合成导入表 + 函数级虚拟化（.pdata 逐函数）+ 指令变异 +
 *       控制流平坦化（双族 VM），产物是自解密的可加载 PE。</li>
 *   <li>{@code .so/.dylib}（ELF/Mach-O）→ PE 壳暂不支持，降级为压缩 + ChaCha20
 *       加密存储（运行时解密落盘 {@code System.load}）。</li>
 * </ul>
 *
 * <p>随后每个（加壳后或原样）库经 {@code NativePacker} 压缩+加密成 KBNL blob，
 * 写入 {@code META-INF/kbox/natlib/N.bin}；清单写入
 * {@code META-INF/kbox/natlibs.list}（每行 {@code 逻辑路径|blob路径|扩展名}）。
 * 产物 jar 中不再存在明文原生库。运行时由
 * {@link com.kbox.runtime.NativeLoader#loadNativeLibs()} 按当前 OS 匹配扩展名
 * 解密落盘加载并擦除临时文件。</p>
 *
 * <p>加壳选项说明：业务 DLL 在 JVM 进程内由 {@code System.load} 加载，Shield 的
 * 运行期防御自检（PEB/时序/VM 探测）在宿主进程内易误判且与杀软实时防护冲突
 * （见经验：defFlags=0 包不受 AV 影响），故 {@code defFlags=0}；虚拟化/变异/平坦化
 * 照常全开，这才是本功能的核心防护。</p>
 */
public final class NativeLibPacker {

    private static final String TAG = "natlib-pack";

    private NativeLibPacker() {
    }

    /** 单个原生库条目的打包结果元数据。 */
    public static final class Entry {
        /** 输入 jar 中的逻辑路径（不含 Spring Boot clsRoot 前缀），如 {@code com/example/native/foo.dll}。 */
        public final String logicalPath;
        /** 产物 jar 中的 blob 路径，如 {@code META-INF/kbox/natlib/0.bin}。 */
        public final String blobPath;
        /** 扩展名小写：dll / so / dylib。 */
        public final String ext;
        /** true 表示经 ShieldPacker 完整加壳 + 虚拟化（仅 .dll）；so/dylib 为加密降级。 */
        public final boolean virtualized;
        /** 原始原生库字节数。 */
        public final int rawLen;

        Entry(String logicalPath, String blobPath, String ext, boolean virtualized, int rawLen) {
            this.logicalPath = logicalPath;
            this.blobPath = blobPath;
            this.ext = ext;
            this.virtualized = virtualized;
            this.rawLen = rawLen;
        }
    }

    /** 打包结果：条目列表 + blobPath→blob 字节。 */
    public static final class Result {
        public final List<Entry> entries = new ArrayList<>();
        /** blobPath → KBNL blob（已压缩+ChaCha20 加密）。 */
        public final Map<String, byte[]> blobs = new LinkedHashMap<>();
        private final Map<String, Entry> byLogical = new LinkedHashMap<>();

        public boolean contains(String logicalPath) {
            return byLogical.containsKey(logicalPath);
        }

        public Entry get(String logicalPath) {
            return byLogical.get(logicalPath);
        }

        void add(Entry e, byte[] blob) {
            entries.add(e);
            byLogical.put(e.logicalPath, e);
            blobs.put(e.blobPath, blob);
        }
    }

    /**
     * 扫描并打包 jar 内全部原生库。任何单个库失败（如加壳异常）仅降级，
     * 不会使整个构建失败。
     *
     * @param graph   已加载的类图（含全部资源字节）
     * @param workDir 工作目录（存放临时加壳中间文件）
     */
    public static Result pack(ClassGraph graph, Path workDir) {
        Result r = new Result();
        if (graph == null || graph.getResources().isEmpty()) {
            return r;
        }
        try {
            Files.createDirectories(workDir);
        } catch (IOException e) {
            KBoxLog.warn(TAG, "Cannot create work dir " + workDir + ": " + e.getMessage());
        }
        int idx = 0;
        for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            String path = e.getKey();
            if (path == null) continue;
            // KBox 自产 blob（native.bin/jnic.bin/vmp.bin/native-crypto.bin 等）本身已是
            // KBNL（压缩+ChaCha20）密文，不重复加壳。
            if (path.startsWith("META-INF/kbox/")) continue;
            byte[] raw = e.getValue();
            if (raw == null) continue;
            String ext = nativeLibExt(path, raw);
            if (ext == null) continue;
            if (raw.length == 0) {
                KBoxLog.warn(TAG, "Skip empty native lib entry: " + path);
                continue;
            }
            // 扩展名未声明为原生库、但内容魔数判定为共享库（如以 *.bin/.dat 命名的 dll/so）。
            boolean magicDetected = !hasNativeExt(path);
            boolean isDll = "dll".equals(ext);
            byte[] lib = raw;
            boolean virtualized = false;
            if (isDll) {
                try {
                    lib = shieldPack(raw, workDir, idx);
                    virtualized = true;
                } catch (Throwable t) {
                    KBoxLog.warn(TAG, "ShieldPacker failed for " + path + ": " + t.getMessage()
                            + " — falling back to encrypted storage");
                }
            }
            com.kbox.core.jnic.NativePacker.Packed packed = com.kbox.core.jnic.NativePacker.pack(lib);
            String blobPath = "META-INF/kbox/natlib/" + idx + ".bin";
            r.add(new Entry(path, blobPath, ext, virtualized, raw.length), packed.blob);
            KBoxLog.info(TAG, "Packed native lib " + path + " -> " + blobPath
                    + " (mode=" + (virtualized ? "shield+vm" : "encrypt-only")
                    + (magicDetected ? ", 内容魔数识别" : "")
                    + ", raw=" + raw.length + "B, blob=" + packed.blob.length + "B)");
            idx++;
        }
        KBoxLog.info(TAG, "Native library packing complete: " + r.entries.size() + " lib(s)");
        return r;
    }

    /**
     * 判定资源条目是否为原生库，返回格式标签（{@code dll}/{@code so}/{@code dylib}），
     * 非原生库返回 {@code null}。
     *
     * <p>规则：<b>扩展名优先</b>（保持既有行为，含 jar 内以 .dll/.so/.dylib 命名的条目）；
     * 扩展名不匹配时按<b>内容魔数</b>识别——因此以 {@code .bin}/{@code .dat} 等任意名字
     * 打包在 jar 里的原生库同样会被加壳。魔数路径只接受「共享库」语义的镜像
     * （PE 带 {@code IMAGE_FILE_DLL}、ELF 为 {@code ET_DYN}、Mach-O 为
     * {@code MH_DYLIB}/{@code MH_BUNDLE}），避免把 jar 内附带的可执行文件或普通数据误判。</p>
     */
    public static String nativeLibExt(String path, byte[] raw) {
        String l = path == null ? "" : path.toLowerCase(Locale.ROOT);
        if (l.endsWith(".dll")) return "dll";
        if (l.endsWith(".so")) return "so";
        if (l.endsWith(".dylib")) return "dylib";
        return detectSharedObject(raw);
    }

    /** 资源路径扩展名是否已声明为原生库（dll/so/dylib）。 */
    public static boolean hasNativeExt(String path) {
        String l = path == null ? "" : path.toLowerCase(Locale.ROOT);
        return l.endsWith(".dll") || l.endsWith(".so") || l.endsWith(".dylib");
    }

    /** 供资源混淆阶段复用：该资源是否为（将被接管的）原生库条目。 */
    public static boolean isNativeLibResource(String path, byte[] raw) {
        return nativeLibExt(path, raw) != null;
    }

    /**
     * 按内容魔数识别共享库（与文件名无关）：
     * <ul>
     *   <li>PE：{@code MZ} + {@code e_lfanew} 指向 {@code PE\0\0}，且 COFF
     *       Characteristics 置位 {@code IMAGE_FILE_DLL}(0x2000)</li>
     *   <li>ELF：{@code \x7fELF}，且 {@code e_type == ET_DYN}(3)（共享对象，含 PIE 库）</li>
     *   <li>Mach-O（thin）：{@code filetype} 为 {@code MH_DYLIB}(6) 或 {@code MH_BUNDLE}(8)</li>
     * </ul>
     * 返回 {@code dll}/{@code so}/{@code dylib}，未识别返回 {@code null}。
     * 不识别胖（FAT）Mach-O——其前 4 字节 {@code CAFEBABE} 与 Java class 魔数冲突，
     * 交由扩展名路径处理更安全。
     */
    private static String detectSharedObject(byte[] b) {
        int n = (b == null) ? 0 : b.length;
        if (n < 64) return null;
        // PE
        if ((b[0] & 0xFF) == 0x4D && (b[1] & 0xFF) == 0x5A) {
            int lfanew = i32le(b, 0x3C);
            if (lfanew > 0 && lfanew + 24 <= n
                    && b[lfanew] == 'P' && b[lfanew + 1] == 'E'
                    && b[lfanew + 2] == 0 && b[lfanew + 3] == 0) {
                int chars = (b[lfanew + 22] & 0xFF) | ((b[lfanew + 23] & 0xFF) << 8);
                if ((chars & 0x2000) != 0) return "dll";
            }
            return null;
        }
        // ELF
        if ((b[0] & 0xFF) == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
            boolean be = (b[5] & 0xFF) == 2;              // EI_DATA: 1=LE, 2=BE
            int eType = be ? (((b[16] & 0xFF) << 8) | (b[17] & 0xFF))
                           : ((b[16] & 0xFF) | ((b[17] & 0xFF) << 8));
            return eType == 3 ? "so" : null;             // ET_DYN
        }
        // Mach-O thin
        int m = ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        boolean le = (m == 0xCEFAEDFE || m == 0xCFFAEDFE);   // 磁盘上为小端
        boolean be = (m == 0xFEEDFACE || m == 0xFEEDFACF);   // 磁盘上为大端
        if (le || be) {
            int ft = le
                    ? ((b[12] & 0xFF) | ((b[13] & 0xFF) << 8)
                       | ((b[14] & 0xFF) << 16) | ((b[15] & 0xFF) << 24))
                    : (((b[12] & 0xFF) << 24) | ((b[13] & 0xFF) << 16)
                       | ((b[14] & 0xFF) << 8) | (b[15] & 0xFF));
            if (ft == 6 || ft == 8) return "dylib";
        }
        return null;
    }

    private static int i32le(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    /**
     * 对一个 .dll 做 ShieldPacker 完整加壳（含函数级虚拟化/变异/平坦化）。
     * 失败抛异常，由调用方降级为加密存储。
     */
    private static byte[] shieldPack(byte[] raw, Path workDir, int idx) throws Exception {
        Path in = workDir.resolve("natlib-in-" + idx + ".dll");
        Path out = workDir.resolve("natlib-out-" + idx + ".dll");
        Files.write(in, raw);
        try {
            ShieldOptions opts = new ShieldOptions();
            // 进程内（JVM 宿主）加载：关闭运行期防御自检，避免误判与杀软冲突。
            opts.defFlags = 0;
            opts.defPolicy = 0;
            // 核心防护：函数级虚拟化 + 指令变异 + 控制流平坦化（双族 VM）。
            opts.virtualizeFunctions = true;
            opts.irMutation = 2;
            opts.cfgFlatten = true;
            StringBuilder log = new StringBuilder();
            boolean ok = ShieldPacker.pack(in.toString(), out.toString(), opts, log);
            if (!ok || !Files.exists(out) || Files.size(out) == 0) {
                throw new IOException("ShieldPacker failed: " + log);
            }
            return Files.readAllBytes(out);
        } finally {
            try { Files.deleteIfExists(in); } catch (Exception ignored) {}
            try { Files.deleteIfExists(out); } catch (Exception ignored) {}
        }
    }
}
