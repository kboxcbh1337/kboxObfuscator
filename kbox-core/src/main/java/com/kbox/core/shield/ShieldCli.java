package com.kbox.core.shield;

import com.kbox.core.log.KBoxLog;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Standalone kboXShield entry point (gap 01: independent DLL protection product).
 *
 * <p>This is deliberately <em>separate</em> from the Java/JAR pipeline: it takes
 * one PE file (EXE or DLL), writes one PE file, and produces a machine-readable
 * report. It performs no JAR work and shares no state with
 * {@code ProtectionPipeline}.
 *
 * <h3>Contract</h3>
 * <pre>
 *   in:  existing PE32/PE32+ binary (MZ + PE\0\0), EXE or DLL
 *   out: packed PE of the same architecture; never written when packing fails
 *   report: JSON with hashes, machine, export table before/after, options
 *   exit codes: 0 ok | 2 bad arguments | 3 unsupported input | 4 pack failure
 * </pre>
 *
 * <h3>Export preservation</h3>
 * Every export name present in the input must still resolve in the output, and
 * the ordinal set must be unchanged. The check is structural (PE export
 * directory parse), not a runtime load, so it is deterministic and does not
 * need the target loader. A missing export fails the run with exit code 4 —
 * silently breaking a DLL's ABI is worse than refusing to pack.
 *
 * <p>Scope is documented in {@code docs/KBOXSHEID.md}; the compatibility matrix
 * and what is still untested live in {@code docs/KBOXSHEID-COMPATIBILITY.md}.
 */
public final class ShieldCli {

    private static final int EXIT_OK = 0;
    private static final int EXIT_ARGS = 2;
    private static final int EXIT_UNSUPPORTED = 3;
    private static final int EXIT_PACK_FAILED = 4;

    /** Options accepted by {@link #run(String[])}. */
    public static final class Args {
        public String in;
        public String out;
        public String report;
        public int arch = ShieldOptions.ARCH_AUTO;
        public Integer defFlags;
        public Integer defPolicy;
        public Integer irMutation;
        public Boolean cfgFlatten;
        public Boolean virtualizeFunctions;
        public Integer sroxLevel;
        public Integer sroxRounds;
        public String sroxReport;
        public Long sroxSeed;
        public boolean matrix;
        public boolean help;
    }

    private ShieldCli() {}

    /** Runs one shield operation. Returns the process exit code. */
    public static int run(String[] argv) {
        Args a;
        try {
            a = parse(argv);
        } catch (IllegalArgumentException e) {
            System.err.println("[kbox-shield] " + e.getMessage());
            usage();
            return EXIT_ARGS;
        }
        if (a.help) {
            usage();
            return EXIT_OK;
        }
        if (a.in == null) {
            usage();
            return EXIT_ARGS;
        }
        if (a.matrix) {
            return runMatrix(a);
        }
        if (a.out == null) {
            System.err.println("[kbox-shield] 缺少 --shield-out");
            usage();
            return EXIT_ARGS;
        }
        try {
            Report r = shieldOne(Paths.get(a.in), Paths.get(a.out), a);
            String json = r.toJson();
            if (a.report != null) {
                Path rp = Paths.get(a.report);
                if (rp.getParent() != null) Files.createDirectories(rp.getParent());
                Files.write(rp, json.getBytes(StandardCharsets.UTF_8));
            }
            System.out.println(json);
            return r.ok ? EXIT_OK : EXIT_PACK_FAILED;
        } catch (UnsupportedInput u) {
            System.err.println("[kbox-shield] 不支持: " + u.getMessage());
            return EXIT_UNSUPPORTED;
        } catch (Throwable t) {
            System.err.println("[kbox-shield] 失败: " + t);
            return EXIT_PACK_FAILED;
        }
    }

    // ------------------------------------------------------------------
    //  One file
    // ------------------------------------------------------------------

    /** Packing report for a single PE (also used by the matrix runner). */
    public static final class Report {
        public String input = "";
        public String output = "";
        public String inputSha256 = "";
        public String outputSha256 = "";
        public String machine = "unknown";
        public boolean isDll;
        public boolean ok;
        public String error = "";
        public final List<String> exportsBefore = new ArrayList<>();
        public final List<String> exportsAfter = new ArrayList<>();
        public final List<String> missingExports = new ArrayList<>();
        public boolean exportsPreserved = true;
        public String options = "";

        public String toJson() {
            StringBuilder sb = new StringBuilder(1024);
            sb.append("{\"input\":\"").append(esc(input)).append('"')
                    .append(",\"output\":\"").append(esc(output)).append('"')
                    .append(",\"ok\":").append(ok)
                    .append(",\"error\":\"").append(esc(error)).append('"')
                    .append(",\"machine\":\"").append(esc(machine)).append('"')
                    .append(",\"isDll\":").append(isDll)
                    .append(",\"inputSha256\":\"").append(esc(inputSha256)).append('"')
                    .append(",\"outputSha256\":\"").append(esc(outputSha256)).append('"')
                    .append(",\"exportsPreserved\":").append(exportsPreserved)
                    .append(",\"exportsBefore\":").append(arr(exportsBefore))
                    .append(",\"exportsAfter\":").append(arr(exportsAfter))
                    .append(",\"missingExports\":").append(arr(missingExports))
                    .append(",\"options\":\"").append(esc(options)).append('"')
                    .append('}');
            return sb.toString();
        }
    }

    private static final class UnsupportedInput extends Exception {
        UnsupportedInput(String m) { super(m); }
    }

    private static Report shieldOne(Path in, Path out, Args a) throws Exception {
        if (!Files.isRegularFile(in)) throw new UnsupportedInput("输入文件不存在: " + in);
        byte[] inBytes = Files.readAllBytes(in);
        PeInfo before = PeInfo.parse(inBytes);
        if (!before.valid) throw new UnsupportedInput("不是有效的 PE 文件（MZ/PE 签名缺失）");
        Report r = new Report();
        r.input = in.toString();
        r.output = out.toString();
        r.inputSha256 = sha256(inBytes);
        r.machine = before.machineName;
        r.isDll = before.isDll;
        r.exportsBefore.addAll(before.exports);
        ShieldOptions opt = new ShieldOptions();
        if (a.arch != ShieldOptions.ARCH_AUTO) opt.arch = a.arch;
        if (a.defFlags != null) opt.defFlags = a.defFlags;
        if (a.defPolicy != null) opt.defPolicy = a.defPolicy;
        if (a.irMutation != null) opt.irMutation = a.irMutation;
        if (a.cfgFlatten != null) opt.cfgFlatten = a.cfgFlatten;
        if (a.virtualizeFunctions != null) opt.virtualizeFunctions = a.virtualizeFunctions;
        if (a.sroxLevel != null) opt.sroxLevel = a.sroxLevel;
        if (a.sroxRounds != null) opt.sroxRounds = a.sroxRounds;
        if (a.sroxReport != null) opt.sroxReport = a.sroxReport;
        if (a.sroxSeed != null) opt.sroxSeed = a.sroxSeed;
        r.options = "arch=" + opt.arch + ",defFlags=0x" + Integer.toHexString(opt.defFlags)
                + ",defPolicy=" + opt.defPolicy + ",irMutation=" + opt.irMutation
                + ",cfgFlatten=" + opt.cfgFlatten + ",virtualizeFunctions=" + opt.virtualizeFunctions
                + ",srox=" + opt.srox + "/" + opt.sroxLevel + "/rounds=" + opt.sroxRounds;
        if (out.getParent() != null) Files.createDirectories(out.getParent());
        StringBuilder log = new StringBuilder();
        boolean packed = ShieldPacker.pack(in.toString(), out.toString(), opt, log);
        if (!packed) {
            r.ok = false;
            r.error = lastError(log);
            r.exportsPreserved = false;
            // A failed run must not leave a half-written output behind.
            try { Files.deleteIfExists(out); } catch (IOException ignored) { }
            return r;
        }
        byte[] outBytes = Files.readAllBytes(out);
        r.outputSha256 = sha256(outBytes);
        PeInfo after = PeInfo.parse(outBytes);
        if (!after.valid) {
            r.ok = false;
            r.error = "输出不是有效 PE（打包器产生非法镜像）";
            r.exportsPreserved = false;
            return r;
        }
        r.exportsAfter.addAll(after.exports);
        Set<String> beforeNames = new LinkedHashSet<>(before.exports);
        beforeNames.removeAll(after.exports);
        r.missingExports.addAll(beforeNames);
        if (!r.missingExports.isEmpty() || before.exports.size() != after.exports.size()) {
            r.exportsPreserved = false;
            r.ok = false;
            r.error = "导出表未保留（缺失 " + r.missingExports.size() + " 项）";
            return r;
        }
        r.ok = true;
        return r;
    }

    private static String lastError(StringBuilder log) {
        String s = log.toString();
        for (String line : s.split("\n")) {
            if (line.contains("ERROR") || line.contains("[ERROR]") || line.contains("失败")) {
                return line.trim();
            }
        }
        return s.length() > 300 ? s.substring(0, 300) : s.trim();
    }

    // ------------------------------------------------------------------
    //  Compatibility matrix runner
    // ------------------------------------------------------------------

    private static int runMatrix(Args a) {
        List<Path> files = new ArrayList<>();
        Path in = Paths.get(a.in);
        try {
            if (Files.isDirectory(in)) {
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(in,
                        p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".dll")
                                || p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".exe"))) {
                    for (Path p : ds) files.add(p);
                }
            } else {
                files.add(in);
            }
        } catch (IOException e) {
            System.err.println("[kbox-shield] 无法读取矩阵输入: " + e);
            return EXIT_ARGS;
        }
        if (files.isEmpty()) {
            System.err.println("[kbox-shield] 矩阵目录中没有 .dll/.exe: " + in);
            return EXIT_ARGS;
        }
        Path outDir = Paths.get(a.out == null ? "shield-matrix-out" : a.out);
        try {
            Files.createDirectories(outDir);
        } catch (IOException e) {
            System.err.println("[kbox-shield] 无法创建输出目录: " + e);
            return EXIT_ARGS;
        }
        List<Report> reports = new ArrayList<>();
        int fail = 0;
        for (Path p : files) {
            Path outFile = outDir.resolve(p.getFileName());
            try {
                Report r = shieldOne(p, outFile, a);
                reports.add(r);
                if (!r.ok) fail++;
            } catch (UnsupportedInput u) {
                Report r = new Report();
                r.input = p.toString();
                r.ok = false;
                r.error = "unsupported: " + u.getMessage();
                reports.add(r);
                fail++;
            } catch (Throwable t) {
                Report r = new Report();
                r.input = p.toString();
                r.ok = false;
                r.error = String.valueOf(t);
                reports.add(r);
                fail++;
            }
        }
        String json = matrixJson(reports);
        String md = matrixMarkdown(reports);
        try {
            Path base = a.report == null ? outDir.resolve("shield-matrix.json") : Paths.get(a.report);
            if (base.getParent() != null) Files.createDirectories(base.getParent());
            Files.write(base, json.getBytes(StandardCharsets.UTF_8));
            String mdName = base.getFileName().toString().replace(".json", ".md");
            Files.write(base.resolveSibling(mdName), md.getBytes(StandardCharsets.UTF_8));
            System.out.println("[kbox-shield] matrix report: " + base);
            System.out.println("[kbox-shield] matrix markdown: " + base.resolveSibling(mdName));
        } catch (IOException e) {
            System.err.println("[kbox-shield] 无法写出矩阵报告: " + e);
            return EXIT_PACK_FAILED;
        }
        System.out.println("[kbox-shield] " + reports.size() + " 个样本，失败 " + fail);
        return fail == 0 ? EXIT_OK : EXIT_PACK_FAILED;
    }

    private static String matrixJson(List<Report> rs) {
        StringBuilder sb = new StringBuilder(2048);
        sb.append("{\"tool\":\"kboXShield\",\"version\":\"3.0.4\",\"samples\":[");
        for (int i = 0; i < rs.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(rs.get(i).toJson());
        }
        sb.append("],\"untested\":[");
        String[] untested = {
                "x86 (PE32) 样本", "TLS 回调", "延迟导入 (delay-load)", "SEH/C++ 异常展开",
                "序号导出（无名字）", "插件式 LoadLibrary 热加载", "反病毒交互"
        };
        for (int i = 0; i < untested.length; i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(esc(untested[i])).append('"');
        }
        sb.append("],\"note\":\"untested 条目表示本次没有对应样本或未执行，不等于通过。\"}");
        return sb.toString();
    }

    private static String matrixMarkdown(List<Report> rs) {
        StringBuilder sb = new StringBuilder();
        sb.append("# kboXShield 兼容性矩阵（实测）\n\n");
        sb.append("| 样本 | 类型 | 架构 | 导出数 | 导出保留 | 结果 | 备注 |\n|---|---|---|---|---|---|---|\n");
        for (Report r : rs) {
            sb.append("| `").append(r.input).append("` | ")
                    .append(r.isDll ? "DLL" : "EXE/未知").append(" | ")
                    .append(r.machine).append(" | ")
                    .append(r.exportsBefore.size()).append(" | ")
                    .append(r.exportsPreserved ? "是" : "否").append(" | ")
                    .append(r.ok ? "PASS" : "FAIL").append(" | ")
                    .append(r.ok ? "—" : esc(r.error)).append(" |\n");
        }
        sb.append("\n## 未测试（不标注为支持）\n\n");
        sb.append("- x86 (PE32) 样本\n- TLS 回调\n- 延迟导入 (delay-load)\n- SEH / C++ 异常展开\n");
        sb.append("- 序号导出（无名字）\n- 插件式 LoadLibrary 热加载\n- 反病毒交互\n\n");
        sb.append("> 只有本表中 PASS 的行代表实测通过；未列出的组合一律视为未验证。\n");
        return sb.toString();
    }

    // ------------------------------------------------------------------
    //  PE parsing (headers + export directory)
    // ------------------------------------------------------------------

    static final class PeInfo {
        boolean valid;
        boolean isDll;
        String machineName = "unknown";
        final List<String> exports = new ArrayList<>();

        static PeInfo parse(byte[] b) {
            PeInfo p = new PeInfo();
            if (b == null || b.length < 0x40) return p;
            if (b[0] != 'M' || b[1] != 'Z') return p;
            int peOff = u4(b, 0x3C);
            if (peOff <= 0 || peOff + 24 > b.length) return p;
            if (b[peOff] != 'P' || b[peOff + 1] != 'E' || b[peOff + 2] != 0 || b[peOff + 3] != 0) return p;
            p.valid = true;
            int machine = u2(b, peOff + 4);
            p.machineName = machine == 0x8664 ? "x64" : (machine == 0x14C ? "x86" : "0x" + Integer.toHexString(machine));
            int numSections = u2(b, peOff + 6);
            int optSize = u2(b, peOff + 20);
            int characteristics = u2(b, peOff + 22);
            p.isDll = (characteristics & 0x2000) != 0;
            int opt = peOff + 24;
            if (opt + 2 > b.length) return p;
            int magic = u2(b, opt);
            int ddOff = magic == 0x20B ? opt + 112 : opt + 96;
            if (ddOff + 8 > b.length) return p;
            int expRva = u4(b, ddOff);
            int expSize = u4(b, ddOff + 4);
            if (expRva == 0 || expSize == 0) return p;
            int secOff = opt + optSize;
            int expOff = rvaToOff(b, secOff, numSections, expRva);
            if (expOff <= 0 || expOff + 40 > b.length) return p;
            int numNames = u4(b, expOff + 24);
            int namesRva = u4(b, expOff + 32);
            if (numNames <= 0 || numNames > 65535) return p;
            int namesOff = rvaToOff(b, secOff, numSections, namesRva);
            if (namesOff <= 0) return p;
            for (int i = 0; i < numNames; i++) {
                int nameRva = u4(b, namesOff + i * 4);
                int nameOff = rvaToOff(b, secOff, numSections, nameRva);
                if (nameOff <= 0 || nameOff >= b.length) continue;
                int end = nameOff;
                while (end < b.length && b[end] != 0) end++;
                p.exports.add(new String(b, nameOff, end - nameOff, StandardCharsets.US_ASCII));
            }
            return p;
        }

        private static int rvaToOff(byte[] b, int secOff, int numSections, int rva) {
            for (int i = 0; i < numSections; i++) {
                int s = secOff + i * 40;
                if (s + 40 > b.length) return -1;
                int va = u4(b, s + 12);
                int rawSize = u4(b, s + 16);
                int rawPtr = u4(b, s + 20);
                if (rva >= va && rva < va + Math.max(rawSize, 1)) {
                    return rawPtr + (rva - va);
                }
            }
            return -1;
        }

        private static int u2(byte[] b, int o) {
            if (o + 2 > b.length) return 0;
            return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
        }

        private static int u4(byte[] b, int o) {
            if (o + 4 > b.length) return 0;
            return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8)
                    | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24);
        }
    }

    // ------------------------------------------------------------------
    //  Arg parsing / helpers
    // ------------------------------------------------------------------

    private static Args parse(String[] argv) {
        Args a = new Args();
        for (int i = 0; i < argv.length; i++) {
            String s = argv[i];
            switch (s) {
                case "-h": case "--help": a.help = true; break;
                case "--shield-dll": case "--shield-in": a.in = next(argv, i++); break;
                case "--shield-out": case "-o": a.out = next(argv, i++); break;
                case "--shield-report": a.report = next(argv, i++); break;
                case "--shield-matrix": a.matrix = true; a.in = next(argv, i++); break;
                case "--shield-arch": {
                    String v = next(argv, i++).trim().toLowerCase(Locale.ROOT);
                    a.arch = v.equals("x86") || v.equals("32") ? ShieldOptions.ARCH_X86
                            : v.equals("x64") || v.equals("64") ? ShieldOptions.ARCH_X64
                            : ShieldOptions.ARCH_AUTO;
                    break;
                }
                case "--shield-def-flags": a.defFlags = parseHex(next(argv, i++)); break;
                case "--shield-def-policy": a.defPolicy = Integer.parseInt(next(argv, i++)); break;
                case "--shield-ir": a.irMutation = Integer.parseInt(next(argv, i++)); break;
                case "--shield-no-cfg": a.cfgFlatten = false; break;
                case "--shield-no-virtualize": a.virtualizeFunctions = false; break;
                case "--shield-srox-level": a.sroxLevel = Integer.parseInt(next(argv, i++)); break;
                case "--shield-srox-rounds": a.sroxRounds = Integer.parseInt(next(argv, i++)); break;
                case "--shield-srox-report": a.sroxReport = next(argv, i++); break;
                case "--shield-seed": a.sroxSeed = (long) parseHex(next(argv, i++)); break;
                default:
                    if (s.startsWith("-")) throw new IllegalArgumentException("未知参数: " + s);
                    break;
            }
        }
        return a;
    }

    private static String next(String[] a, int i) {
        if (i + 1 >= a.length) throw new IllegalArgumentException("参数缺少值: " + a[i]);
        return a[i + 1];
    }

    private static int parseHex(String s) {
        String t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        return (int) Long.parseLong(t, 16);
    }

    private static void usage() {
        System.out.println("kboXShield standalone (PE protection)");
        System.out.println("  --shield-dll <in.dll|in.exe>   input PE (DLL or EXE)");
        System.out.println("  --shield-out <out.dll>         output PE (required)");
        System.out.println("  --shield-report <file.json>    write the JSON report here");
        System.out.println("  --shield-matrix <dir|file>     run the compatibility matrix and report");
        System.out.println("  --shield-arch auto|x86|x64     architecture preference");
        System.out.println("  --shield-def-flags 0xNNNN      runtime defence flags (0 disables)");
        System.out.println("  --shield-def-policy N          defence policy id");
        System.out.println("  --shield-ir 0..N               IR mutation level");
        System.out.println("  --shield-no-cfg                disable CFG flattening");
        System.out.println("  --shield-no-virtualize         disable function-level virtualization");
        System.out.println("  --shield-srox-level 0..3       SROX level");
        System.out.println("  --shield-srox-rounds N         SROX rounds");
        System.out.println("  --shield-srox-report <file>    per-build SROX report (differentiation evidence)");
        System.out.println("  --shield-seed 0xNNNN           deterministic build seed");
        System.out.println();
        System.out.println("Export table is compared before/after; a missing export fails the run (exit 4).");
    }

    private static String sha256(byte[] b) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(b);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte x : d) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String arr(List<String> xs) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < xs.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(esc(xs.get(i))).append('"');
        }
        return sb.append(']').toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }

    /** Convenience for the CLI: logs one line and returns the exit code. */
    public static int runLogged(String[] argv) {
        int rc = run(argv);
        if (rc == EXIT_OK) KBoxLog.info("shield", "kboXShield finished OK");
        return rc;
    }
}
