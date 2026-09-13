package com.kbox.gui;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.awt.Desktop;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * KBox HTML UI（替换原 Swing 界面）。
 *
 * <p>启动一个内嵌 HTTP 服务（JDK 内置 {@link HttpServer}，零第三方依赖）并自动
 * 打开默认浏览器访问 <code>http://127.0.0.1:&lt;port&gt;/</code>。界面为单页
 * HTML（白绿/黑绿双主题 + 灵动动画 + 等待动画），通过 REST 接口驱动混淆：
 *
 * <ul>
 *   <li><code>GET  /</code>             → 返回 <code>web/index.html</code>（classpath 资源）</li>
 *   <li><code>GET  /api/state</code>    → 轮询当前状态 / 进度 / 增量日志</li>
 *   <li><code>POST /api/protect</code>  → 提交输入输出与选项，后台线程跑保护管线</li>
 *   <li><code>POST /api/browse</code>   → 弹出原生文件选择对话框（EDT）</li>
 * </ul>
 *
 * <p>兼容 CLI 的 <code>--gui</code> 反射入口 {@link #launch(String,String,String,boolean)}。
 */
public final class ProtectorGui {

    /** 页面资源，位于 kbox-gui/src/main/resources/web/index.html。 */
    private static final String PAGE = "/web/index.html";

    // ---- 运行状态（HTTP 线程 + 管线线程共享）----
    private volatile String status = "idle";          // idle | running | done | error
    private volatile int stage = 0;
    private volatile int total = 0;
    private volatile int percent = 0;
    private volatile String stageName = "";
    private volatile String summary = "";
    private volatile String error = "";

    /** 本轮日志：seq 单调递增，客户端用 since 拉增量。每轮开始时清空。 */
    private final ConcurrentLinkedQueue<LogEntry> ring = new ConcurrentLinkedQueue<>();
    private final AtomicLong seq = new AtomicLong();

    /** 当前运行批号：routeProtect 生成并下发给客户端，/api/state 回显，
     *  客户端用它丢弃过期响应（新 run 开始后旧响应直接忽略）。 */
    private volatile long curRunId = 0;

    private HttpServer server;
    private volatile boolean running;                 // 当前是否正在保护

    /** CLI 传入的预填路径（launch 时设置），routeRoot 注入到页面供自动适配。 */
    private volatile String prefillIn;
    private volatile String prefillOut;

    private static final class LogEntry {
        final long s;
        final String lvl;
        final String line;
        LogEntry(long s, String lvl, String line) { this.s = s; this.lvl = lvl; this.line = line; }
    }

    // ============================================================
    // 启动
    // ============================================================

    private ProtectorGui() throws IOException {
        KBoxLog.setListener(new KBoxLog.ProgressListener() {
            @Override public void onStage(int st, int tot, String name) {
                stage = st; total = tot; stageName = name; percent = 0;
            }
            @Override public void onProgress(int pct, String detail) { percent = pct; }
            @Override public void onComplete(String s) {
                status = "done"; summary = s; percent = 100;
            }
        });

        // 把每行日志同时送进 ring（带级别）与真实 stdout。
        KBoxLog.setOut(new PrintStream(new java.io.OutputStream() {
            private final StringBuilder buf = new StringBuilder();
            @Override public void write(int b) {
                buf.append((char) b);
                if (b == '\n') flush();
            }
            @Override public void flush() {
                String line = buf.toString();
                buf.setLength(0);
                System.out.print(line);
                if (!line.isEmpty()) {
                    ring.add(new LogEntry(seq.incrementAndGet(), levelOf(line), line));
                    // 只保留最近 4000 行，防止无限增长。
                    while (ring.size() > 4000) ring.poll();
                }
            }
        }));

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // FIXED core pool (not cached): a cached pool has corePoolSize 0, so when
        // the UI is idle (>60s with no request) every worker is reaped and the
        // JVM exits — the page then becomes unreachable ("浏览器打不开"). Keeping
        // two permanent non-daemon workers holds the process alive while idle.
        server.setExecutor(Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "kbox-http");
            t.setDaemon(false);                    // 非 daemon：保持 JVM 存活
            return t;
        }));
        registerRoutes();
        server.start();
    }

    /** 从 KBoxLog 行格式 "[HH:mm:ss.SSS] [INFO ] tag - msg" 中提取级别。 */
    private static String levelOf(String line) {
        int a = line.indexOf("] [");
        if (a >= 0) {
            int b = line.indexOf(']', a + 3);
            if (b > a + 3) return line.substring(a + 3, b).trim().toLowerCase();
        }
        return "info";
    }

    private void registerRoutes() {
        server.createContext("/", this::routeRoot);
        server.createContext("/api/state", this::routeState);
        server.createContext("/api/protect", this::routeProtect);
        server.createContext("/api/upload", this::routeUpload);
        server.createContext("/api/analyze", this::routeAnalyze);
        server.createContext("/favicon.ico", ex -> send(ex, 204, "no-cache", ""));
    }

    /** 页面 / 静态资源。 */
    private void routeRoot(HttpExchange ex) throws IOException {
        if (!"/".equals(ex.getRequestURI().getPath())) {
            send(ex, 404, "text/plain; charset=utf-8", "not found");
            return;
        }
        try (InputStream in = ProtectorGui.class.getResourceAsStream(PAGE)) {
            if (in == null) { send(ex, 500, "text/plain; charset=utf-8", "page resource missing"); return; }
            byte[] html = in.readAllBytes();
            ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            // Prefill from the CLI launch arguments (--gui -i/-o) so the page can
            // run its automatic "smart-adapt" analysis without manual entry.
            String pf = "<script>window._pf={i:" + (prefillIn == null ? "null" : esc(prefillIn))
                    + ",o:" + (prefillOut == null ? "null" : esc(prefillOut)) + "};</script>";
            byte[] body = pf.getBytes(StandardCharsets.UTF_8);
            byte[] out = new byte[html.length + body.length];
            System.arraycopy(body, 0, out, 0, body.length);
            System.arraycopy(html, 0, out, body.length, html.length);
            ex.sendResponseHeaders(200, out.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(out); }
        }
    }

    /** 状态轮询：runId 用于客户端丢弃过期响应；since 拉增量日志。 */
    private void routeState(HttpExchange ex) throws IOException {
        String q = ex.getRequestURI().getQuery() == null ? "" : ex.getRequestURI().getQuery();
        long since = paramLong(q, "since", 0);
        StringBuilder sb = new StringBuilder();
        sb.append("{\"runId\":").append(curRunId)
          .append(",\"status\":\"").append(status).append("\"")
          .append(",\"stage\":").append(stage)
          .append(",\"total\":").append(total)
          .append(",\"percent\":").append(percent)
          .append(",\"stageName\":").append(esc(stageName))
          .append(",\"summary\":").append(esc(summary))
          .append(",\"error\":").append(esc(error))
          .append(",\"running\":").append(running)
          .append(",\"entries\":[");
        boolean first = true;
        for (LogEntry e : ring) {
            if (e.s <= since) continue;
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"s\":").append(e.s)
              .append(",\"lvl\":").append(esc(e.lvl))
              .append(",\"l\":").append(esc(e.line)).append('}');
        }
        sb.append("]}");
        send(ex, 200, "application/json; charset=utf-8", sb.toString());
    }

    /** 启动保护：body 为 JSON 选项。 */
    private void routeProtect(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"POST required\"}");
            return;
        }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String in = jstr(body, "input");
        String out = jstr(body, "output");
        if (in.isEmpty() || out.isEmpty()) {
            send(ex, 400, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"输入与输出 jar 均为必填\"}");
            return;
        }
        if (running) {
            send(ex, 409, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"已有任务正在执行\"}");
            return;
        }
        running = true;
        status = "running"; stage = 0; total = 0; percent = 0;
        stageName = "启动"; summary = ""; error = "";
        curRunId = System.currentTimeMillis();       // 下发新批号，隔离新旧轮询
        ring.clear(); seq.set(0);

        String cfg = jstr(body, "config");
        String cc = jstr(body, "cc");
        Thread t = new Thread(() -> runPipeline(in, out, cfg, cc, body), "kbox-protect");
        t.setDaemon(false);
        t.start();
        send(ex, 202, "application/json; charset=utf-8",
                "{\"ok\":true,\"runId\":" + curRunId + "}");
    }

    /** 纯 HTML 文件选择：浏览器 multipart 上传到服务端临时目录，返回真实路径。
     *  不再调用 Java Swing JFileChooser（浏览器原生选择 + 丝滑动画）。 */
    private void routeUpload(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"POST required\"}");
            return;
        }
        String ctype = ex.getRequestHeaders().getFirst("Content-Type");
        if (ctype == null || !ctype.toLowerCase(java.util.Locale.ROOT).startsWith("multipart/form-data")) {
            send(ex, 400, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"multipart required\"}");
            return;
        }
        byte[] body = ex.getRequestBody().readAllBytes();
        String boundary = null;
        int bi = ctype.indexOf("boundary=");
        if (bi >= 0) {
            boundary = ctype.substring(bi + 9).trim();
            if (boundary.startsWith("\"")) {
                int e2 = boundary.indexOf('"', 1);
                if (e2 > 1) boundary = boundary.substring(1, e2);
            }
        }
        if (boundary == null || boundary.isEmpty() || body.length == 0) {
            send(ex, 400, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"bad multipart\"}");
            return;
        }
        byte[] delim = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        int p0 = indexOf(body, delim, 0);
        if (p0 < 0) { send(ex, 400, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"no part\"}"); return; }
        p0 += delim.length;
        if (p0 + 2 <= body.length && body[p0] == '-' && body[p0 + 1] == '-') {
            send(ex, 400, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"no file part\"}");
            return;
        }
        while (p0 + 2 <= body.length && (body[p0] == '\r' || body[p0] == '\n')) p0++;
        int hdrEnd = indexOf(body, "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), p0);
        if (hdrEnd < 0) { send(ex, 400, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"bad header\"}"); return; }
        String header = new String(body, p0, hdrEnd - p0, StandardCharsets.ISO_8859_1);
        String filename = "";
        int fn = header.indexOf("filename=\"");
        if (fn >= 0) {
            int f0 = fn + 10;
            int f1 = header.indexOf('"', f0);
            if (f1 > f0) filename = header.substring(f0, f1);
        }
        if (filename.isEmpty()) {
            send(ex, 400, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"no filename\"}");
            return;
        }
        int dataStart = hdrEnd + 4;
        int partEnd = indexOf(body, delim, dataStart);
        if (partEnd < 0) partEnd = body.length;
        int dataLen = partEnd - dataStart;
        if (dataLen >= 2 && body[dataStart + dataLen - 2] == '\r' && body[dataStart + dataLen - 1] == '\n') {
            dataLen -= 2;   // 去掉 part 尾部的 CRLF
        }
        if (dataLen <= 0) {
            send(ex, 400, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"empty file\"}");
            return;
        }
        filename = new java.io.File(filename).getName();   // 防目录穿越
        Path uploadDir = Paths.get("kbox-work", "uploads");
        try { java.nio.file.Files.createDirectories(uploadDir); } catch (Exception ignore) { }
        Path out = uploadDir.resolve(System.currentTimeMillis() + "-" + filename);
        byte[] chunk = new byte[dataLen];
        System.arraycopy(body, dataStart, chunk, 0, dataLen);
        java.nio.file.Files.write(out, chunk);
        send(ex, 200, "application/json; charset=utf-8",
                "{\"ok\":true,\"path\":" + esc(out.toAbsolutePath().toString())
                + ",\"name\":" + esc(filename) + ",\"size\":" + dataLen + "}");
    }

    /** 字节数组子串查找（零依赖）。 */
    private static int indexOf(byte[] hay, byte[] needle, int from) {
        outer:
        for (int i = Math.max(0, from); i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    /** 输入 jar 智能分析：识别项目类型并给出推荐选项（自适应配置）。 */
    private void routeAnalyze(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"POST required\"}");
            return;
        }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String in = jstr(body, "input");
        if (in.isEmpty() || !new java.io.File(in).isFile()) {
            send(ex, 200, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"输入 jar 不存在或不可读\"}");
            return;
        }
        send(ex, 200, "application/json; charset=utf-8", analyzeJar(in));
    }

    /** 扫描 jar 的布局特征，产出 JSON：{ok,label,note,checks[],sets{key:value}}。 */
    private static String analyzeJar(String input) {
        StringBuilder label = new StringBuilder("Java 应用");
        boolean hasMain = false;
        boolean springBoot = false;
        boolean fabric = false, forge = false, bukkit = false, mixin = false, tweak = false;
        boolean kotlin = false, spi = false;
        boolean library = false;
        int classCount = 0, resourceCount = 0;
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(input)) {
            String manifestMain = null;
            String tweakClass = null;
            java.util.Enumeration<? extends java.util.zip.ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                java.util.zip.ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String n = e.getName();
                if (n.endsWith(".class")) classCount++;
                else resourceCount++;
                if (n.equals("META-INF/MANIFEST.MF")) {
                    try {
                        java.io.InputStream is = zf.getInputStream(e);
                        byte[] mb = is.readAllBytes(); is.close();
                        String mf = new String(mb, StandardCharsets.UTF_8);
                        for (String line : mf.split("\r?\n")) {
                            if (line.startsWith("Main-Class:")) manifestMain = line.substring(11).trim();
                            else if (line.startsWith("TweakClass:")) tweakClass = line.substring(11).trim();
                        }
                    } catch (Throwable ignore) { }
                } else if (n.startsWith("BOOT-INF/classes/")) springBoot = true;
                else if (n.equals("fabric.mod.json")) fabric = true;
                else if (n.equals("META-INF/mods.toml") || n.equals("META-INF/neoforge.mods.toml")) forge = true;
                else if (n.equals("plugin.yml")) bukkit = true;
                else if (n.endsWith("mixins.json") || (n.startsWith("mixin") && n.endsWith(".json"))) mixin = true;
                else if (n.startsWith("kotlin/") || n.startsWith("kotlinx/")) kotlin = true;
                else if (n.startsWith("META-INF/services/")) spi = true;
            }
            hasMain = manifestMain != null && !manifestMain.isEmpty();
            if (tweakClass != null) tweak = true;
            if (fabric || forge || bukkit || tweak || mixin) library = false;
            else if (!hasMain && !springBoot) library = true;
        } catch (Throwable t) {
            return "{\"ok\":false,\"error\":" + esc("无法分析 jar: " + t) + "}";
        }

        // 建议集合：{checkbox/select key -> "1"/"0"/数值}
        java.util.LinkedHashMap<String, String> sets = new java.util.LinkedHashMap<>();
        // —— 全部项目共用的中等强度基线 ——
        sets.put("rename", "1"); sets.put("strings", "1"); sets.put("cf", "1");
        sets.put("cfStrength", "2"); sets.put("strStrength", "3");
        sets.put("kotlin", kotlin ? "1" : "0"); sets.put("silentShield", "1");
        sets.put("antiDebug", "1"); sets.put("vmpSelfCheck", "1"); sets.put("integrity", "1");
        sets.put("whiteboxStrings", "1"); sets.put("exJump", "1");
        sets.put("hideCallGraph", "1"); sets.put("fakeDebugInfo", "1");
        sets.put("methodInlineExtract", "1"); sets.put("eraseAnnotations", "1");
        sets.put("nativeShell", "2"); sets.put("antiDec", "2");
        sets.put("scatter", "0"); sets.put("typeConfusion", "0"); sets.put("mbaConstants", "0");
        sets.put("bfvm", "0"); sets.put("bfShield", "0"); sets.put("bfShieldLevel", "0");

        StringBuilder note = new StringBuilder();
        String[] kinds;
        if (springBoot) {
            label.setLength(0); label.append("Spring Boot 可执行包");
            hasMain = true;
            kinds = new String[] { "Spring Boot fat jar（BOOT-INF/classes）", "入口由 spring 启动器接管" };
            // BF 会把启动器吞进 blob 破坏 boot 链路：走类加密而非 BF。
            sets.put("bfLoader", "0"); sets.put("classEnc", "1"); sets.put("resources", "1");
            sets.put("vmp", "0"); sets.put("jnic", "0"); sets.put("autoAdaptMc", "0");
            sets.put("reflectionGate", "0");
            note.append("Spring 大量反射/代理，避免 VMP 化框架类；已关 VMP/JNIC/BF，开启类加密。");
        } else if (fabric || forge || bukkit || tweak || mixin) {
            String which = fabric ? "Fabric" : forge ? "Forge/NeoForge" : bukkit ? "Bukkit/Paper" : tweak ? "Forge TweakClass" : "含 Mixin";
            label.setLength(0); label.append("Minecraft ").append(which).append(" 模组");
            kinds = new String[] {
                (fabric ? "fabric.mod.json" : forge ? "META-INF/mods.toml" : bukkit ? "plugin.yml" : tweak ? "TweakClass" : "mixins.json"),
                hasMain ? "带主类" : "纯 mod（无主类）", mixin ? "含 Mixin" : null
            };
            sets.put("autoAdaptMc", "1");
            sets.put("bfLoader", "0"); sets.put("classEnc", "0"); sets.put("resources", "0");
            sets.put("vmp", "0"); sets.put("jnic", "0"); sets.put("reflectionGate", "0");
            note.append("已启用 autoAdaptMc（mod 加载器自动适配）；类加密/资源混淆/BF 关闭以避免 Mixin 与入口破坏。");
        } else if (library) {
            label.setLength(0); label.append("Java 库（无 Main-Class）");
            kinds = new String[] { "库类（被第三方引用）", spi ? "ServiceLoader SPI 提供方" : null };
            sets.put("bfLoader", "0"); sets.put("classEnc", "1"); sets.put("resources", "1");
            sets.put("vmp", "0"); sets.put("jnic", "0"); sets.put("autoAdaptMc", "0");
            note.append("无入口 → BF 混沌加载自动降级；改用类加密 + 资源混淆。库包注意 keep 公开 API。");
        } else {
            // 普通可执行应用
            label.setLength(0); label.append("可执行 Java 应用");
            kinds = new String[] { hasMain ? "带 Main-Class" : "入口类未知" };
            sets.put("bfLoader", "1"); sets.put("classEnc", "0"); sets.put("resources", "0");
            sets.put("vmp", "1"); sets.put("vmpNative", "1");
            sets.put("jnic", "1"); sets.put("jnicEpl", "1");
            sets.put("obfConstants", "1"); sets.put("reflectionGate", "1");
            sets.put("autoAdaptMc", "0");
            note.append("独立应用：BF 混沌加载 + VMP/JNIC 分层；性能敏感可关 JNIC。");
        }

        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"ok\":true,\"label\":").append(esc(label.toString()))
          .append(",\"classes\":").append(classCount)
          .append(",\"resources\":").append(resourceCount)
          .append(",\"checks\":[");
        boolean first = true;
        if (hasMain) { sb.append(esc("Main-Class 入口")); first = false; }
        if (springBoot) { if (!first) sb.append(','); sb.append(esc("Spring Boot")); first = false; }
        for (String k : kinds) {
            if (k == null) continue;
            if (!first) sb.append(',');
            sb.append(esc(k)); first = false;
        }
        if (kotlin) { if (!first) sb.append(','); sb.append(esc("Kotlin 类（元数据修复已开）")); first = false; }
        if (spi) { if (!first) sb.append(','); sb.append(esc("ServiceLoader SPI（已保留）")); first = false; }
        sb.append("],\"sets\":{");
        boolean fs = true;
        for (java.util.Map.Entry<String, String> e2 : sets.entrySet()) {
            if (!fs) sb.append(',');
            fs = false;
            sb.append(esc(e2.getKey())).append(':').append(esc(e2.getValue()));
        }
        sb.append("},\"note\":").append(esc(note.toString())).append('}');
        return sb.toString();
    }

    // ============================================================
    // 管线执行（后台线程）
    // ============================================================

    private void runPipeline(String in, String out, String cfg, String cc, String opts) {
        try {
            KBoxLog.setLevel(KBoxLog.LEVEL_DEBUG);
            ProtectionConfig p = ConfigLoader.load(cfg.isEmpty() ? null : Paths.get(cfg));
            applyOptions(p, opts);
            if (!cc.isEmpty()) p.setCc(cc);
            Path workDir = Paths.get(out).getParent() == null
                    ? Paths.get(".")
                    : Paths.get(out).getParent().resolve("kbox-work");
            new ProtectionPipeline(Paths.get(in), Paths.get(out), p, workDir).run();
            status = "done";
            summary = "输出：" + out;
        } catch (Throwable t) {
            error = t.toString();
            KBoxLog.error("gui", "Protection failed", t);
            status = "error";
        } finally {
            running = false;
        }
    }

    /** 与旧 Swing 版 doRun() 对齐的选项映射。 */
    private static void applyOptions(ProtectionConfig p, String o) {
        // ---- 一键全开（最大强度预设，可开关）----
        // 置于所有单键映射之前：UI 单键值作为覆盖仍会生效（与全开一致）。
        if (jbool(o, "allMax", false)) p.applyMaxStrength();
        p.setRenameIdentifiers(jbool(o, "rename", true));
        p.setEncryptStrings(jbool(o, "strings", true));
        p.setScatterStrings(jbool(o, "scatter", false));
        p.setObfuscateControlFlow(jbool(o, "cf", true));
        p.setEncryptClasses(jbool(o, "classEnc", false));
        p.setEnableVmp(jbool(o, "vmp", false));
        p.setEnableJnic(jbool(o, "jnic", false));
        p.setObfuscateResources(jbool(o, "resources", false));
        p.setFixKotlinMetadata(jbool(o, "kotlin", true));
        p.setAntiDebug(jbool(o, "antiDebug", false));
        p.setVmpSelfCheck(jbool(o, "vmpSelfCheck", false));
        p.setIntegrityCheck(jbool(o, "integrity", false));
        p.setExceptionJumpObf(jbool(o, "exJump", false));
        p.setNativeAntiHook(jbool(o, "nativeAntiHook", false));
        p.setControlFlowStrength(jint(o, "cfStrength", 2));
        p.setStringEncryptionStrength(jint(o, "strStrength", 3));
        p.setAntiDecompilerLevel(jint(o, "antiDec", 0));
        String wm = jstr(o, "watermark");
        if (!wm.isEmpty()) p.setWatermark(wm);
        String scope = jstr(o, "scope");
        try {
            if (!scope.isEmpty()) p.setObfuscationScope(ProtectionConfig.ObfuscationScope.valueOf(scope));
        } catch (Exception ignore) {}
        // ---- 高级选项（HTML UI 可覆盖 config 中对应键）----
        p.setBrainfuckLoader(jbool(o, "bfLoader", false));
        p.setBrainfuckShield(jbool(o, "bfShield", false));
        p.setBrainfuckShieldLevel(jint(o, "bfShieldLevel", 3));
        p.setEnableBfvm(jbool(o, "bfvm", false));
        p.setNativeShell(jint(o, "nativeShell", 3));
        p.setTypeConfusionStrength(jint(o, "typeConfusion", 0));
        p.setMbaConstants(jint(o, "mbaConstants", 0));
        p.setWhiteboxStrings(jbool(o, "whiteboxStrings", false));
        p.setObfuscateConstants(jbool(o, "obfConstants", false));
        p.setOpaqueStateMachine(jint(o, "opaqueStateMachine", 0));
        p.setHoneypotLevel(jint(o, "honeypot", 0));
        p.setMethodSplit(jint(o, "methodSplit", 0));
        p.setSilentShield(jbool(o, "silentShield", true));
        // ---- 全开缺失项补齐（allMax 打开时同样生效） ----
        p.setEnableVmpNative(jbool(o, "vmpNative", false));
        p.setAutoAdaptMinecraft(jbool(o, "autoAdaptMc", false));
        p.setReflectionGate(jbool(o, "reflectionGate", false));
        p.setJnicEplDriven(jbool(o, "jnicEpl", false));
        // ---- VMP/JNIC 排除类（自定义前缀列表，逗号/分号/换行分隔）----
        String vmpExc = jstr(o, "vmpExclude");
        if (!vmpExc.isEmpty()) addExclusionPrefixes(p.getVmpExcludePrefixes(), vmpExc);
        String jnicExc = jstr(o, "jnicExclude");
        if (!jnicExc.isEmpty()) addExclusionPrefixes(p.getJnicExcludePrefixes(), jnicExc);
        p.setHideCallGraph(jbool(o, "hideCallGraph", false));
        p.setFakeDebugInfo(jbool(o, "fakeDebugInfo", false));
        p.setMethodInlineExtract(jbool(o, "methodInlineExtract", false));
        p.setEraseAnnotations(jbool(o, "eraseAnnotations", false));
        p.setNullGuard(jbool(o, "nullGuard", false));
        p.setScatterStrings(jbool(o, "scatter", false));
        p.setVmpProtectRuntime(jbool(o, "vmpProtectRuntime", false));
        p.setSentinelInterleave(jint(o, "sentinelInterleave", 0));
        p.setBlobMockFill(jint(o, "blobMockFill", 0));
        p.setStackFrameRedirect(jint(o, "stackFrameRedirect", 0));
        p.setEntropyTimeAnchor(jint(o, "entropyTimeAnchor", 0));
        p.setSelfWipeSections(jint(o, "selfWipeSections", 0));
        p.setProcessHeartbeat(jint(o, "processHeartbeat", 0));
        p.setHoneypotPe(jint(o, "honeypotPe", 0));
        p.setOneTimeSemantic(jint(o, "oneTimeSemantic", 0));
        p.setLineageChain(jint(o, "lineageChain", 0));
        p.setSelfRefAuth(jint(o, "selfRefAuth", 0));
        p.setMultiRep(jint(o, "multiRep", 0));
        p.setPolyGold(jint(o, "polyGold", 0));
        p.setSignalPoison(jint(o, "signalPoison", 0));
        p.setBuildSigBind(jint(o, "buildSigBind", 0));
    }

    // ============================================================
    // 极简 JSON（避免第三方依赖）
    // ============================================================

    private static String jstr(String json, String key) {
        int i = json.indexOf('"' + key + '"');
        if (i < 0) return "";
        int c = json.indexOf(':', i + key.length() + 2);
        if (c < 0) return "";
        c++;
        while (c < json.length() && Character.isWhitespace(json.charAt(c))) c++;
        if (c < json.length() && json.charAt(c) == '"') return readString(json, c);
        return "";
    }

    private static String readString(String json, int openQuote) {
        StringBuilder sb = new StringBuilder();
        int i = openQuote + 1;
        while (i < json.length()) {
            char ch = json.charAt(i);
            if (ch == '\\' && i + 1 < json.length()) {
                char n = json.charAt(i + 1);
                switch (n) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 5 < json.length()) {
                            try { sb.append((char) Integer.parseInt(json.substring(i + 2, i + 6), 16)); }
                            catch (NumberFormatException ignore) {}
                            i += 4;
                        }
                        break;
                    default: sb.append(n);
                }
                i += 2;
            } else if (ch == '"') {
                return sb.toString();
            } else {
                sb.append(ch);
                i++;
            }
        }
        return sb.toString();
    }

    private static boolean jbool(String json, String key, boolean dflt) {
        int i = json.indexOf('"' + key + '"');
        if (i < 0) return dflt;
        int c = json.indexOf(':', i + key.length() + 2);
        if (c < 0) return dflt;
        String rest = json.substring(c + 1).trim();
        return rest.startsWith("true");
    }

    private static int jint(String json, String key, int dflt) {
        int i = json.indexOf('"' + key + '"');
        if (i < 0) return dflt;
        int c = json.indexOf(':', i + key.length() + 2);
        if (c < 0) return dflt;
        StringBuilder n = new StringBuilder();
        for (int k = c + 1; k < json.length(); k++) {
            char ch = json.charAt(k);
            if (Character.isDigit(ch) || ch == '-') n.append(ch);
            else if (!Character.isWhitespace(ch)) break;
        }
        try { return Integer.parseInt(n.toString()); } catch (Exception e) { return dflt; }
    }

    /** 解析 UI 排除类列表（逗号/分号/换行分隔），归一化点分格式后写入前缀集合。 */
    private static void addExclusionPrefixes(java.util.Set<String> target, String raw) {
        for (String tok : raw.split("[,;\n\r]+")) {
            String t = tok.trim();
            if (t.isEmpty()) continue;
            // 兼容点分（com.example.Foo）与斜杠（com/example/Foo）两种写法
            String dotted = t.replace('/', '.').replace('\\', '.');
            if (dotted.endsWith(".*")) dotted = dotted.substring(0, dotted.length() - 2);
            if (dotted.endsWith(".")) dotted = dotted.substring(0, dotted.length() - 1);
            if (!dotted.isEmpty()) target.add(dotted);
        }
    }

    private static long paramLong(String query, String key, long dflt) {
        for (String kv : query.split("&")) {
            int e = kv.indexOf('=');
            if (e > 0 && kv.substring(0, e).equals(key)) {
                try { return Long.parseLong(kv.substring(e + 1)); } catch (Exception ignore) {}
            }
        }
        return dflt;
    }

    /** 生成 JSON 字符串字面量（含转义）。 */
    private static String esc(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.append('"').toString();
    }

    private static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length == 0 ? -1 : b.length);
        if (b.length > 0) {
            try (OutputStream os = ex.getResponseBody()) { os.write(b); }
        }
        ex.close();
    }

    // ============================================================
    // 入口（兼容 CLI --gui 反射调用）
    // ============================================================

    /** CLI {@code --gui} 入口：启动服务并打开浏览器。 */
    public static void launch(String in, String out, String cfg, boolean verbose) {
        if (verbose) KBoxLog.setLevel(KBoxLog.LEVEL_DEBUG);
        try {
            ProtectorGui g = new ProtectorGui();
            g.prefillIn = in;
            g.prefillOut = out;
            int port = g.server.getAddress().getPort();
            System.out.println("[KBox-GUI] HTML UI: http://127.0.0.1:" + port + "/");
            openBrowser("http://127.0.0.1:" + port + "/");
            if (in != null && out != null) {
                KBoxLog.info("gui", "已预填输入/输出，页面将自动完成配置适配。");
            }
        } catch (Exception e) {
            System.err.println("[KBox-GUI] failed to start: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("HTML UI failed to start", e);
        }
    }

    private static void openBrowser(String url) {
        // 1) 标准 AWT Desktop。
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
        } catch (Throwable ignore) {
            // fall through to OS-level launchers
        }
        // 2) OS 级启动器（Desktop 在无 JNI 桌面/受限会话下常失败）。
        try {
            String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
            if (os.contains("win")) {
                // rundll32 打开默认浏览器；cmd start 作为二次兜底。
                try {
                    new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url).start();
                    return;
                } catch (Throwable ignore) { }
                new ProcessBuilder("cmd", "/c", "start", "", "\"" + url + "\"").start();
                return;
            }
            if (os.contains("mac")) {
                new ProcessBuilder("open", url).start();
                return;
            }
            new ProcessBuilder("xdg-open", url).start();
            return;
        } catch (Throwable ignore) {
            // fall through to the manual-URL hint below
        }
        // 3) 兜底：打印 URL，让用户手动打开（服务在 127.0.0.1 上持续可用）。
        System.out.println("[KBox-GUI] 无法自动打开浏览器，请手动访问: " + url);
    }

    public static void main(String[] args) {
        launch(null, null, null, false);
    }
}
