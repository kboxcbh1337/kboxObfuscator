package com.kbox.gui;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import java.awt.Desktop;
import java.awt.HeadlessException;
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
        server.setExecutor(Executors.newCachedThreadPool(r -> {
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
        server.createContext("/api/browse", this::routeBrowse);
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
            ex.sendResponseHeaders(200, html.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(html); }
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

    /** 原生文件选择对话框（EDT）。 */
    private void routeBrowse(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8", "{\"path\":null}");
            return;
        }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String mode = jstr(body, "mode");
        String current = jstr(body, "current");
        final String[] picked = {null};
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    JFileChooser fc = new JFileChooser();
                    if (!current.isEmpty()) {
                        try { fc.setSelectedFile(Paths.get(current).toFile()); } catch (Exception ignore) {}
                    }
                    int r = "open".equals(mode) ? fc.showOpenDialog(null) : fc.showSaveDialog(null);
                    if (r == JFileChooser.APPROVE_OPTION && fc.getSelectedFile() != null) {
                        picked[0] = fc.getSelectedFile().getAbsolutePath();
                    }
                } catch (HeadlessException he) {
                    KBoxLog.warn("gui", "browse: headless environment");
                }
            });
        } catch (Exception e) {
            KBoxLog.warn("gui", "browse dialog failed: " + e.getMessage());
        }
        send(ex, 200, "application/json; charset=utf-8",
                "{\"path\":" + (picked[0] == null ? "null" : esc(picked[0])) + "}");
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
            int port = g.server.getAddress().getPort();
            System.out.println("[KBox-GUI] HTML UI: http://127.0.0.1:" + port + "/");
            openBrowser("http://127.0.0.1:" + port + "/");
            if (in != null && out != null) {
                KBoxLog.info("gui", "已预填输入/输出，请在页面点击「开始混淆」。");
            }
        } catch (Exception e) {
            System.err.println("[KBox-GUI] failed to start: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("HTML UI failed to start", e);
        }
    }

    private static void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
        } catch (Exception ignore) {}
        // 兜底：打印 URL，让用户手动打开。
        System.out.println("[KBox-GUI] 请手动打开浏览器访问: " + url);
    }

    public static void main(String[] args) {
        launch(null, null, null, false);
    }
}
