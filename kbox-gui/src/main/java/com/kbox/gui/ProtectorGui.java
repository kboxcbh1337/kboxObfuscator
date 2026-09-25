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

    // ---- 远程监控（手机 APK / 局域网 / 公网穿透）----
    /** 监听地址：默认 0.0.0.0（局域网/公网可达）；127.0.0.1 则仅本机。 */
    private final String bindHost;
    /** 绑定的端口（0 = 系统随机分配）。 */
    private final int bindPort;
    /** 外部可达地址（公网/穿透域名，可选）：非空时用于二维码与配对 URL。 */
    private final String serveAddr;
    /** 配对令牌：控制类 POST 需携带，防局域网被陌生设备劫持提交任务。 */
    private final String pairToken;

    /** SSE 订阅者集合：集合须满足 {@code write(byte[],int,int).flush()} 可重入。 */
    private final java.util.List<HttpExchange> sseClients =
            java.util.Collections.synchronizedList(new java.util.ArrayList<>());

    /** 实时推送序号：每次状态/日志变化递增，客户端据此判重。 */
    private final java.util.concurrent.atomic.AtomicLong sseSeq = new java.util.concurrent.atomic.AtomicLong();

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
        this(detect().host, detect().port, detect().serveAddr);
    }

    /** 从系统属性/环境变量读取监听配置（{@code kbox.gui.host/port/serveAddr}）。 */
    private static Proto detect() {
        return new Proto();
    }

    private static final class Proto {
        final String host;
        final int port;
        final String serveAddr;
        Proto() {
            String h = System.getProperty("kbox.gui.host",
                    System.getenv("KBOX_GUI_HOST") == null ? null : System.getenv("KBOX_GUI_HOST"));
            if (h == null || h.trim().isEmpty()) h = "0.0.0.0";
            this.host = h.trim();
            int p = 0;
            String ps = System.getProperty("kbox.gui.port",
                    System.getenv("KBOX_GUI_PORT") == null ? null : System.getenv("KBOX_GUI_PORT"));
            if (ps != null) { try { p = Integer.parseInt(ps.trim()); } catch (Exception ignore) {} }
            this.port = p;
            String sa = System.getProperty("kbox.gui.serveAddr",
                    System.getenv("KBOX_GUI_SERVE_ADDR") == null ? null : System.getenv("KBOX_GUI_SERVE_ADDR"));
            this.serveAddr = (sa == null || sa.trim().isEmpty()) ? null : sa.trim();
        }
    }

    /** 主构造：可指定监听 host/port 与外部可达地址。 */
    ProtectorGui(String host, int port, String serveAddr) throws IOException {
        this.bindHost = (host == null || host.trim().isEmpty()) ? "0.0.0.0" : host.trim();
        this.bindPort = port;
        this.serveAddr = (serveAddr == null || serveAddr.trim().isEmpty()) ? null : serveAddr.trim();
        this.pairToken = randomToken();

        KBoxLog.setListener(new KBoxLog.ProgressListener() {
            @Override public void onStage(int st, int tot, String name) {
                stage = st; total = tot; stageName = name; percent = 0;
                pushStateEvent();
            }
            @Override public void onProgress(int pct, String detail) { percent = pct; pushStateEvent(); }
            @Override public void onComplete(String s) {
                status = "done"; summary = s; percent = 100; pushStateEvent();
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
                    long s = seq.incrementAndGet();
                    String lvl = levelOf(line);
                    ring.add(new LogEntry(s, lvl, line));
                    // 只保留最近 4000 行，防止无限增长。
                    while (ring.size() > 4000) ring.poll();
                    pushLogEvent(s, lvl, line);
                }
            }
        }));

        server = HttpServer.create(new InetSocketAddress(bindHost, bindPort), 0);
        // FIXED core pool (not cached): a cached pool has corePoolSize 0, so when
        // the UI is idle (>60s with no request) every worker is reaped and the
        // JVM exits — the page then becomes unreachable ("浏览器打不开"). Keeping
        // permanent non-daemon workers holds the process alive while idle.
        // 线程数容纳 SSE 长连接 + REST 轮询（SSE 会长期占用一个 worker）。
        server.setExecutor(Executors.newFixedThreadPool(16, r -> {
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
        server.createContext("/api/pair", this::routePair);
        server.createContext("/api/stream", this::routeStream);
        server.createContext("/api/protect", this::routeProtect);
        server.createContext("/api/upload", this::routeUpload);
        server.createContext("/api/analyze", this::routeAnalyze);
        // kboXShield 独立功能线（Windows PE 加壳）：分析与打包
        server.createContext("/api/shield/analyze", this::routeShieldAnalyze);
        server.createContext("/api/shield", this::routeShield);
        server.createContext("/favicon.ico", ex -> send(ex, 204, "no-cache", ""));
    }

    // ============================================================
    // 远程监控（配对 + SSE 实时推送）
    // ============================================================

    /** 配对信息：手机 APK / 浏览器据此构造连接串（含令牌）。GET 免令牌（只读信息）。 */
    private void routePair(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"GET required\"}");
            return;
        }
        int port = server.getAddress().getPort();
        String lan = lanIp();
        String host = serveAddr != null ? serveAddr : (lan != null ? lan : "127.0.0.1");
        String url = "http://" + host + ":" + port + "/?token=" + pairToken;
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true")
          .append(",\"bindHost\":").append(esc(bindHost))
          .append(",\"port\":").append(port)
          .append(",\"lanIp\":").append(lan == null ? "null" : esc(lan))
          .append(",\"serveAddr\":").append(serveAddr == null ? "null" : esc(serveAddr))
          .append(",\"displayHost\":").append(esc(host))
          .append(",\"token\":").append(esc(pairToken))
          .append(",\"url\":").append(esc(url)).append('}');
        send(ex, 200, "application/json; charset=utf-8", sb.toString());
    }

    /** SSE 实时推送：{@code evt: state/log} 事件，断线即移除订阅。 */
    private void routeStream(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "text/plain; charset=utf-8", "GET required");
            return;
        }
        ex.getResponseHeaders().set("Content-Type", "text/event-stream; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-cache");
        ex.getResponseHeaders().set("Connection", "keep-alive");
        ex.sendResponseHeaders(200, 0);
        sseClients.add(ex);
        try {
            // 基线：先推当前全量状态，避免客户端等待下一次事件。
            sendToClient(ex, frame("state", stateJson()));
            while (true) {
                Thread.sleep(1000);
                // 心跳注释（SSE 忽略行首冒号）：同时用于探测客户端断线。
                sendToClient(ex, ": hb\n\n");
            }
        } catch (InterruptedException | IOException ignored) {
        } finally {
            sseClients.remove(ex);
        }
    }

    /** 向单个 SSE 客户端写帧（同步，避免与广播互踩）。 */
    private static void sendToClient(HttpExchange ex, String frame) throws IOException {
        java.io.OutputStream os = ex.getResponseBody();
        byte[] b = frame.getBytes(StandardCharsets.UTF_8);
        synchronized (ex) {
            os.write(b);
            os.flush();
        }
    }

    /** 推送全量状态事件（stage/total/percent/stageName/summary/error/status）。 */
    private void pushStateEvent() {
        sseSeq.incrementAndGet();
        broadcast("state", stateJson());
    }

    /** 推送单条日志事件。 */
    private void pushLogEvent(long s, String lvl, String line) {
        sseSeq.incrementAndGet();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"s\":").append(s)
          .append(",\"lvl\":").append(esc(lvl))
          .append(",\"l\":").append(esc(line)).append('}');
        broadcast("log", sb.toString());
    }

    /** 当前全量状态 JSON（与 /api/state 的语义字段一致）。 */
    private String stateJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"runId\":").append(curRunId)
          .append(",\"status\":").append(esc(status))
          .append(",\"stage\":").append(stage)
          .append(",\"total\":").append(total)
          .append(",\"percent\":").append(percent)
          .append(",\"stageName\":").append(esc(stageName))
          .append(",\"summary\":").append(esc(summary))
          .append(",\"error\":").append(esc(error))
          .append(",\"running\":").append(running)
          .append('}');
        return sb.toString();
    }

    /** 给所有 SSE 订阅者广播一条命名事件。单个客户端写失败即摘除。 */
    private void broadcast(String evt, String data) {
        java.util.List<HttpExchange> dead = null;
        for (HttpExchange ex : sseClients) {
            try {
                sendToClient(ex, frame(evt, data));
            } catch (Throwable t) {
                if (dead == null) dead = new java.util.ArrayList<>();
                dead.add(ex);
            }
        }
        if (dead != null) for (HttpExchange d : dead) sseClients.remove(d);
    }

    private static String frame(String evt, String data) {
        return "event: " + evt + "\ndata: " + data + "\n\n";
    }

    /** 取本机局域网 IPv4（用于配对 URL）；无则返回 null。 */
    private static String lanIp() {
        try {
            java.util.Enumeration<java.net.NetworkInterface> nis =
                    java.net.NetworkInterface.getNetworkInterfaces();
            while (nis.hasMoreElements()) {
                java.net.NetworkInterface ni = nis.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                java.util.Enumeration<java.net.InetAddress> ads = ni.getInetAddresses();
                while (ads.hasMoreElements()) {
                    java.net.InetAddress a = ads.nextElement();
                    if (a.isLoopbackAddress()) continue;
                    byte[] b = a.getAddress();
                    if (b.length == 4 && !a.isAnyLocalAddress() && !a.isMulticastAddress()
                            && !(b[0] == (byte) 169 && b[1] == (byte) 254)) {
                        return a.getHostAddress();
                    }
                }
            }
        } catch (Throwable ignore) {}
        return null;
    }

    /** 生成长度 16 的十六进制配对令牌。 */
    private static String randomToken() {
        java.util.concurrent.ThreadLocalRandom r = java.util.concurrent.ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 16; i++) sb.append("0123456789abcdef".charAt(r.nextInt(16)));
        return sb.toString();
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
            // 远程监控配对：注入连接串 + 令牌，前端据此生成二维码并接入 SSE。
            String pair = qrPairJson();
            String pp = "<script>window._pair=" + pair + ";function _kboxPair(){return window._pair;}</script>";
            byte[] body = (pf + pp).getBytes(StandardCharsets.UTF_8);
            byte[] out = new byte[html.length + body.length];
            System.arraycopy(body, 0, out, 0, body.length);
            System.arraycopy(html, 0, out, body.length, html.length);
            ex.sendResponseHeaders(200, out.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(out); }
        }
    }

    /** 构造前端配对 JSON（含 LAN/公网地址、端口、令牌与完整 URL）。 */
    private String qrPairJson() {
        int port = server.getAddress().getPort();
        String lan = lanIp();
        String host = serveAddr != null ? serveAddr : (lan != null ? lan : "127.0.0.1");
        String url = "http://" + host + ":" + port + "/?token=" + pairToken;
        return "{\"port\":" + port
                + ",\"lanIp\":" + (lan == null ? "null" : esc(lan))
                + ",\"displayHost\":" + esc(host)
                + ",\"token\":" + esc(pairToken)
                + ",\"url\":" + esc(url) + "}";
    }

    /** 令牌校验：本机回环请求放行（本地页面 UI 正常工作）；远端请求须携带令牌。 */
    private boolean authed(HttpExchange ex) {
        String q = ex.getRequestURI().getRawQuery();
        if (q != null && q.contains("token=" + pairToken)) return true;
        java.net.InetAddress ra = ex.getRemoteAddress().getAddress();
        if (ra != null && ra.isLoopbackAddress()) return true;
        return false;
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
        if (!authed(ex)) {
            send(ex, 403, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"forbidden: missing/incorrect token\"}");
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
        if (!authed(ex)) {
            send(ex, 403, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"forbidden: missing/incorrect token\"}");
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
        if (!authed(ex)) {
            send(ex, 403, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"forbidden: missing/incorrect token\"}");
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

    /** kboXShield PE 加壳：把 PE 解析结果适配成推荐选项（智能适配）。 */
    private void routeShieldAnalyze(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"POST required\"}");
            return;
        }
        if (!authed(ex)) {
            send(ex, 403, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"forbidden: missing/incorrect token\"}");
            return;
        }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String in = jstr(body, "input");
        if (in.isEmpty() || !new java.io.File(in).isFile()) {
            send(ex, 200, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"输入 PE 不存在或不可读\"}");
            return;
        }
        send(ex, 200, "application/json; charset=utf-8", analyzePe(in));
    }

    /** kboXShield PE 加壳：执行打包并回带结构自检结果。 */
    private void routeShield(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"POST required\"}");
            return;
        }
        if (!authed(ex)) {
            send(ex, 403, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"forbidden: missing/incorrect token\"}");
            return;
        }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String in = jstr(body, "input");
        String out = jstr(body, "output");
        if (in.isEmpty() || !new java.io.File(in).isFile()) {
            send(ex, 200, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"输入 PE 不存在或不可读\"}");
            return;
        }
        if (out.isEmpty()) {
            out = defaultShieldOut(in);
        }

        com.kbox.core.shield.ShieldOptions o = new com.kbox.core.shield.ShieldOptions();
        o.arch = jint(body, "arch", com.kbox.core.shield.ShieldOptions.ARCH_AUTO);
        o.defFlags = jint(body, "defFlags", 0x0003FFFF);
        o.defPolicy = jint(body, "defPolicy", 7);
        o.defDelayLoops = jint(body, "defDelayLoops", 20000000);
        o.defTimingTicks = jint(body, "defTimingTicks", 100000);
        boolean v = jbool(body, "virtualize", true);
        o.virtualizeMarkedSections = v;
        o.virtualizeFunctions = v;

        StringBuilder log = new StringBuilder();
        boolean ok = false;
        try {
            ok = com.kbox.core.shield.ShieldPacker.pack(in, out, o, log);
        } catch (Throwable t) {
            log.append("打包异常: ").append(t).append('\n');
        }

        StringBuilder sb = new StringBuilder(2048);
        sb.append("{\"ok\":").append(ok)
          .append(",\"output\":").append(esc(out))
          .append(",\"log\":").append(esc(log.toString()));
        if (ok && new java.io.File(out).isFile()) {
            try {
                com.kbox.core.shield.ShieldVerify.Report rep =
                        com.kbox.core.shield.ShieldVerify.verify(out, o);
                sb.append(",\"verify\":{\"ok\":").append(rep.ok)
                  .append(",\"okCount\":").append(rep.count("ok"))
                  .append(",\"warnCount\":").append(rep.count("warn"))
                  .append(",\"failCount\":").append(rep.count("fail"))
                  .append(",\"findings\":[");
                boolean first = true;
                for (com.kbox.core.shield.ShieldVerify.Finding fd : rep.findings) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append("{\"level\":").append(esc(fd.level))
                      .append(",\"msg\":").append(esc(fd.msg)).append('}');
                }
                sb.append("]}");
            } catch (Throwable t) {
                sb.append(",\"verify\":null");
            }
        } else {
            sb.append(",\"verify\":null");
        }
        sb.append('}');
        send(ex, 200, "application/json; charset=utf-8", sb.toString());
    }

    private static String defaultShieldOut(String in) {
        java.io.File f = new java.io.File(in);
        String n = f.getName();
        int dot = n.lastIndexOf('.');
        String base = dot > 0 ? n.substring(0, dot) : n;
        java.io.File parent = f.getParentFile();
        String dir = parent == null ? "." : parent.getPath();
        return new java.io.File(dir, base + "-protected.exe").getPath();
    }

    /** PE 特征扫描 → {ok,label,note,checks[],sets{}}（供加壳面板的智能适配使用）。 */
    private static String analyzePe(String input) {
        byte[] d;
        try {
            d = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(input));
        } catch (Throwable t) {
            return "{\"ok\":false,\"error\":" + esc("无法读取 PE: " + t) + "}";
        }
        com.kbox.core.shield.PeImage img = new com.kbox.core.shield.PeImage();
        StringBuilder err = new StringBuilder();
        if (!img.parse(d, d.length, err)) {
            return "{\"ok\":false,\"error\":" + esc("不是可解析的 PE：" + err) + "}";
        }
        boolean is64 = img.is64Bit();
        boolean isDll = img.isDll();
        boolean tls = img.tlsPresent();
        boolean res = img.hasDirectory(com.kbox.core.shield.PeImage.DIR_RESOURCE);
        boolean reloc = img.hasDirectory(com.kbox.core.shield.PeImage.DIR_BASERELOC);
        int resSize = img.directorySize(com.kbox.core.shield.PeImage.DIR_RESOURCE);
        int textvm = 0;
        long textvmBytes = 0;
        for (com.kbox.core.shield.PeImage.SectionInfo s : img.sections()) {
            String nm = s.name == null ? "" : s.name;
            if (nm.startsWith(".textvm")) {
                textvm++;
                textvmBytes += Math.max(s.virtualSize, s.rawSize);
            }
        }
        // x86 stub 未导出独立 dispatch 桩，无法承载虚拟化 trampoline
        boolean vmSupported = is64;

        // ---- 推荐选项 ----
        java.util.LinkedHashMap<String, String> sets = new java.util.LinkedHashMap<>();
        sets.put("arch", String.valueOf(com.kbox.core.shield.ShieldOptions.ARCH_AUTO));
        sets.put("defFlags", "262143");          // 0x0003FFFF：18 项检测全开
        // DLL 由宿主进程加载，误判即终止代价高 → 推荐「延迟 + 诱饵」但不终止（policy=3）
        sets.put("defPolicy", isDll ? "3" : "7");
        sets.put("defDelayLoops", "20000000");
        sets.put("defTimingTicks", isDll ? "250000" : "100000");
        sets.put("virtualize", (vmSupported && textvm > 0) ? "1" : "0");

        String label = "Windows " + (is64 ? "PE32+（x86-64）" : "PE32（x86）")
                + (isDll ? " 动态库（DLL）" : " 可执行程序");
        StringBuilder note = new StringBuilder();
        note.append("架构 ").append(is64 ? "x64" : "x86").append("，")
            .append(img.numberOfSections()).append(" 节，入口 0x")
            .append(Integer.toHexString(img.entryRva())).append("；")
            .append(img.sections().size()).append(" 节表已解析。");
        if (!vmSupported) {
            note.append("x86 stub 未导出虚拟化分派桩，本轮不做方法体虚拟化（仅加壳）。");
        } else if (textvm == 0) {
            note.append("未发现 .textvm* 标记节 → 不做虚拟化；如需虚拟化请把目标代码放入名为 .textvm* 的节。");
        } else {
            note.append("发现 ").append(textvm).append(" 个标记节（合计 ")
                .append(textvmBytes).append(" 字节）→ 建议开启虚拟化。");
        }
        if (isDll) {
            note.append(" DLL 场景已把响应策略降为「延迟 + 诱饵」（不终止宿主进程），并放宽时序阈值。");
        }
        if (!res) {
            note.append(" 警告：未检测到资源目录，加壳后应用清单/图标在运行期不可用。");
        }
        if (!reloc) {
            note.append(" 无重定位目录：stub 会跳过重定位修复。");
        }

        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"ok\":true,\"label\":").append(esc(label))
          .append(",\"classes\":").append(img.numberOfSections())
          .append(",\"resources\":").append(resSize)
          .append(",\"checks\":[");
        boolean first = true;
        String[] checks = {
                is64 ? "PE32+ / x86-64" : "PE32 / x86",
                isDll ? "DLL 映像" : "EXE 映像",
                tls ? "含 TLS 回调（加壳后代跑）" : null,
                res ? "资源目录（明文保留）" : "无资源目录",
                reloc ? "含重定位目录（清零后由 stub 修复）" : "无重定位目录",
                textvm > 0 ? (textvm + " 个 .textvm 标记节") : null
        };
        for (String c : checks) {
            if (c == null) {
                continue;
            }
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append(esc(c));
        }
        sb.append("],\"sets\":{");
        boolean fs = true;
        for (java.util.Map.Entry<String, String> e2 : sets.entrySet()) {
            if (!fs) {
                sb.append(',');
            }
            fs = false;
            sb.append(esc(e2.getKey())).append(':').append(esc(e2.getValue()));
        }
        sb.append("},\"note\":").append(esc(note.toString())).append('}');
        return sb.toString();
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
        sets.put("nullGuard", "1"); sets.put("vmpProtectRuntime", "1");
        sets.put("antiDec", "2");
        // —— nativeShell 增强壳：智能适配也在其覆盖范围内 ——
        // M1 字符串擦除 / M2 控制流变异 / M3 IAT·导入隐藏 均为「源码级」改写，
        // 作用于所有生成的原生源码（JNIC 分片、VMP native、native crypto、
        // BF native decoder）。若该类型不产出原生码，则为 no-op（安全上限），
        // 故统一推荐最强 3；若产出原生码但未配置编译器，则降为 0 以免构建失败。
        boolean producesNative = false;   // 由下面的类型分支决定
        // —— 除 BF 家族以外的数字选项：推荐全部拉满（最强档）——
        sets.put("typeConfusion", "2");            // 0..2
        sets.put("mbaConstants", "2");             // 0..2
        sets.put("opaqueStateMachine", "3");
        sets.put("honeypot", "3");
        sets.put("methodSplit", "3");
        sets.put("sentinelInterleave", "3");
        sets.put("blobMockFill", "3");
        sets.put("stackFrameRedirect", "3");
        sets.put("entropyTimeAnchor", "3");
        sets.put("selfWipeSections", "3");
        sets.put("processHeartbeat", "3");
        sets.put("honeypotPe", "3");
        sets.put("oneTimeSemantic", "3");
        sets.put("lineageChain", "3");
        sets.put("selfRefAuth", "3");
        sets.put("multiRep", "3");
        sets.put("polyGold", "3");
        sets.put("signalPoison", "3");
        sets.put("buildSigBind", "3");
        // BF 家族保持关闭（自混淆/无入口/框架场景下会吞掉入口，需显式开启）
        sets.put("scatter", "0");
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
            // Mixin 会重排局部变量并把 handler 合入目标类，改写栈帧的 pass 需收敛
            sets.put("stackFrameRedirect", "0"); sets.put("methodSplit", "1");
            note.append("已启用 autoAdaptMc（mod 加载器自动适配）；类加密/资源混淆/BF 关闭以避免 Mixin 与入口破坏；"
                    + "栈帧重定向已收敛（Mixin 会重排局部变量）。");
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
            sets.put("protectNativeLibs", "1");
            sets.put("autoAdaptMc", "0");
            producesNative = true;
            note.append("独立应用：BF 混沌加载 + VMP/JNIC 分层；性能敏感可关 JNIC。");
        }
        // nativeShell 增强壳：仅在会产出原生码时才真正生效，按此给出推荐档
        sets.put("nativeShell", producesNative ? "3" : "0");
        if (!producesNative) {
            note.append("nativeShell 增强壳本轮无原生码产出（VMP/JNIC/BF 均关），推荐 0 以避免无谓的原生构建；"
                    + "如需 native crypto 路径加固可手动置 3。");
        } else {
            note.append("nativeShell 增强壳推荐 3（M1 字符串擦除 + M2 控制流变异 + M3 IAT/导入隐藏），"
                    + "对 JNIC 分片、VMP native 与 BF native decoder 的生成源码统一生效。");
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
        p.setProtectNativeLibs(jbool(o, "protectNativeLibs", false));
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
            g.printPair();
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

    /** 控制台打印远程监控连接信息（手机 APK / 浏览器）。 */
    private void printPair() {
        int port = server.getAddress().getPort();
        String lan = lanIp();
        String host = serveAddr != null ? serveAddr : (lan != null ? lan : "127.0.0.1");
        System.out.println("[KBox-GUI] 监听: " + bindHost + ":" + port);
        if (lan != null) System.out.println("[KBox-GUI] 局域网: http://" + lan + ":" + port + "/");
        System.out.println("[KBox-GUI] 手机监控连接串: http://" + host + ":" + port + "/?token=" + pairToken);
        if (serveAddr != null) System.out.println("[KBox-GUI] 公网/穿透: " + serveAddr + ":" + port);
        System.out.println("[KBox-GUI] 控制令牌: " + pairToken + "（远端 POST 控制需携带 token）");
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
