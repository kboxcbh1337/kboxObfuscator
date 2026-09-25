# 使用说明：局域网直连 / 公网穿透

## 一、局域网直连（最简单）

1. 电脑与手机连**同一个 WiFi / 网线**路由器。
2. 电脑端启动混淆器 GUI（`start-pc-monitor.bat` 或 `java -jar kbox.jar --gui`）。
   - 控制台会打印：
     ```
     [KBox-GUI] 局域网: http://192.168.1.10:xxxxx/
     [KBox-GUI] 手机监控连接串: http://192.168.1.10:xxxxx/?token=abc...
     ```
3. 手机 APK 连接页：
   - 手输：`http://192.168.1.10:xxxxx`
   - 或扫码：扫描电脑端监控页上显示的二维码（需 GUI 页面已带二维码）。
4. 连接后即显示进度与日志。

> 若手机连不上，先确认电脑防火墙允许该端口（同局域网 TCP 入站）。可用命令：
> ```powershell
> New-NetFirewallRule -DisplayName "KBoxMonitor" -Direction Inbound -Protocol TCP `
>   -LocalPort <端口> -Action Allow
> ```

## 二、公网 / 内网穿透（异地远程查看）

电脑混淆器服务本身跑在 `http://电脑IP:端口`，公网访问只需把该端口暴露出去。

### 方式 A：ssh 隧道（最省事，需一台公网机器）
```bash
# 在电脑上执行（把本机随机端口 <PORT> 映射到公网机 9000）
ssh -R 9000:127.0.0.1:<PORT> user@公网IP
# 手机填：http://公网IP:9000
```

### 方式 B：frp（需自建 frps 服务器）
- `frps.ini`：
  ```ini
  [common]
  bind_port = 7000
  ```
- `frpc.ini`（电脑上跑）：
  ```ini
  [common]
  server_addr = 公网IP
  server_port = 7000

  [kbox]
  type = tcp
  local_ip = 127.0.0.1
  local_port = <PORT>
  remote_port = 9000
  ```
- 手机填：`http://公网IP:9000`

### 方式 C：ngrok / cloudflared（无需自建，但域名随机）
```bash
ngrok http <PORT>       # 得到 https://xxxx.ngrok.io
cloudflared tunnel --url http://127.0.0.1:<PORT>
```
- 手机填：得到的公网地址。

### 方式 D：指定对外展示地址（serveAddr）
用一个固定的对外地址作为二维码/连接串展示，避免每次手动改：
```powershell
java -Dkbox.gui.serveAddr=mydomain.com -jar kbox.jar --gui
```
控制台打印的手机监控连接串会变成 `http://mydomain.com:<PORT>/?token=...`。

## 三、安全说明

- 监听默认 `0.0.0.0` 全接口。**公网/穿透场景请务必确认已理解 token 作用**：
  - 读取监控（`/api/state`、`/api/stream`）免令牌；发起/控制任务（POST）须带令牌 `?token=`。
  - token 每次启动随机生成（16 位十六进制）。QR 与连接串中已包含。
- 若完全无需远程控制，只做只读监控即可，令牌不透明向第三方暴露也无风险。
- 强烈建议端口不要映射到公网 0-1024 之外不做额外防护的裸 IP，如需更强访问控制再加内网/VPN。