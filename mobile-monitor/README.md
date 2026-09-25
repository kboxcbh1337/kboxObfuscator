# KBox Mobile Monitor / 手机远程监控

让手机（Android）远程查看电脑端混淆器的实时进度：当前阶段、进度百分比、阶段名、实时日志。
电脑端继续跑完整混淆（含 PE 加壳 / native 编译 / VMP / JNIC 等），手机只做**远程监控端**。

## 目录结构

```
mobile-monitor/
├── apk-source/               # Android 工程（Kotlin，可构建 APK）
├── build-scripts/
│   └── build-apk.ps1         # 一键引导安装 Android SDK 并产出 APK
├── docs/
│   ├── USAGE.md              # 局域网直连 / 公网穿透 实操步骤
│   └── PROTOCOL.md           # PC↔手机 使用的 JSON / SSE 协议（供双端同步）
├── start-pc-monitor.bat      # 电脑端双击启动混淆器 GUI + 监控服务
├── sync.ps1                  # 把最新 kboxObfPro dist 同步到本目录，保证两端版本一致
└── README.md
```

## 快速上手（局域网）

1. **电脑端**：双击 `start-pc-monitor.bat`（或 `java -jar kboxObfuscator.jar --gui`）。
   控制台会打印一行 `手机监控连接串: http://<电脑IP>:<端口>/?token=xxxx`。
2. **手机端**：安装 APK 后，在连接页**手输**该地址，或**扫电脑端监控页上的二维码**。
3. 进入监控页即实时显示电脑端混淆进度与日志。

> 手机与电脑需在同一局域网，或电脑做了公网/内网穿透（见 `docs/USAGE.md`）。

## 电脑端（电脑版）

改动位于 `kbox-gui/src/main/java/com/kbox/gui/ProtectorGui.java`：

- 监听地址由 `127.0.0.1` 改为 `0.0.0.0`（局域网即可达，可用 `-Dkbox.gui.host=` 覆盖）。
- 新增 `/api/pair`（配对信息 JSON）、`/api/stream`（SSE 实时推送）。
- 控制类 POST（保护/上传/加壳/分析）需携带 `?token=`；本机回环放行，远端须带令牌。
- 命令行参数：`-Dkbox.gui.host=<ip>`、`-Dkbox.gui.port=<port>`、`-Dkbox.gui.serveAddr=<域名/公网IP>`。

**如何重建电脑版 jar**（使监控生效）：

```powershell
mvn -f pom.xml -pl kbox-cli -am -DskipTests package
# 产物：kbox-cli/target/kbox-protector.jar（含 GUI 与监控服务）
java -jar kbox-cli/target/kbox-protector.jar --gui
```

## 手机版（APK）

- 运行 `build-scripts/build-apk.ps1`：脚本会自动下载并安装 Android SDK（首次需联网）、写入
  `sdk.dir`，再用系统 Gradle 编译出 `app/build/outputs/apk/debug/app-debug.apk`。
- APK 为侧载安装（需在手机“安装未知来源应用”中开启允许）。

## 电脑版 ↔ 手机版 同步更新

协议在 `docs/PROTOCOL.md` 中统一定义（`/api/state` JSON 字段 + SSE 事件名）。两端只要遵循同一
schema 即自动保持同步；`sync.ps1` 会把最新 kboxObfPro dist 同步进来，确保电脑版与手机版能力一致。
