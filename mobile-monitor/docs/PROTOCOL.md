# PC(电脑版混淆器) ↔ 手机(APK) 监控协议
该协议统一定义，两端（电脑版 GUI / 手机版 APK）遵循同一 schema 即保持同步。

## 基础信息

- 电脑端启动混淆器 GUI 后内嵌一个 HTTP 服务，默认监听 `0.0.0.0:<随机端口>`。
- 基地址记为 `BASE = http://<host>:<port>`。
- 监控读取免令牌；控制类 POST 须带 `?token=<pairToken>`（本机回环放行）。

## 1. 配对信息 `GET BASE/api/pair`

返回 JSON：

```json
{
  "ok": true,
  "bindHost": "0.0.0.0",
  "port": 45415,
  "lanIp": "192.168.1.10",
  "serveAddr": null,
  "displayHost": "192.168.1.10",
  "token": "a1b2...",
  "url": "http://192.168.1.10:45415/?token=a1b2..."
}
```

- `url` 为可直接连接/扫码的连接串。APK 用 `normalizeBase` 抽取出 `BASE`（去 path 与 query）。

## 2. 状态快照 `GET BASE/api/state?since=<seq>`

返回 JSON：

```json
{
  "runId": 173...,
  "status": "running",
  "stage": 3,
  "total": 25,
  "percent": 42,
  "stageName": "Class obfuscation",
  "summary": "",
  "error": "",
  "running": true,
  "entries": [
    {"s": 12, "lvl": "info", "l": "[12:00:01] ..."}
  ]
}
```

- `runId`：本次运行批号，客户端用它丢弃过期响应（新 run 开始后旧响应忽略）。
- `entries`：日志增量，`since` 为上次拉到的最新 `s`。

## 3. 实时推送 `GET BASE/api/stream`（SSE）

`Content-Type: text/event-stream`。每行以 `event: <type>` + `data: <json>` + 空行分隔。

事件类型：

- `event: state`，`data` 为段2的状态 JSON（无 `entries` 字段）。
- `event: log`，`data` 为单条日志：`{"s":<seq>,"lvl":"info","l":"<行文本>"}`。

心跳：每秒发送 `: hb` 注释（SSE 规范中行首冒号视为注释，客户端忽略）。

## 4. 控制（手机默认只读，不调用）

- `POST BASE/api/protect`：提交混淆任务。必须携带 `?token=`。
- `POST BASE/api/upload` / `POST BASE/api/analyze` / `POST BASE/api/shield[/analyze]`：同上。
- 未认证的远端 POST 返回 `403 {"ok":false,"error":"forbidden: missing/incorrect token"}`。

## Android 端实现要点

- 解析库：OkHttp SSE（`com.squareup.okhttp3:okhttp-sse`）+ `org.json`。
- 连接页：`ProgressClient.normalizeBase()` 归一化任意输入/扫码串 → 严格 `http://host[:port]`。
- 监控页：`ProgressClient` 先轮询基线，再开 SSE；SSE 断开自动回落轮询（3s 重连）。
- 主线程更新 UI（`Handler` 回调包装 onState/onLog/onStatus）。