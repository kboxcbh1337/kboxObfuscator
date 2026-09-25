package com.kbox.monitor

import android.os.Handler
import android.os.Looper
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import okhttp3.sse.EventSources
import org.json.JSONObject
import java.io.IOException
import java.net.URL
import java.util.concurrent.TimeUnit

/** 与 PC 端混淆器监控服务交互的客户端（SSE 实时 + /api/state 轮询兜底）。 */
class ProgressClient(
    private val baseUrl: String,            // http://host:port（不含路径、不含 token）
    private val onState: (State) -> Unit,   // 状态更新（主线程回调）
    private val onLog: (LogLine) -> Unit,   // 新增日志行（主线程回调）
    private val onStatus: (Boolean, String?) -> Unit // 连接/断开状态；err 非空表示有错
) {
    data class State(
        val runId: Long, val status: String, val stage: Int, val total: Int,
        val percent: Int, val stageName: String, val summary: String,
        val error: String, val running: Boolean
    )
    data class LogLine(val s: Long, val lvl: String, val line: String)

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)   // SSE 长连接
        .pingInterval(20, TimeUnit.SECONDS)
        .build()
    private val handler = Handler(Looper.getMainLooper())

    private var eventSource: EventSource? = null
    private var pollCall: Call? = null
    private var started = false

    fun start() {
        if (started) return
        started = true
        watchSse()
        pollOnce()                  // 基线
    }

    fun stop() {
        started = false
        eventSource?.cancel()
        eventSource = null
        pollCall?.cancel()
        pollCall = null
    }

    // ---- SSE 实时通道 ----
    private fun watchSse() {
        val req = Request.Builder().url(baseUrl.trimEnd('/') + "/api/stream").build()
        EventSources.createFactory(client).newEventSource(req, object : EventSourceListener() {
            override fun onEvent(es: EventSource, id: String?, type: String?, data: String) {
                if (!started) return
                when (type) {
                    "state" -> dispatchState(parseStateOrNull(data))
                    "log" -> dispatchLog(parseLogOrNull(data))
                    else -> {}
                }
            }
            override fun onFailure(es: EventSource, t: Throwable?, response: Response?) {
                if (!started) return
                onStatus(false, t?.message)
            }
            override fun onClosed(es: EventSource) {
                if (!started) return
                onStatus(false, null)
            }
        }).also { eventSource = it }
    }

    // ---- 轮询兜底（初始化 + 断流保护）----
    private fun pollOnce() {
        if (!started) return
        val req = Request.Builder().url(baseUrl.trimEnd('/') + "/api/state").build()
        val cb = object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (!started) return
                onStatus(false, e.message)
                handler.postDelayed({ pollOnce() }, 3000)
            }
            override fun onResponse(call: Call, response: Response) {
                try {
                    val body = response.body?.string()
                    if (body != null && response.isSuccessful) {
                        val s = parseStateOrNull(body)
                        if (s != null) {
                            onStatus(true, null)
                            dispatchState(s)
                        }
                    }
                } catch (ignore: Exception) {
                } finally {
                    response.close()
                }
                if (started) handler.postDelayed({ pollOnce() }, 4000)
            }
        }
        pollCall?.cancel()
        pollCall = client.newCall(req)
        try { pollCall?.enqueue(cb) } catch (ignore: Exception) {}
    }

    private fun dispatchState(s: State) = handler.post { onState(s) }
    private fun dispatchLog(l: LogLine) = handler.post { onLog(l) }

    private fun parseStateOrNull(json: String): State? = try {
        val o = JSONObject(json)
        State(
            runId = o.optLong("runId", 0),
            status = o.optString("status", "idle"),
            stage = o.optInt("stage", 0),
            total = o.optInt("total", 0),
            percent = o.optInt("percent", 0),
            stageName = o.optString("stageName", ""),
            summary = o.optString("summary", ""),
            error = o.optString("error", ""),
            running = o.optBoolean("running", false)
        )
    } catch (t: Exception) { null }

    private fun parseLogOrNull(json: String): LogLine? = try {
        val o = JSONObject(json)
        LogLine(o.optLong("s", 0), o.optString("lvl", "info"), o.optString("l", ""))
    } catch (t: Exception) { null }

    companion object {
        /** 从形如 http://host:port / kboxmon://host:port?token= 归一化 baseUrl。 */
        fun normalizeBase(raw: String): String? {
            var s = raw.trim()
            if (s.isEmpty()) return null
            if (s.startsWith("kboxmon://")) s = "http://" + s.removePrefix("kboxmon://")
            else if (!s.startsWith("http://") && !s.startsWith("https://")) s = "http://" + s
            s = s.trimEnd('/')
            val q = s.indexOf('?')
            if (q >= 0) s = s.substring(0, q)   // 剥离 token（读取不需要）
            try {
                val u = URL(s)
                val host = u.host ?: return null
                val port = if (u.port == -1) "" else ":" + u.port
                return "http://$host$port"
            } catch (e: Exception) {
                return null
            }
        }
    }
}