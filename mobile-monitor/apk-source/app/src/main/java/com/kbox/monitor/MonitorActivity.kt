package com.kbox.monitor

import android.os.Bundle
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import com.kbox.monitor.databinding.ActivityMonitorBinding
import java.util.Collections

/** 实时监控页：进度条 + 阶段名 + 日志流（SSE 实时 + 轮询兜底）。 */
class MonitorActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMonitorBinding
    private var client: ProgressClient? = null
    private val logs = Collections.synchronizedList(ArrayList<String>())
    private lateinit var adapter: ArrayAdapter<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMonitorBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val baseUrl = intent.getStringExtra(EXTRA_BASE_URL) ?: return finish()

        binding.hostView.text = baseUrl
        binding.progressBar.max = 100

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, logs)
        binding.logList.adapter = adapter

        client = ProgressClient(
            baseUrl = baseUrl,
            onState = { render(it) },
            onLog = { appendLog(it) },
            onStatus = { ok, err ->
                binding.connView.text = if (ok) getString(R.string.connected)
                    else getString(R.string.disconnected, err ?: "-")
            }
        )
        client?.start()
    }

    private fun render(s: ProgressClient.State) {
        binding.statusView.text = s.status
        val pct = s.percent.coerceIn(0, 100)
        binding.progressBar.progress = pct
        binding.percentView.text = "$pct%"
        binding.stageView.text =
            if (s.total > 0) getString(R.string.stage_progress, s.stage, s.total, s.stageName)
            else s.stageName
        binding.summaryView.text = s.summary
    }

    private fun appendLog(l: ProgressClient.LogLine) {
        logs.add(l.line)
        // 仅保留最近 500 行，防止内存无限增长。
        while (logs.size > 500) logs.removeAt(0)
        adapter.notifyDataSetChanged()
        if (logs.isNotEmpty()) {
            binding.logList.post { binding.logList.setSelection(logs.size - 1) }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        client?.stop()
        client = null
    }

    override fun onBackPressed() {
        client?.stop()
        super.onBackPressed()
    }

    companion object {
        const val EXTRA_BASE_URL = "base_url"
    }
}