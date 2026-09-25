package com.kbox.monitor

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.kbox.monitor.databinding.ActivityConnectBinding

/** 连接页：扫码 / 手输 PC 端监控地址（http://host:port），进入实时监控。 */
class ConnectActivity : AppCompatActivity() {

    private lateinit var binding: ActivityConnectBinding
    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val url = result.contents
        if (url != null && url.isNotBlank()) {
            binding.urlInput.setText(url.trim())
        } else {
            Toast.makeText(this, getString(R.string.scan_failed), Toast.LENGTH_SHORT).show()
        }
    }
    private val camPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> if (granted) openScanner() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityConnectBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // 回填上次连接地址
        val last = getSharedPreferences("kbox", MODE_PRIVATE).getString("last_url", null)
        if (last != null) binding.urlInput.setText(last)

        binding.btnConnect.setOnClickListener { doConnect(binding.urlInput.text.toString().trim()) }

        binding.btnScan.setOnClickListener {
            if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                openScanner()
            } else {
                camPermLauncher.launch(Manifest.permission.CAMERA)
            }
        }

        // 外部调起：kboxmon://... 
        val dataUrl = intent.data?.toString()
        if (dataUrl != null && dataUrl.isNotBlank()) {
            binding.urlInput.setText(dataUrl)
            doConnect(dataUrl)
        }
    }

    private fun openScanner() {
        val opts = ScanOptions()
        opts.setBeepEnabled(false)
        opts.setOrientationLocked(true)
        scanLauncher.launch(opts)
    }

    private fun doConnect(raw: String) {
        val base = ProgressClient.normalizeBase(raw)
        if (base == null) {
            Toast.makeText(this, getString(R.string.url_invalid), Toast.LENGTH_SHORT).show()
            return
        }
        getSharedPreferences("kbox", MODE_PRIVATE)
            .edit().putString("last_url", base).apply()

        binding.statusText.text = getString(R.string.connecting)
        startActivity(Intent(this, MonitorActivity::class.java)
            .putExtra(MonitorActivity.EXTRA_BASE_URL, base))
    }
}