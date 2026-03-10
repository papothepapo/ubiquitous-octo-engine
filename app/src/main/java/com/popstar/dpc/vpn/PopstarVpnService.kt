package com.popstar.dpc.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.popstar.dpc.data.firewall.FirewallRuleEngine
import com.popstar.dpc.data.firewall.FirewallRuntime
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

class PopstarVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private val ruleEngine = FirewallRuleEngine()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running.compareAndSet(false, true)) {
            startForeground(NOTIFICATION_ID, buildNotification())
            val builder = Builder()
                .setSession("Popstar Local Firewall")
                .addAddress("10.66.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
            vpnInterface = builder.establish()
            startReadLoop()
        }
        return Service.START_STICKY
    }

    private fun startReadLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        Thread {
            FileInputStream(fd).use { input ->
                val buffer = ByteArray(32767)
                while (running.get()) {
                    val length = input.read(buffer)
                    if (length <= 0) continue
                    val host = PacketParsers.extractDnsQueryHost(buffer, length) ?: continue
                    if (ruleEngine.shouldBlock(host, null, FirewallRuntime.rules)) {
                        FirewallRuntime.logBlocked("dns blocked: $host")
                    }
                }
            }
        }.start()
    }

    override fun onDestroy() {
        running.set(false)
        vpnInterface?.close()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Popstar VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Popstar Firewall")
            .setContentText("Local VPN active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "popstar_vpn"
        private const val NOTIFICATION_ID = 7
    }
}
