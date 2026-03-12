package com.popstar.dpc.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.popstar.dpc.data.firewall.FirewallRuleEngine
import com.popstar.dpc.data.firewall.FirewallRuntime
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

class PopstarVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private val ruleEngine = FirewallRuleEngine()
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return Service.START_NOT_STICKY
        }

        if (running.compareAndSet(false, true)) {
            startForeground(NOTIFICATION_ID, buildNotification())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running.compareAndSet(false, true)) {
            val builder = Builder()
                .setSession("Popstar Local Firewall")
                .addAddress("10.66.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(DNS_UPSTREAM)
                .addDnsServer("1.1.1.1")
            vpnInterface = builder.establish()
            startReadLoop()
        }
        return Service.START_REDELIVER_INTENT
        return Service.START_STICKY
    }

    private fun startReadLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        worker = Thread({
            FileInputStream(fd).use { input ->
                FileOutputStream(fd).use { output ->
                    val buffer = ByteArray(32767)
                    while (running.get()) {
                        val length = input.read(buffer)
                        if (length <= 0) continue

                        val host = PacketParsers.extractDnsQueryHost(buffer, length)
                            ?: PacketParsers.extractTlsSniHost(buffer, length)

                        if (host != null && ruleEngine.shouldBlock(host, null, FirewallRuntime.rules)) {
                            FirewallRuntime.logBlocked("blocked host: $host")
                            continue
                        }

                        // Forward allowed DNS packets to upstream resolver and inject response.
                        val dnsQuery = DnsTunnelPacketCodec.parseQuery(buffer, length)
                        if (dnsQuery != null) {
                            val response = forwardDnsQuery(dnsQuery.dnsPayload)
                            if (response != null) {
                                val packet = DnsTunnelPacketCodec.buildResponse(dnsQuery, response)
                                output.write(packet)
                                output.flush()
                            }
                        }
        Thread {
            FileInputStream(fd).use { input ->
                val buffer = ByteArray(32767)
                while (running.get()) {
                    val length = input.read(buffer)
                    if (length <= 0) continue
                    val host = PacketParsers.extractDnsQueryHost(buffer, length)
                        ?: PacketParsers.extractTlsSniHost(buffer, length)
                        ?: continue
                    if (ruleEngine.shouldBlock(host, null, FirewallRuntime.rules)) {
                        FirewallRuntime.logBlocked("blocked host: $host")
                    }
                }
            }
        }, "popstar-vpn-reader").apply { start() }
    }

    private fun forwardDnsQuery(query: ByteArray): ByteArray? {
        return runCatching {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = 3_000
                val request = DatagramPacket(query, query.size, InetAddress.getByName(DNS_UPSTREAM), 53)
                socket.send(request)
                val responseBuffer = ByteArray(4096)
                val response = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(response)
                response.data.copyOf(response.length)
            }
        }.getOrNull()
    }

    override fun onRevoke() {
        super.onRevoke()
        stopSelf()
    override fun onRevoke() {
        super.onRevoke()
        stopSelf()
                    // Packet inspection and blocking decisions are evaluated here.
                }
            }
        }.start()
    }

    override fun onDestroy() {
        running.set(false)
        worker?.interrupt()
        worker = null
        vpnInterface?.close()
        stopForeground(STOP_FOREGROUND_REMOVE)
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

        val stopIntent = Intent(this, PopstarVpnService::class.java).apply { action = ACTION_STOP }
        val stopPending = PendingIntent.getService(
            this,
            10,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Popstar Firewall")
            .setContentText("Local VPN active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .addAction(Notification.Action.Builder(null, "Stop", stopPending).build())
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "popstar_vpn"
        private const val NOTIFICATION_ID = 7
        private const val ACTION_STOP = "com.popstar.dpc.vpn.STOP"
        private const val DNS_UPSTREAM = "1.1.1.1"
    }
        vpnInterface?.close()
        super.onDestroy()
    }
}
