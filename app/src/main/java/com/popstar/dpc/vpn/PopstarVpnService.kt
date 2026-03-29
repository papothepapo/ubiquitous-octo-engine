package com.popstar.dpc.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants.IPPROTO_TCP
import android.system.OsConstants.IPPROTO_UDP
import com.popstar.dpc.data.firewall.FirewallRuleEngine
import com.popstar.dpc.data.firewall.FirewallRuntime
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import androidx.core.app.NotificationCompat

class PopstarVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private val ruleEngine = FirewallRuleEngine()
    private var worker: Thread? = null
    private val connectionOwnerCache = ConcurrentHashMap<Int, String?>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            running.set(false)
            vpnInterface?.close()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return Service.START_NOT_STICKY
        }

        if (running.compareAndSet(false, true)) {
            startForeground(NOTIFICATION_ID, buildNotification())
            vpnInterface = Builder()
                .setSession("Popstar Local Firewall")
                .setMtu(1500)
                .addAddress("10.66.0.2", 32)
                // Route only DNS resolver traffic through this local VPN so normal app traffic
                // keeps flowing over the system network stack.
                .addRoute(DNS_UPSTREAM, 32)
                .addRoute("1.0.0.1", 32)
                .addDnsServer(DNS_UPSTREAM)
                .addDnsServer("1.1.1.1")
                .establish()
            startReadLoop()
        }

        return Service.START_REDELIVER_INTENT
    }

    private fun startReadLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        worker = Thread({
            FileInputStream(fd).use { input ->
                FileOutputStream(fd).use { output ->
                    val buffer = ByteArray(32767)
                    while (running.get()) {
                        val length = input.read(buffer)
                        if (length <= 0) {
                            if (!running.get()) break
                            continue
                        }

                        val appPackage = resolvePacketOwnerPackage(buffer, length)
                        if (appPackage != null && appPackage in FirewallRuntime.blockedPackages) {
                            FirewallRuntime.logBlocked(category = "app", appPackage = appPackage, details = "Blocked app request")
                            continue
                        }

                        val host = PacketParsers.extractDnsQueryHost(buffer, length)
                            ?: PacketParsers.extractTlsSniHost(buffer, length)

                        if (host != null && ruleEngine.shouldBlock(host, appPackage, FirewallRuntime.rules)) {
                            FirewallRuntime.logBlocked(category = "site", appPackage = appPackage, site = host, details = if (appPackage == null) "Blocked host" else "Blocked host for app")
                            continue
                        }

                        val dnsQuery = DnsTunnelPacketCodec.parseQuery(buffer, length)
                        if (dnsQuery != null) {
                            val response = forwardDnsQuery(dnsQuery.dnsPayload) ?: continue
                            val packet = DnsTunnelPacketCodec.buildResponse(dnsQuery, response)
                            output.write(packet)
                            output.flush()
                            continue
                        }

                        // Non-DNS packets are not handled here; only DNS resolver traffic is routed
                        // into this service via Builder routes.
                    }
                }
            }
        }, "popstar-vpn-reader").apply { start() }
    }


    private fun resolvePacketOwnerPackage(packet: ByteArray, length: Int): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        val metadata = PacketParsers.extractConnectionMetadata(packet, length) ?: return null
        val protocol = when (metadata.protocol) {
            6 -> IPPROTO_TCP
            17 -> IPPROTO_UDP
            else -> return null
        }

        val local = InetSocketAddress(
            InetAddress.getByAddress(intToIpv4(metadata.sourceIp)),
            metadata.sourcePort
        )
        val remote = InetSocketAddress(
            InetAddress.getByAddress(intToIpv4(metadata.destIp)),
            metadata.destPort
        )
        val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
        val ownerUid = runCatching { connectivity.getConnectionOwnerUid(protocol, local, remote) }.getOrNull() ?: return null
        if (ownerUid <= 0) return null

        return connectionOwnerCache.getOrPut(ownerUid) {
            packageManager.getPackagesForUid(ownerUid)?.firstOrNull()
        }
    }

    private fun forwardDnsQuery(query: ByteArray): ByteArray? {
        return runCatching {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = 1_500
                val request = DatagramPacket(query, query.size, InetAddress.getByName(DNS_UPSTREAM), 53)
                socket.send(request)
                val responseBuffer = ByteArray(4096)
                val response = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(response)
                response.data.copyOf(response.length)
            }
        }.getOrNull()
    }

    private fun intToIpv4(value: Int): ByteArray {
        return byteArrayOf(
            ((value ushr 24) and 0xFF).toByte(),
            ((value ushr 16) and 0xFF).toByte(),
            ((value ushr 8) and 0xFF).toByte(),
            (value and 0xFF).toByte()
        )
    }

    override fun onRevoke() {
        running.set(false)
        vpnInterface?.close()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onRevoke()
        stopSelf()
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
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Popstar VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Popstar Firewall")
            .setContentText("Local VPN active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "popstar_vpn"
        private const val NOTIFICATION_ID = 7
        private const val ACTION_STOP = "com.popstar.dpc.vpn.STOP"
        private const val DNS_UPSTREAM = "1.1.1.1"

        fun startIntent(context: android.content.Context): Intent = Intent(context, PopstarVpnService::class.java)

        fun stopIntent(context: android.content.Context): Intent =
            Intent(context, PopstarVpnService::class.java).apply { action = ACTION_STOP }
    }
}
