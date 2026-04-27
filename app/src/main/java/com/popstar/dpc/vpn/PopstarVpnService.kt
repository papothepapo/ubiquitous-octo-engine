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
import android.system.OsConstants.AF_INET
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
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import androidx.core.app.NotificationCompat

class PopstarVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private val ruleEngine = FirewallRuleEngine()
    private var worker: Thread? = null
    private val connectionOwnerCache = ConcurrentHashMap<Int, String?>()
    private val lastLegacySinkLogMs = AtomicLong(0L)
    @Volatile
    private var legacyBlockedAppSinkActive = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            running.set(false)
            closeVpnInterface()
            stopWorker(join = false)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return Service.START_NOT_STICKY
        }

        if (running.compareAndSet(false, true)) {
            startForeground(NOTIFICATION_ID, buildNotification())
            vpnInterface = buildVpnInterface()
            if (vpnInterface == null) {
                running.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            } else {
                startReadLoop()
            }
        } else {
            rebuildVpnInterface()
        }

        return Service.START_REDELIVER_INTENT
    }

    private fun buildVpnInterface(): ParcelFileDescriptor? {
        return runCatching {
            val legacySinkRequested = shouldUseLegacyBlockedAppSink()
            val builder = Builder()
                .setSession("Popstar Local Firewall")
                .setMtu(1500)
                .addAddress("10.66.0.2", 32)
                .allowFamily(AF_INET)

            if (legacySinkRequested) {
                val routedPackages = FirewallRuntime.blockedPackages
                    .filterNot { it == packageName }
                    .mapNotNull { blockedPackage ->
                        runCatching {
                            builder.addAllowedApplication(blockedPackage)
                            blockedPackage
                        }.getOrNull()
                    }

                if (routedPackages.isEmpty()) {
                    legacyBlockedAppSinkActive = false
                    DNS_ROUTES.forEach { resolver -> builder.addRoute(resolver, 32) }
                } else {
                    legacyBlockedAppSinkActive = true
                    builder.addRoute("0.0.0.0", 0)
                }
            } else {
                legacyBlockedAppSinkActive = false
                DNS_ROUTES.forEach { resolver ->
                    builder.addRoute(resolver, 32)
                }
            }

            DNS_UPSTREAMS.forEach { resolver -> builder.addDnsServer(resolver) }

            builder.establish()
        }.getOrNull()
    }

    private fun rebuildVpnInterface() {
        closeVpnInterface()
        stopWorker(join = true)

        val nextInterface = buildVpnInterface()
        if (nextInterface == null) {
            running.set(false)
            legacyBlockedAppSinkActive = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        vpnInterface = nextInterface
        startReadLoop()
    }

    private fun startReadLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        worker = Thread({
            runCatching {
                FileInputStream(fd).use { input ->
                    FileOutputStream(fd).use { output ->
                        val buffer = ByteArray(32767)
                        while (running.get()) {
                            val length = input.read(buffer)
                            if (length <= 0) {
                                if (!running.get()) break
                                continue
                            }

                            if (legacyBlockedAppSinkActive) {
                                logLegacySinkDrop()
                                continue
                            }

                            val appPackage = resolvePacketOwnerPackage(buffer, length)
                            if (appPackage != null && appPackage in FirewallRuntime.blockedPackages) {
                                FirewallRuntime.logBlocked(category = "app", appPackage = appPackage, details = "Blocked app DNS request")
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

                            // Normal app traffic remains on the system network unless Android
                            // lockdown policy or legacy blocked-app sink routing sends it here.
                        }
                    }
                }
            }.onFailure { error ->
                if (running.get() && error !is SocketException) {
                    FirewallRuntime.logBlocked(category = "vpn", details = "VPN loop stopped: ${error.message}")
                }
            }
        }, "popstar-vpn-reader").apply { start() }
    }

    private fun shouldUseLegacyBlockedAppSink(): Boolean {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.Q && FirewallRuntime.blockedPackages.isNotEmpty()
    }

    private fun logLegacySinkDrop() {
        val now = System.currentTimeMillis()
        val previous = lastLegacySinkLogMs.get()
        if (now - previous > LEGACY_SINK_LOG_INTERVAL_MS && lastLegacySinkLogMs.compareAndSet(previous, now)) {
            FirewallRuntime.logBlocked(
                category = "app",
                details = "Blocked app traffic on Android 9 or below"
            )
        }
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
                val request = DatagramPacket(query, query.size, InetAddress.getByName(DNS_UPSTREAMS.first()), 53)
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
        closeVpnInterface()
        stopWorker(join = false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onRevoke()
        stopSelf()
    }

    override fun onDestroy() {
        running.set(false)
        closeVpnInterface()
        stopWorker(join = false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun closeVpnInterface() {
        runCatching { vpnInterface?.close() }
        vpnInterface = null
    }

    private fun stopWorker(join: Boolean) {
        val oldWorker = worker
        worker = null
        oldWorker?.interrupt()
        if (join && oldWorker != null && oldWorker != Thread.currentThread()) {
            runCatching { oldWorker.join(WORKER_JOIN_TIMEOUT_MS) }
        }
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
        private val DNS_UPSTREAMS = listOf("1.1.1.1", "1.0.0.1")
        private val DNS_ROUTES = listOf(
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "9.9.9.9",
            "208.67.222.222",
            "208.67.220.220"
        )
        private const val LEGACY_SINK_LOG_INTERVAL_MS = 2_000L
        private const val WORKER_JOIN_TIMEOUT_MS = 500L

        fun startIntent(context: android.content.Context): Intent = Intent(context, PopstarVpnService::class.java)

        fun stopIntent(context: android.content.Context): Intent =
            Intent(context, PopstarVpnService::class.java).apply { action = ACTION_STOP }
    }
}
