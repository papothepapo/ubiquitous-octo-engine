package com.popstar.dpc.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
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

class PopstarVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private val ruleEngine = FirewallRuleEngine()
    private var worker: Thread? = null
    private val connectionOwnerCache = ConcurrentHashMap<Int, String?>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return Service.START_NOT_STICKY
        }

        if (running.compareAndSet(false, true)) {
            startForeground(NOTIFICATION_ID, buildNotification())
            vpnInterface = Builder()
                .setSession("Popstar Local Firewall")
                .addAddress("10.66.0.2", 32)
                .addRoute("0.0.0.0", 0)
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
                        if (length <= 0) continue

                        val appPackage = resolvePacketOwnerPackage(buffer, length)
                        if (appPackage != null && appPackage in FirewallRuntime.blockedPackages) {
                            FirewallRuntime.logBlocked("blocked app: $appPackage")
                            continue
                        }

                        val host = PacketParsers.extractDnsQueryHost(buffer, length)
                            ?: PacketParsers.extractTlsSniHost(buffer, length)

                        if (host != null && ruleEngine.shouldBlock(host, appPackage, FirewallRuntime.rules)) {
                            FirewallRuntime.logBlocked(
                                if (appPackage == null) "blocked host: $host" else "blocked host: $host app: $appPackage"
                            )
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

                        val udpPacket = UdpTunnelPacketCodec.parsePacket(buffer, length)
                        if (udpPacket != null) {
                            val response = forwardUdpPacket(udpPacket) ?: continue
                            val packet = UdpTunnelPacketCodec.buildResponse(udpPacket, response)
                            output.write(packet)
                            output.flush()
                            continue
                        }
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
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return null
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


    private fun forwardUdpPacket(packet: UdpTunnelPacketCodec.UdpPacket): UdpTunnelPacketCodec.UdpResponse? {
        return runCatching {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = 2_000

                val destination = InetAddress.getByAddress(intToIpv4(packet.destIp))
                val outbound = DatagramPacket(packet.payload, packet.payload.size, destination, packet.destPort)
                socket.send(outbound)

                val responseBuffer = ByteArray(65507)
                val inbound = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(inbound)

                val sourceAddress = inbound.socketAddress as? InetSocketAddress
                val sourceIp = sourceAddress?.address?.address?.let(::ipv4ToInt) ?: packet.destIp
                UdpTunnelPacketCodec.UdpResponse(
                    sourceIp = sourceIp,
                    sourcePort = inbound.port,
                    payload = inbound.data.copyOf(inbound.length)
                )
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

    private fun ipv4ToInt(bytes: ByteArray): Int {
        if (bytes.size < 4) return 0
        return ((bytes[0].toInt() and 0xFF) shl 24) or
            ((bytes[1].toInt() and 0xFF) shl 16) or
            ((bytes[2].toInt() and 0xFF) shl 8) or
            (bytes[3].toInt() and 0xFF)
    }

    override fun onRevoke() {
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
}
