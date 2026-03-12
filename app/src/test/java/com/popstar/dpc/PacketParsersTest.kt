package com.popstar.dpc

import com.popstar.dpc.vpn.PacketParsers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PacketParsersTest {
    @Test
    fun parsesIpv4UdpDnsQueryHost() {
        val packet = buildDnsQueryPacket("ads.example.com")
        val host = PacketParsers.extractDnsQueryHost(packet, packet.size)
        assertEquals("ads.example.com", host)
    }

    @Test
    fun parsesTlsSniHost() {
        val packet = buildTlsClientHelloPacket("video.example.com")
        val host = PacketParsers.extractTlsSniHost(packet, packet.size)
        assertEquals("video.example.com", host)
    }

    @Test
    fun returnsNullForNonDnsPacket() {
        val packet = ByteArray(40)
        packet[0] = 0x45
        packet[9] = 0x06 // TCP
        assertNull(PacketParsers.extractDnsQueryHost(packet, packet.size))
    }

    private fun buildDnsQueryPacket(host: String): ByteArray {
        val labels = host.split('.')
        val qname = mutableListOf<Byte>()
        labels.forEach { label ->
            qname.add(label.length.toByte())
            qname.addAll(label.toByteArray(Charsets.US_ASCII).toList())
        }
        qname.add(0)

        val dns = ByteArray(12 + qname.size + 4)
        dns[4] = 0x00
        dns[5] = 0x01 // QDCOUNT = 1
        var i = 12
        qname.forEach { dns[i++] = it }
        dns[i++] = 0x00
        dns[i++] = 0x01 // A
        dns[i++] = 0x00
        dns[i] = 0x01 // IN

        val ihl = 20
        val udpLen = 8 + dns.size
        val packet = ByteArray(ihl + udpLen)
        packet[0] = 0x45
        packet[9] = 0x11 // UDP
        packet[ihl + 2] = 0x00
        packet[ihl + 3] = 0x35 // dst port 53
        packet[ihl + 4] = ((udpLen shr 8) and 0xFF).toByte()
        packet[ihl + 5] = (udpLen and 0xFF).toByte()
        System.arraycopy(dns, 0, packet, ihl + 8, dns.size)
        return packet
    }

    private fun buildTlsClientHelloPacket(host: String): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val sniName = byteArrayOf(0x00) + u16(hostBytes.size) + hostBytes
        val sniList = u16(sniName.size) + sniName
        val sniExt = u16(0x0000) + u16(sniList.size) + sniList
        val extensions = sniExt

        val body = mutableListOf<Byte>()
        body += byteArrayOf(0x03, 0x03).toList() // client version
        body += ByteArray(32).toList() // random
        body += byteArrayOf(0x00).toList() // session id len
        body += byteArrayOf(0x00, 0x02).toList() // cipher suites len
        body += byteArrayOf(0x13, 0x01).toList() // TLS_AES_128_GCM_SHA256
        body += byteArrayOf(0x01, 0x00).toList() // compression methods
        body += u16(extensions.size).toList()
        body += extensions.toList()

        val handshake = mutableListOf<Byte>()
        handshake += 0x01.toByte() // client hello
        handshake += u24(body.size).toList()
        handshake += body

        val tls = mutableListOf<Byte>()
        tls += 0x16.toByte() // handshake record
        tls += byteArrayOf(0x03, 0x03).toList()
        tls += u16(handshake.size).toList()
        tls += handshake

        val tcpHeaderLen = 20
        val ipHeaderLen = 20
        val packet = ByteArray(ipHeaderLen + tcpHeaderLen + tls.size)
        packet[0] = 0x45
        packet[9] = 0x06 // TCP
        val srcPort = 55555
        packet[ipHeaderLen] = ((srcPort shr 8) and 0xFF).toByte()
        packet[ipHeaderLen + 1] = (srcPort and 0xFF).toByte()
        packet[ipHeaderLen + 2] = 0x01
        packet[ipHeaderLen + 3] = (0xBB).toByte() // 443
        packet[ipHeaderLen + 12] = 0x50 // data offset 5 (20 bytes)
        System.arraycopy(tls.toByteArray(), 0, packet, ipHeaderLen + tcpHeaderLen, tls.size)
        return packet
    }

    private fun u16(value: Int): ByteArray = byteArrayOf(((value shr 8) and 0xFF).toByte(), (value and 0xFF).toByte())
    private fun u24(value: Int): ByteArray = byteArrayOf(((value shr 16) and 0xFF).toByte(), ((value shr 8) and 0xFF).toByte(), (value and 0xFF).toByte())
}
