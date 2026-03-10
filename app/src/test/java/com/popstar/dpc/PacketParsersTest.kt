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
}
