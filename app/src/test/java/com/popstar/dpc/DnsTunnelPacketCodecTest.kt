package com.popstar.dpc

import com.popstar.dpc.vpn.DnsTunnelPacketCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DnsTunnelPacketCodecTest {
    @Test
    fun parseAndBuildResponseRoundTrip() {
        val queryPacket = buildDnsUdpPacket()
        val query = DnsTunnelPacketCodec.parseQuery(queryPacket, queryPacket.size)
        assertNotNull(query)

        val dnsResponse = byteArrayOf(
            0x12, 0x34, (0x81).toByte(), (0x80).toByte(),
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00
        )
        val responsePacket = DnsTunnelPacketCodec.buildResponse(query!!, dnsResponse)
        assertEquals(20 + 8 + dnsResponse.size, responsePacket.size)
        assertEquals(17, responsePacket[9].toInt() and 0xFF)
    }

    @Test
    fun returnsNullForInvalidIpv4HeaderLength() {
        val queryPacket = buildDnsUdpPacket()
        queryPacket[0] = 0x41
        assertNull(DnsTunnelPacketCodec.parseQuery(queryPacket, queryPacket.size))
    }

    private fun buildDnsUdpPacket(): ByteArray {
        val dns = byteArrayOf(
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x03, 'w'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte(),
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00, 0x00, 0x01, 0x00, 0x01
        )
        val udpLen = 8 + dns.size
        val packet = ByteArray(20 + udpLen)
        packet[0] = 0x45
        packet[9] = 0x11
        // src ip 10.66.0.2
        packet[12] = 10
        packet[13] = 66
        packet[14] = 0
        packet[15] = 2
        // dst ip 1.1.1.1
        packet[16] = 1
        packet[17] = 1
        packet[18] = 1
        packet[19] = 1
        // src port 12345
        packet[20] = 0x30
        packet[21] = 0x39
        // dst port 53
        packet[22] = 0x00
        packet[23] = 0x35
        packet[24] = ((udpLen shr 8) and 0xFF).toByte()
        packet[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(dns, 0, packet, 28, dns.size)
        return packet
    }
}
