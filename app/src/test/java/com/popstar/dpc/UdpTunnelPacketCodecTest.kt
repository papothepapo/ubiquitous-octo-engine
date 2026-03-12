package com.popstar.dpc

import com.popstar.dpc.vpn.UdpTunnelPacketCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class UdpTunnelPacketCodecTest {
    @Test
    fun parseAndBuildResponseRoundTrip() {
        val requestPacket = buildUdpPacket(
            srcIp = byteArrayOf(10, 66, 0, 2),
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 40000,
            dstPort = 123,
            payload = "hello".toByteArray()
        )

        val parsed = UdpTunnelPacketCodec.parsePacket(requestPacket, requestPacket.size)
        assertNotNull(parsed)

        val response = UdpTunnelPacketCodec.UdpResponse(
            sourceIp = ipv4Int(8, 8, 8, 8),
            sourcePort = 123,
            payload = "world".toByteArray()
        )

        val responsePacket = UdpTunnelPacketCodec.buildResponse(parsed!!, response)
        assertEquals(17, responsePacket[9].toInt() and 0xFF)
        assertEquals(123, u16(responsePacket, 20))
        assertEquals(40000, u16(responsePacket, 22))
    }

    private fun buildUdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val packet = ByteArray(20 + udpLen)
        packet[0] = 0x45
        packet[9] = 0x11

        packet[12] = srcIp[0]
        packet[13] = srcIp[1]
        packet[14] = srcIp[2]
        packet[15] = srcIp[3]

        packet[16] = dstIp[0]
        packet[17] = dstIp[1]
        packet[18] = dstIp[2]
        packet[19] = dstIp[3]

        packet[20] = ((srcPort shr 8) and 0xFF).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = ((dstPort shr 8) and 0xFF).toByte()
        packet[23] = (dstPort and 0xFF).toByte()
        packet[24] = ((udpLen shr 8) and 0xFF).toByte()
        packet[25] = (udpLen and 0xFF).toByte()
        packet[26] = 0
        packet[27] = 0

        System.arraycopy(payload, 0, packet, 28, payload.size)
        return packet
    }

    private fun u16(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    }

    private fun ipv4Int(a: Int, b: Int, c: Int, d: Int): Int {
        return (a shl 24) or (b shl 16) or (c shl 8) or d
    }
}
