package com.popstar.dpc.vpn

import java.nio.ByteBuffer

/**
 * Minimal IPv4 UDP codec for non-DNS request/response forwarding.
 */
object UdpTunnelPacketCodec {
    data class UdpPacket(
        val sourceIp: Int,
        val destIp: Int,
        val sourcePort: Int,
        val destPort: Int,
        val payload: ByteArray
    )

    data class UdpResponse(
        val sourceIp: Int,
        val sourcePort: Int,
        val payload: ByteArray
    )

    fun parsePacket(packet: ByteArray, length: Int): UdpPacket? {
        if (length < 28) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (length < ihl + 8) return null
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null

        val sourceIp = ByteBuffer.wrap(packet, 12, 4).int
        val destIp = ByteBuffer.wrap(packet, 16, 4).int
        val sourcePort = u16(packet, ihl)
        val destPort = u16(packet, ihl + 2)

        val udpLen = u16(packet, ihl + 4)
        if (udpLen < 8) return null
        val payloadLen = (udpLen - 8).coerceAtLeast(0)
        if (ihl + 8 + payloadLen > length) return null

        val payload = packet.copyOfRange(ihl + 8, ihl + 8 + payloadLen)
        return UdpPacket(
            sourceIp = sourceIp,
            destIp = destIp,
            sourcePort = sourcePort,
            destPort = destPort,
            payload = payload
        )
    }

    fun buildResponse(request: UdpPacket, response: UdpResponse): ByteArray {
        val ipHeaderLen = 20
        val udpLen = 8 + response.payload.size
        val totalLen = ipHeaderLen + udpLen
        val out = ByteArray(totalLen)

        out[0] = 0x45
        out[1] = 0x00
        out[2] = ((totalLen shr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[8] = 64
        out[9] = 17

        putInt(out, 12, response.sourceIp)
        putInt(out, 16, request.sourceIp)

        out[20] = ((response.sourcePort shr 8) and 0xFF).toByte()
        out[21] = (response.sourcePort and 0xFF).toByte()
        out[22] = ((request.sourcePort shr 8) and 0xFF).toByte()
        out[23] = (request.sourcePort and 0xFF).toByte()
        out[24] = ((udpLen shr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0
        out[27] = 0

        System.arraycopy(response.payload, 0, out, 28, response.payload.size)

        val csum = ipv4Checksum(out, 0, ipHeaderLen)
        out[10] = ((csum shr 8) and 0xFF).toByte()
        out[11] = (csum and 0xFF).toByte()
        return out
    }

    private fun u16(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    }

    private fun putInt(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = ((value ushr 24) and 0xFF).toByte()
        packet[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        packet[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        packet[offset + 3] = (value and 0xFF).toByte()
    }

    private fun ipv4Checksum(packet: ByteArray, offset: Int, len: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + len) {
            if (i == offset + 10) {
                i += 2
                continue
            }
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
            i += 2
        }
        return sum.inv() and 0xFFFF
    }
}
