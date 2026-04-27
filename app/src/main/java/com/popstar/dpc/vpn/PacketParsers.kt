package com.popstar.dpc.vpn

import java.nio.ByteBuffer

object PacketParsers {
    data class ConnectionMetadata(
        val protocol: Int,
        val sourceIp: Int,
        val destIp: Int,
        val sourcePort: Int,
        val destPort: Int,
        val transportOffset: Int
    )

    fun extractConnectionMetadata(packet: ByteArray, length: Int): ConnectionMetadata? {
        val ipv4 = ipv4(packet, length) ?: return null
        val protocol = ipv4.protocol
        if (protocol != 6 && protocol != 17) return null
        if (length < ipv4.transportOffset + 4) return null

        val sourceIp = ByteBuffer.wrap(packet, 12, 4).int
        val destIp = ByteBuffer.wrap(packet, 16, 4).int
        val sourcePort = readU16(packet, ipv4.transportOffset)
        val destPort = readU16(packet, ipv4.transportOffset + 2)

        return ConnectionMetadata(
            protocol = protocol,
            sourceIp = sourceIp,
            destIp = destIp,
            sourcePort = sourcePort,
            destPort = destPort,
            transportOffset = ipv4.transportOffset
        )
    }

    fun extractDnsQueryHost(packet: ByteArray, length: Int): String? {
        if (length < 28) return null
        val meta = extractConnectionMetadata(packet, length) ?: return null
        if (meta.protocol != 17) return null
        if (meta.sourcePort != 53 && meta.destPort != 53) return null

        val dnsStart = meta.transportOffset + 8
        if (length < dnsStart + 12) return null
        val qdCount = readU16(packet, dnsStart + 4)
        if (qdCount <= 0) return null

        var index = dnsStart + 12
        val labels = mutableListOf<String>()
        while (index < length) {
            val size = packet[index].toInt() and 0xFF
            if (size and 0xC0 != 0) return null
            if (size > 63) return null
            if (size == 0) {
                return if (labels.isEmpty()) null else labels.joinToString(".").lowercase()
            }
            index += 1
            if (index + size > length) return null
            labels += packet.copyOfRange(index, index + size).toString(Charsets.US_ASCII)
            index += size
        }
        return null
    }

    fun extractTlsSniHost(packet: ByteArray, length: Int): String? {
        if (length < 40) return null
        val ipv4 = ipv4(packet, length) ?: return null
        if (ipv4.protocol != 6) return null // TCP only

        val tcpStart = ipv4.transportOffset
        if (tcpStart + 13 > length) return null
        val srcPort = readU16(packet, tcpStart)
        val dstPort = readU16(packet, tcpStart + 2)
        if (srcPort != 443 && dstPort != 443) return null

        val dataOffset = ((packet[tcpStart + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOffset < 20) return null
        val tlsStart = tcpStart + dataOffset
        if (tlsStart + 5 > length) return null

        val contentType = packet[tlsStart].toInt() and 0xFF
        if (contentType != 0x16) return null
        val recordLen = readU16(packet, tlsStart + 3)
        if (tlsStart + 5 + recordLen > length) return null

        val hsType = packet[tlsStart + 5].toInt() and 0xFF
        if (hsType != 0x01) return null // client hello

        val hsLen = ((packet[tlsStart + 6].toInt() and 0xFF) shl 16) or
            ((packet[tlsStart + 7].toInt() and 0xFF) shl 8) or
            (packet[tlsStart + 8].toInt() and 0xFF)
        var idx = tlsStart + 9
        val hsEnd = idx + hsLen
        if (hsEnd > length) return null

        idx += 2 + 32 // version + random
        if (idx >= hsEnd) return null
        val sessionIdLen = packet[idx].toInt() and 0xFF
        idx += 1 + sessionIdLen
        if (idx + 2 > hsEnd) return null

        val cipherLen = readU16(packet, idx)
        idx += 2 + cipherLen
        if (idx >= hsEnd) return null

        val compLen = packet[idx].toInt() and 0xFF
        idx += 1 + compLen
        if (idx + 2 > hsEnd) return null

        val extLen = readU16(packet, idx)
        idx += 2
        val extEnd = idx + extLen
        if (extEnd > hsEnd) return null

        while (idx + 4 <= extEnd) {
            val extType = readU16(packet, idx)
            val extSize = readU16(packet, idx + 2)
            idx += 4
            if (idx + extSize > extEnd) return null
            if (extType == 0x0000) {
                if (idx + 2 > extEnd) return null
                val listLen = readU16(packet, idx)
                var listIdx = idx + 2
                val listEnd = listIdx + listLen
                if (listEnd > extEnd) return null
                while (listIdx + 3 <= listEnd) {
                    val nameType = packet[listIdx].toInt() and 0xFF
                    val nameLen = readU16(packet, listIdx + 1)
                    listIdx += 3
                    if (listIdx + nameLen > listEnd) return null
                    if (nameType == 0) {
                        return packet.copyOfRange(listIdx, listIdx + nameLen)
                            .toString(Charsets.US_ASCII)
                            .lowercase()
                    }
                    listIdx += nameLen
                }
            }
            idx += extSize
        }
        return null
    }

    private fun ipv4(packet: ByteArray, length: Int): Ipv4? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20) return null
        if (length < ihl + 8) return null
        val protocol = packet[9].toInt() and 0xFF
        return Ipv4(ihl, protocol)
    }

    private fun readU16(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    }

    private data class Ipv4(val transportOffset: Int, val protocol: Int)
}
