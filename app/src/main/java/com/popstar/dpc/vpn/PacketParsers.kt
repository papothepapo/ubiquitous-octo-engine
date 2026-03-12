package com.popstar.dpc.vpn

object PacketParsers {
    fun extractDnsQueryHost(packet: ByteArray, length: Int): String? {
        if (length < 28) return null
        val ipv4 = ipv4(packet, length) ?: return null
        if (ipv4.protocol != 17) return null // UDP only

        val srcPort = readU16(packet, ipv4.transportOffset)
        val dstPort = readU16(packet, ipv4.transportOffset + 2)
        if (srcPort != 53 && dstPort != 53) return null

        val dnsStart = ipv4.transportOffset + 8
        if (length < dnsStart + 12) return null
        val qdCount = readU16(packet, dnsStart + 4)
        if (qdCount <= 0) return null

        var index = dnsStart + 12
        val labels = mutableListOf<String>()
        while (index < length) {
            val size = packet[index].toInt() and 0xFF
            if (size == 0) break
            if (size > 63 || index + size >= length) return null
            labels.add(packet.copyOfRange(index + 1, index + 1 + size).toString(Charsets.US_ASCII))
            index += 1 + size
        }
        if (labels.isEmpty()) return null
        return labels.joinToString(".").lowercase()
    }

    fun extractTlsSniHost(packet: ByteArray, length: Int): String? {
        val ipv4 = ipv4(packet, length) ?: return null
        if (ipv4.protocol != 6) return null // TCP only

        val srcPort = readU16(packet, ipv4.transportOffset)
        val dstPort = readU16(packet, ipv4.transportOffset + 2)
        if (srcPort != 443 && dstPort != 443) return null

        val dataOffsetWords = (packet[ipv4.transportOffset + 12].toInt() ushr 4) and 0x0F
        val tcpHeaderLength = dataOffsetWords * 4
        val payloadOffset = ipv4.transportOffset + tcpHeaderLength
        if (payloadOffset + 5 >= length) return null

        // TLS handshake record
        if ((packet[payloadOffset].toInt() and 0xFF) != 0x16) return null
        // Client Hello handshake type
        if ((packet[payloadOffset + 5].toInt() and 0xFF) != 0x01) return null

        var idx = payloadOffset + 9 // handshake header + version
        idx += 32 // random
        if (idx >= length) return null

        val sessionIdLen = packet[idx].toInt() and 0xFF
        idx += 1 + sessionIdLen
        if (idx + 2 >= length) return null

        val cipherSuitesLen = readU16(packet, idx)
        idx += 2 + cipherSuitesLen
        if (idx >= length) return null

        val compressionLen = packet[idx].toInt() and 0xFF
        idx += 1 + compressionLen
        if (idx + 2 >= length) return null

        val extensionsLen = readU16(packet, idx)
        idx += 2
        val extEnd = (idx + extensionsLen).coerceAtMost(length)

        while (idx + 4 <= extEnd) {
            val extType = readU16(packet, idx)
            val extLen = readU16(packet, idx + 2)
            idx += 4
            if (idx + extLen > extEnd) return null
            if (extType == 0x0000) { // server_name
                if (extLen < 5) return null
                val listLen = readU16(packet, idx)
                var listIdx = idx + 2
                val listEnd = (listIdx + listLen).coerceAtMost(idx + extLen)
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
            idx += extLen
        }
        return null
    }

    private fun ipv4(packet: ByteArray, length: Int): Ipv4? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (length < ihl + 8) return null
        val protocol = packet[9].toInt() and 0xFF
        return Ipv4(ihl, protocol)
    }

    private fun readU16(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    }

    private data class Ipv4(val transportOffset: Int, val protocol: Int)
}
