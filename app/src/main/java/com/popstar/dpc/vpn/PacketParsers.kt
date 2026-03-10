package com.popstar.dpc.vpn

object PacketParsers {
    fun extractDnsQueryHost(packet: ByteArray, length: Int): String? {
        if (length < 28) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (length < ihl + 12) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null // UDP only

        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        if (srcPort != 53 && dstPort != 53) return null

        val dnsStart = ihl + 8
        if (length < dnsStart + 12) return null
        val qdCount = ((packet[dnsStart + 4].toInt() and 0xFF) shl 8) or (packet[dnsStart + 5].toInt() and 0xFF)
        if (qdCount <= 0) return null

        var index = dnsStart + 12
        val labels = mutableListOf<String>()
        while (index < length) {
            val size = packet[index].toInt() and 0xFF
            if (size == 0) {
                index++
                break
            }
            if (size > 63 || index + size >= length) return null
            val label = packet.copyOfRange(index + 1, index + 1 + size).toString(Charsets.US_ASCII)
            labels.add(label)
            index += 1 + size
        }
        if (labels.isEmpty()) return null
        return labels.joinToString(".").lowercase()
    }
}
