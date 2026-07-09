package com.outshake.vpn

/** Builds IPv4 TCP/UDP packets to write back into the TUN device. */
object PacketBuilder {

    /** Build an IPv4/TCP segment. [srcAddr]/[dstAddr] are the packet's src/dst (i.e. remote->local). */
    fun tcp(
        srcAddr: ByteArray, srcPort: Int,
        dstAddr: ByteArray, dstPort: Int,
        seq: Long, ack: Long, flags: Int,
        window: Int,
        payload: ByteArray? = null,
    ): ByteArray {
        val dataLen = payload?.size ?: 0
        val ipHeaderLen = 20
        val tcpHeaderLen = 20
        val total = ipHeaderLen + tcpHeaderLen + dataLen
        val pkt = ByteArray(total)

        // IPv4 header
        pkt[0] = 0x45
        pkt[1] = 0
        Ip.put16(pkt, 2, total)
        Ip.put16(pkt, 4, 0)          // id
        Ip.put16(pkt, 6, 0x4000)     // don't fragment
        pkt[8] = 64                  // ttl
        pkt[9] = Ip.PROTO_TCP.toByte()
        System.arraycopy(srcAddr, 0, pkt, 12, 4)
        System.arraycopy(dstAddr, 0, pkt, 16, 4)
        Ip.put16(pkt, 10, 0)
        Ip.put16(pkt, 10, Ip.checksum(pkt, 0, ipHeaderLen))

        // TCP header
        val t = ipHeaderLen
        Ip.put16(pkt, t, srcPort)
        Ip.put16(pkt, t + 2, dstPort)
        Ip.put32(pkt, t + 4, seq)
        Ip.put32(pkt, t + 8, ack)
        pkt[t + 12] = (5 shl 4).toByte() // data offset = 5 words
        pkt[t + 13] = flags.toByte()
        Ip.put16(pkt, t + 14, window)
        Ip.put16(pkt, t + 16, 0)     // checksum placeholder
        Ip.put16(pkt, t + 18, 0)     // urgent
        if (payload != null) System.arraycopy(payload, 0, pkt, t + tcpHeaderLen, dataLen)

        Ip.put16(pkt, t + 16, tcpChecksum(pkt, srcAddr, dstAddr, t, tcpHeaderLen + dataLen))
        return pkt
    }

    /** Build an IPv4/UDP datagram (remote->local). */
    fun udp(
        srcAddr: ByteArray, srcPort: Int,
        dstAddr: ByteArray, dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val ipHeaderLen = 20
        val udpLen = 8 + payload.size
        val total = ipHeaderLen + udpLen
        val pkt = ByteArray(total)

        pkt[0] = 0x45
        Ip.put16(pkt, 2, total)
        Ip.put16(pkt, 6, 0x4000)
        pkt[8] = 64
        pkt[9] = Ip.PROTO_UDP.toByte()
        System.arraycopy(srcAddr, 0, pkt, 12, 4)
        System.arraycopy(dstAddr, 0, pkt, 16, 4)
        Ip.put16(pkt, 10, Ip.checksum(pkt, 0, ipHeaderLen))

        val u = ipHeaderLen
        Ip.put16(pkt, u, srcPort)
        Ip.put16(pkt, u + 2, dstPort)
        Ip.put16(pkt, u + 4, udpLen)
        Ip.put16(pkt, u + 6, 0)
        System.arraycopy(payload, 0, pkt, u + 8, payload.size)
        Ip.put16(pkt, u + 6, udpChecksum(pkt, srcAddr, dstAddr, u, udpLen))
        return pkt
    }

    private fun tcpChecksum(pkt: ByteArray, src: ByteArray, dst: ByteArray, off: Int, len: Int): Int {
        val pseudo = pseudoHeaderSum(src, dst, Ip.PROTO_TCP, len)
        val cs = Ip.checksum(pkt, off, len, pseudo)
        return if (cs == 0) 0xFFFF else cs
    }

    private fun udpChecksum(pkt: ByteArray, src: ByteArray, dst: ByteArray, off: Int, len: Int): Int {
        val pseudo = pseudoHeaderSum(src, dst, Ip.PROTO_UDP, len)
        val cs = Ip.checksum(pkt, off, len, pseudo)
        return if (cs == 0) 0xFFFF else cs
    }

    private fun pseudoHeaderSum(src: ByteArray, dst: ByteArray, proto: Int, len: Int): Long {
        var sum = 0L
        sum += (((src[0].toInt() and 0xFF) shl 8) or (src[1].toInt() and 0xFF)).toLong()
        sum += (((src[2].toInt() and 0xFF) shl 8) or (src[3].toInt() and 0xFF)).toLong()
        sum += (((dst[0].toInt() and 0xFF) shl 8) or (dst[1].toInt() and 0xFF)).toLong()
        sum += (((dst[2].toInt() and 0xFF) shl 8) or (dst[3].toInt() and 0xFF)).toLong()
        sum += proto.toLong()
        sum += len.toLong()
        return sum
    }
}
