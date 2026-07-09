package com.outshake.vpn

/** Minimal IPv4 + TCP/UDP packet parsing and construction for the userspace tun2socks engine. */
object Ip {
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun version(pkt: ByteArray): Int = (pkt[0].toInt() shr 4) and 0xF
    fun ihl(pkt: ByteArray): Int = (pkt[0].toInt() and 0xF) * 4
    fun protocol(pkt: ByteArray): Int = pkt[9].toInt() and 0xFF
    fun totalLength(pkt: ByteArray): Int = u16(pkt, 2)
    fun srcAddr(pkt: ByteArray): ByteArray = pkt.copyOfRange(12, 16)
    fun dstAddr(pkt: ByteArray): ByteArray = pkt.copyOfRange(16, 20)

    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
    fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
            ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

    fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v shr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    fun put32(b: ByteArray, off: Int, v: Long) {
        b[off] = ((v shr 24) and 0xFF).toByte()
        b[off + 1] = ((v shr 16) and 0xFF).toByte()
        b[off + 2] = ((v shr 8) and 0xFF).toByte()
        b[off + 3] = (v and 0xFF).toByte()
    }

    fun ipToString(a: ByteArray): String =
        "${a[0].toInt() and 0xFF}.${a[1].toInt() and 0xFF}.${a[2].toInt() and 0xFF}.${a[3].toInt() and 0xFF}"

    fun checksum(data: ByteArray, off: Int, len: Int, initial: Long = 0): Int {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) sum += ((data[i].toInt() and 0xFF) shl 8).toLong()
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}

/** TCP flag bits and field accessors relative to the start of the TCP header. */
object Tcp {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10

    fun srcPort(tcp: ByteArray, off: Int) = Ip.u16(tcp, off)
    fun dstPort(tcp: ByteArray, off: Int) = Ip.u16(tcp, off + 2)
    fun seq(tcp: ByteArray, off: Int) = Ip.u32(tcp, off + 4)
    fun ack(tcp: ByteArray, off: Int) = Ip.u32(tcp, off + 8)
    fun dataOffset(tcp: ByteArray, off: Int) = ((tcp[off + 12].toInt() shr 4) and 0xF) * 4
    fun flags(tcp: ByteArray, off: Int) = tcp[off + 13].toInt() and 0x3F
}

object Udp {
    fun srcPort(b: ByteArray, off: Int) = Ip.u16(b, off)
    fun dstPort(b: ByteArray, off: Int) = Ip.u16(b, off + 2)
    fun length(b: ByteArray, off: Int) = Ip.u16(b, off + 4)
}
