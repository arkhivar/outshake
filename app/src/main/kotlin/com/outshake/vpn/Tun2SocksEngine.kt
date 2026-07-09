package com.outshake.vpn

import android.util.Log
import com.outshake.transport.ShadowsocksClient
import com.outshake.transport.ShadowsocksUdpCodec
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

/** Protects sockets from being routed back into the VPN (VpnService.protect). */
interface SocketProtector {
    fun protect(socket: Socket): Boolean
    fun protect(socket: DatagramSocket): Boolean
}

private const val TAG = "Tun2Socks"
private const val MASK = 0xFFFFFFFFL
private const val MSS = 1400
private const val WINDOW = 65535
private const val UDP_IDLE_MS = 60_000L        // drop a UDP flow after 60s idle
private const val UDP_SWEEP_MS = 15_000L       // eviction sweep interval
private const val DNS_FALLBACK_MS = 1_500L     // if no UDP DNS reply, retry over TCP
private const val UDP_MAX_DATAGRAM = 65535

/**
 * A pragmatic userspace tun2socks: parses IPv4 packets from the TUN device and tunnels TCP and UDP
 * flows through a Shadowsocks server. Designed for the lossless local TUN link, so it does not
 * implement TCP retransmission or congestion control. UDP is relayed per the Shadowsocks AEAD UDP
 * spec (fresh salt per datagram); DNS is sent over UDP with a TCP fallback for UDP-disabled servers.
 */
class Tun2SocksEngine(
    private val tunIn: FileInputStream,
    private val tunOut: FileOutputStream,
    private val client: ShadowsocksClient,
    private val protector: SocketProtector,
) {
    private val running = AtomicBoolean(false)
    private val sessions = ConcurrentHashMap<String, TcpSession>()
    private val udpSessions = UdpNatTable<UdpSession>(UDP_IDLE_MS)
    private val udpCodec: ShadowsocksUdpCodec = client.udpCodec()
    private val pool = Executors.newCachedThreadPool()
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private val writeLock = Any()

    fun writeToTun(pkt: ByteArray) {
        synchronized(writeLock) {
            try {
                tunOut.write(pkt)
                tunOut.flush()
            } catch (e: Exception) {
                Log.w(TAG, "tun write failed: ${e.message}")
            }
        }
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        pool.execute { readLoop() }
        scheduler.scheduleWithFixedDelay({
            try {
                udpSessions.evictExpired(System.currentTimeMillis()).forEach { it.close() }
            } catch (e: Exception) {
                Log.w(TAG, "udp eviction error: ${e.message}")
            }
        }, UDP_SWEEP_MS, UDP_SWEEP_MS, TimeUnit.MILLISECONDS)
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        sessions.values.forEach { it.close(sendRst = false) }
        sessions.clear()
        udpSessions.values().forEach { it.close() }
        scheduler.shutdownNow()
        pool.shutdownNow()
    }

    private fun readLoop() {
        val buf = ByteArray(32767)
        while (running.get()) {
            val n = try {
                tunIn.read(buf)
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "tun read ended: ${e.message}")
                break
            }
            if (n <= 0) continue
            val pkt = buf.copyOf(n)
            try {
                if (Ip.version(pkt) != 4) continue
                when (Ip.protocol(pkt)) {
                    Ip.PROTO_TCP -> handleTcp(pkt)
                    Ip.PROTO_UDP -> handleUdp(pkt)
                }
            } catch (e: Exception) {
                Log.w(TAG, "packet handling error: ${e.message}")
            }
        }
    }

    // ------------------------------------------------------------------ TCP
    private fun handleTcp(pkt: ByteArray) {
        val ihl = Ip.ihl(pkt)
        val src = Ip.srcAddr(pkt)
        val dst = Ip.dstAddr(pkt)
        val srcPort = Tcp.srcPort(pkt, ihl)
        val dstPort = Tcp.dstPort(pkt, ihl)
        val seq = Tcp.seq(pkt, ihl)
        val ack = Tcp.ack(pkt, ihl)
        val flags = Tcp.flags(pkt, ihl)
        val dataOff = ihl + Tcp.dataOffset(pkt, ihl)
        val payload = if (pkt.size > dataOff) pkt.copyOfRange(dataOff, Ip.totalLength(pkt)) else ByteArray(0)

        val key = "${Ip.ipToString(src)}:$srcPort-${Ip.ipToString(dst)}:$dstPort"

        if (flags and Tcp.SYN != 0 && flags and Tcp.ACK == 0) {
            // New connection.
            sessions.remove(key)?.close(sendRst = false)
            val session = TcpSession(key, src, srcPort, dst, dstPort)
            sessions[key] = session
            session.onSyn(seq)
            return
        }
        val session = sessions[key]
        if (session == null) {
            if (flags and Tcp.RST == 0) {
                // Unknown flow — reset it.
                writeToTun(PacketBuilder.tcp(dst, dstPort, src, srcPort, ack, (seq + payload.size) and MASK, Tcp.RST or Tcp.ACK, 0))
            }
            return
        }
        session.onSegment(seq, ack, flags, payload)
    }

    private inner class TcpSession(
        val key: String,
        val localAddr: ByteArray, val localPort: Int,   // app side
        val remoteAddr: ByteArray, val remotePort: Int, // target side
    ) {
        private var myseq = Random.nextLong(0, MASK)     // our send sequence
        private var theirSeq = 0L                        // next expected byte from app
        private var conn: com.outshake.transport.ShadowsocksTcpConnection? = null
        private val pending = ArrayList<ByteArray>()
        private val stateLock = Any()
        private val closed = AtomicBoolean(false)
        private var established = false

        fun onSyn(clientIsn: Long) {
            theirSeq = (clientIsn + 1) and MASK
            // Send SYN|ACK
            sendCtl(Tcp.SYN or Tcp.ACK)
            myseq = (myseq + 1) and MASK
            pool.execute { openUpstream() }
        }

        private fun openUpstream() {
            try {
                val socket = Socket()
                if (!protector.protect(socket)) Log.w(TAG, "protect() failed for $key")
                socket.connect(InetSocketAddress(client.serverHost, client.serverPort), 15000)
                val c = client.connect(socket, Ip.ipToString(remoteAddr), remotePort)
                synchronized(stateLock) {
                    conn = c
                    pending.forEach { c.write(it, 0, it.size) }
                    pending.clear()
                }
                pumpUpstreamToTun(c)
            } catch (e: Exception) {
                Log.w(TAG, "upstream connect failed for $key: ${e.message}")
                close(sendRst = true)
            }
        }

        private fun pumpUpstreamToTun(c: com.outshake.transport.ShadowsocksTcpConnection) {
            try {
                while (!closed.get()) {
                    val chunk = c.read() ?: break
                    var off = 0
                    while (off < chunk.size) {
                        val n = minOf(MSS, chunk.size - off)
                        val seg = chunk.copyOfRange(off, off + n)
                        synchronized(stateLock) {
                            writeToTun(build(Tcp.PSH or Tcp.ACK, seg))
                            myseq = (myseq + n) and MASK
                        }
                        off += n
                    }
                }
                // Upstream EOF -> FIN toward app.
                synchronized(stateLock) {
                    if (!closed.get()) {
                        writeToTun(build(Tcp.FIN or Tcp.ACK, null))
                        myseq = (myseq + 1) and MASK
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "upstream read ended for $key: ${e.message}")
                close(sendRst = true)
            }
        }

        fun onSegment(seq: Long, ack: Long, flags: Int, payload: ByteArray) {
            if (flags and Tcp.RST != 0) {
                close(sendRst = false)
                return
            }
            if (flags and Tcp.SYN != 0) return
            if (!established && flags and Tcp.ACK != 0) established = true

            if (payload.isNotEmpty()) {
                when {
                    seq == theirSeq -> {
                        theirSeq = (theirSeq + payload.size) and MASK
                        forwardToUpstream(payload)
                        sendCtl(Tcp.ACK)
                    }
                    else -> sendCtl(Tcp.ACK) // retransmit or reorder: re-ACK expected
                }
            }
            if (flags and Tcp.FIN != 0) {
                theirSeq = (theirSeq + 1) and MASK
                sendCtl(Tcp.ACK)
                // Half-close upstream write by closing the connection after draining.
                close(sendRst = false)
            }
        }

        private fun forwardToUpstream(payload: ByteArray) {
            synchronized(stateLock) {
                val c = conn
                if (c == null) pending.add(payload) else c.write(payload, 0, payload.size)
            }
        }

        private fun sendCtl(flags: Int) {
            synchronized(stateLock) { writeToTun(build(flags, null)) }
        }

        private fun build(flags: Int, payload: ByteArray?): ByteArray =
            PacketBuilder.tcp(remoteAddr, remotePort, localAddr, localPort, myseq, theirSeq, flags, WINDOW, payload)

        fun close(sendRst: Boolean) {
            if (!closed.compareAndSet(false, true)) return
            if (sendRst) {
                synchronized(stateLock) { writeToTun(build(Tcp.RST or Tcp.ACK, null)) }
            }
            try { conn?.close() } catch (_: Exception) {}
            sessions.remove(key)
        }
    }

    // ------------------------------------------------------------------ UDP
    private fun handleUdp(pkt: ByteArray) {
        val ihl = Ip.ihl(pkt)
        val src = Ip.srcAddr(pkt)
        val dst = Ip.dstAddr(pkt)
        val srcPort = Udp.srcPort(pkt, ihl)
        val dstPort = Udp.dstPort(pkt, ihl)
        val udpLen = Udp.length(pkt, ihl)
        if (udpLen < 8 || ihl + udpLen > pkt.size) return
        val dataOff = ihl + 8
        val payload = pkt.copyOfRange(dataOff, dataOff + (udpLen - 8))

        val key = "${Ip.ipToString(src)}:$srcPort"
        val now = System.currentTimeMillis()
        val session = udpSessions.getOrCreate(key, now) { UdpSession(key, src, srcPort) }
        session.send(dst, dstPort, payload)
    }

    /**
     * One relay session per app-side UDP endpoint. A single protected [DatagramSocket] to the
     * Shadowsocks server carries datagrams to any number of targets (each SS UDP packet embeds its
     * own target address); replies are decrypted and written back to the TUN as the origin endpoint.
     */
    private inner class UdpSession(
        private val key: String,
        private val localAddr: ByteArray,
        private val localPort: Int,
    ) {
        private val socket = DatagramSocket()
        private val closed = AtomicBoolean(false)
        // DNS transaction ids awaiting a UDP reply; each has a scheduled TCP-fallback task.
        private val pendingDns = ConcurrentHashMap<Int, java.util.concurrent.ScheduledFuture<*>>()

        init {
            protector.protect(socket)
            socket.connect(InetSocketAddress(client.serverHost, client.serverPort))
            pool.execute { receiveLoop() }
        }

        fun send(dstAddr: ByteArray, dstPort: Int, payload: ByteArray) {
            if (closed.get()) return
            udpSessions.touch(key, System.currentTimeMillis())
            try {
                val wire = udpCodec.encode(Ip.ipToString(dstAddr), dstPort, payload)
                socket.send(DatagramPacket(wire, wire.size))
                if (dstPort == 53) armDnsFallback(dstAddr, payload)
            } catch (e: Exception) {
                Log.w(TAG, "udp send failed for $key: ${e.message}")
            }
        }

        private fun receiveLoop() {
            val buf = ByteArray(UDP_MAX_DATAGRAM)
            while (!closed.get()) {
                val dp = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(dp)
                } catch (e: Exception) {
                    break
                }
                udpSessions.touch(key, System.currentTimeMillis())
                try {
                    val decoded = udpCodec.decode(dp.data.copyOf(dp.length)) ?: continue
                    val originAddr = InetAddress.getByName(decoded.host).address
                    if (decoded.port == 53) cancelDnsFallback(decoded.payload)
                    writeToTun(
                        PacketBuilder.udp(originAddr, decoded.port, localAddr, localPort, decoded.payload)
                    )
                } catch (e: Exception) {
                    Log.w(TAG, "udp reply decode failed for $key: ${e.message}")
                }
            }
        }

        /** If no UDP DNS reply arrives in time, resolve the query over the reliable TCP path. */
        private fun armDnsFallback(dstAddr: ByteArray, query: ByteArray) {
            val txid = dnsTxId(query) ?: return
            if (pendingDns.containsKey(txid)) return
            val task = scheduler.schedule({
                if (pendingDns.remove(txid) == null || closed.get()) return@schedule
                try {
                    val resp = dnsOverTcp(dstAddr, query)
                    if (resp != null && !closed.get()) {
                        writeToTun(PacketBuilder.udp(dstAddr, 53, localAddr, localPort, resp))
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "DNS TCP fallback failed: ${e.message}")
                }
            }, DNS_FALLBACK_MS, TimeUnit.MILLISECONDS)
            pendingDns[txid] = task
        }

        private fun cancelDnsFallback(reply: ByteArray) {
            val txid = dnsTxId(reply) ?: return
            pendingDns.remove(txid)?.cancel(false)
        }

        fun close() {
            if (!closed.compareAndSet(false, true)) return
            pendingDns.values.forEach { it.cancel(false) }
            pendingDns.clear()
            try { socket.close() } catch (_: Exception) {}
            udpSessions.remove(key)
        }
    }

    private fun dnsTxId(dns: ByteArray): Int? =
        if (dns.size >= 2) ((dns[0].toInt() and 0xFF) shl 8) or (dns[1].toInt() and 0xFF) else null

    private fun dnsOverTcp(dstAddr: ByteArray, query: ByteArray): ByteArray? {
        val socket = Socket()
        protector.protect(socket)
        socket.connect(InetSocketAddress(client.serverHost, client.serverPort), 10000)
        val c = client.connect(socket, Ip.ipToString(dstAddr), 53)
        try {
            val framed = ByteArray(query.size + 2)
            framed[0] = ((query.size shr 8) and 0xFF).toByte()
            framed[1] = (query.size and 0xFF).toByte()
            System.arraycopy(query, 0, framed, 2, query.size)
            c.write(framed, 0, framed.size)
            return readDnsResponse(c)
        } finally {
            c.close()
        }
    }

    private fun readDnsResponse(c: com.outshake.transport.ShadowsocksTcpConnection): ByteArray? {
        val acc = java.io.ByteArrayOutputStream()
        while (acc.size() < 2) {
            val chunk = c.read() ?: return null
            acc.write(chunk)
        }
        val bytes = acc.toByteArray()
        val len = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
        val body = java.io.ByteArrayOutputStream()
        body.write(bytes, 2, bytes.size - 2)
        while (body.size() < len) {
            val chunk = c.read() ?: break
            body.write(chunk)
        }
        val out = body.toByteArray()
        return if (out.size >= len) out.copyOf(len) else out
    }
}
