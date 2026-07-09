package com.outshake.transport

import com.outshake.config.Cipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit

/**
 * End-to-end proof that the app's *actual* UDP transport ([ShadowsocksUdpCodec]) round-trips real
 * datagrams through a stock `ss-server` running with UDP enabled (`-u`). A local UDP echo target
 * stands in for a DNS/QUIC peer. Skips gracefully if `ss-server` is unavailable.
 */
class ShadowsocksUdpLiveTrafficTest {

    private fun ssServerBin(): String? =
        listOf("/usr/bin/ss-server", "/usr/local/bin/ss-server")
            .firstOrNull { java.io.File(it).canExecute() }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun waitForPort(port: Int, timeoutMs: Long) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200) }
                return
            } catch (_: Exception) {
                Thread.sleep(50)
            }
        }
        throw IllegalStateException("port $port never opened")
    }

    /** A UDP echo server that returns whatever bytes it receives. */
    private fun startUdpEcho(): Pair<DatagramSocket, Int> {
        val sock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        Thread {
            val buf = ByteArray(65535)
            try {
                while (!sock.isClosed) {
                    val dp = DatagramPacket(buf, buf.size)
                    sock.receive(dp)
                    sock.send(DatagramPacket(dp.data, dp.length, dp.address, dp.port))
                }
            } catch (_: Exception) { /* closed */ }
        }.apply { isDaemon = true; start() }
        return sock to sock.localPort
    }

    private fun runUdpRoundTrip(cipher: Cipher) {
        val bin = ssServerBin()
        assumeTrue("ss-server not installed; skipping UDP live traffic test", bin != null)

        val (echo, echoPort) = startUdpEcho()
        val ssPort = freePort()
        val password = "outshake-udp-pw"

        // -u enables UDP relay alongside TCP (NOT -U, which would make it UDP-only).
        val proc = ProcessBuilder(
            bin, "-s", "127.0.0.1", "-p", ssPort.toString(),
            "-k", password, "-m", cipher.id, "-u", "-v"
        ).redirectErrorStream(true).start()
        try {
            try {
                waitForPort(ssPort, 8000)
            } catch (e: Exception) {
                val avail = proc.inputStream.available()
                val log = if (avail > 0) proc.inputStream.readNBytes(avail).decodeToString() else "<none>"
                throw IllegalStateException("ss-server port $ssPort not up: ${e.message}; log=[$log]")
            }

            val masterKey = ShadowsocksCrypto.deriveMasterKey(password, cipher.keySize)
            val codec = ShadowsocksUdpCodec(cipher, masterKey)
            val payload = "OUTSHAKE-UDP-${System.nanoTime()}".toByteArray()

            val client = DatagramSocket()
            client.soTimeout = 5000
            val wire = codec.encode("127.0.0.1", echoPort, payload)
            client.send(DatagramPacket(wire, wire.size, InetAddress.getByName("127.0.0.1"), ssPort))

            val recvBuf = ByteArray(65535)
            val recv = DatagramPacket(recvBuf, recvBuf.size)
            client.receive(recv)
            val decoded = codec.decode(recv.data.copyOf(recv.length))!!
            client.close()

            assertArrayEquals(
                "UDP payload mismatch through relay (cipher=${cipher.id})", payload, decoded.payload
            )
            assertEquals("127.0.0.1", decoded.host)
            assertEquals(echoPort, decoded.port)
            println(
                "LIVE-UDP OK cipher=${cipher.id} sent=${payload.size}B wire=${wire.size}B " +
                    "echoedFrom=${decoded.host}:${decoded.port} via ss-server:$ssPort"
            )
        } finally {
            echo.close()
            proc.destroy()
            proc.waitFor(3, TimeUnit.SECONDS)
            if (proc.isAlive) proc.destroyForcibly()
        }
    }

    @Test
    fun `chacha20 real udp round-trip`() = runUdpRoundTrip(Cipher.CHACHA20_IETF_POLY1305)

    @Test
    fun `aes256gcm real udp round-trip`() = runUdpRoundTrip(Cipher.AES_256_GCM)
}
