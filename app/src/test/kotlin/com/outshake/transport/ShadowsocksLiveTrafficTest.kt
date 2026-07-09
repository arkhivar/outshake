package com.outshake.transport

import com.outshake.config.Cipher
import com.outshake.config.TransportConfig
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit

/**
 * End-to-end proof that the app's *actual* Shadowsocks transport code moves real bytes through a
 * real Shadowsocks server. Spawns a stock `ss-server` (shadowsocks-libev) and a local HTTP target,
 * then drives [ShadowsocksClient] exactly as [com.outshake.vpn.OutshakeVpnService] does. Runs with
 * and without a salt prefix and across ciphers. Skips gracefully if `ss-server` is unavailable.
 */
class ShadowsocksLiveTrafficTest {

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

    /** Minimal one-shot HTTP target that serves a known body; returns [port, tokenBody, thread]. */
    private fun startHttpTarget(token: String): Triple<Int, String, Thread> {
        val server = ServerSocket(0)
        val port = server.localPort
        val body = "OUTSHAKE-OK-$token"
        val t = Thread {
            try {
                while (!server.isClosed) {
                    val c = server.accept()
                    c.getInputStream().read(ByteArray(4096)) // consume request line/headers (best effort)
                    val resp = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n" +
                        "Connection: close\r\n\r\n$body"
                    c.getOutputStream().write(resp.toByteArray())
                    c.getOutputStream().flush()
                    c.close()
                }
            } catch (_: Exception) { /* server closed */ }
        }.apply { isDaemon = true; start() }
        // stash the ServerSocket on the thread so caller can close via interrupt path
        openTargets += server
        return Triple(port, body, t)
    }

    private val openTargets = mutableListOf<ServerSocket>()

    private fun fetchThroughProxy(
        config: TransportConfig,
        targetHost: String,
        targetPort: Int,
        request: String,
    ): String {
        val socket = Socket()
        socket.connect(InetSocketAddress(config.host, config.port), 3000)
        socket.soTimeout = 5000
        val conn = ShadowsocksClient(config).connect(socket, targetHost, targetPort)
        val reqBytes = request.toByteArray()
        conn.write(reqBytes, 0, reqBytes.size)
        val out = ByteArrayOutputStream()
        try {
            while (true) {
                val chunk = conn.read() ?: break
                out.write(chunk)
            }
        } catch (_: Exception) { /* server closed the stream */ }
        conn.close()
        return String(out.toByteArray())
    }

    private fun runServerAndFetch(cipher: Cipher, prefix: ByteArray?) {
        val bin = ssServerBin()
        assumeTrue("ss-server not installed; skipping live traffic test", bin != null)

        val token = System.nanoTime().toString()
        val (targetPort, expectedBody, _) = startHttpTarget(token)
        val ssPort = freePort()
        val password = "outshake-test-pw"

        val proc = ProcessBuilder(
            bin, "-s", "127.0.0.1", "-p", ssPort.toString(),
            "-k", password, "-m", cipher.id, "-v"
        ).redirectErrorStream(true).start()
        try {
            try {
                waitForPort(ssPort, 8000)
            } catch (e: Exception) {
                val avail = proc.inputStream.available()
                val log = if (avail > 0) proc.inputStream.readNBytes(avail).decodeToString() else "<none>"
                throw IllegalStateException("ss-server port $ssPort not up: ${e.message}; log=[$log]")
            }
            val config = TransportConfig(
                host = "127.0.0.1", port = ssPort, cipher = cipher,
                password = password, prefix = prefix,
            )
            val request = "GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
            val response = fetchThroughProxy(config, "127.0.0.1", targetPort, request)

            assertTrue(
                "expected body '$expectedBody' not found through proxy (cipher=${cipher.id}, " +
                    "prefix=${prefix?.size ?: 0}B). Got: ${response.take(200)}",
                response.contains(expectedBody)
            )
            println(
                "LIVE-TRAFFIC OK cipher=${cipher.id} prefix=${prefix?.size ?: 0}B " +
                    "wireBytesIn=${response.length} body='$expectedBody' via ss-server:$ssPort"
            )
        } finally {
            proc.destroy()
            proc.waitFor(3, TimeUnit.SECONDS)
            if (proc.isAlive) proc.destroyForcibly()
            openTargets.forEach { runCatching { it.close() } }
            openTargets.clear()
        }
    }

    @Test
    fun `chacha20 real traffic without prefix`() =
        runServerAndFetch(Cipher.CHACHA20_IETF_POLY1305, null)

    @Test
    fun `chacha20 real traffic with prefix`() =
        runServerAndFetch(
            Cipher.CHACHA20_IETF_POLY1305,
            byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x00) // TLS-ClientHello-looking prefix
        )

    @Test
    fun `aes256gcm real traffic without prefix`() =
        runServerAndFetch(Cipher.AES_256_GCM, null)

    @Test
    fun `aes256gcm real traffic with prefix`() =
        runServerAndFetch(Cipher.AES_256_GCM, byteArrayOf(0x05, 0x0a, 0x0f, 0x14))
}
