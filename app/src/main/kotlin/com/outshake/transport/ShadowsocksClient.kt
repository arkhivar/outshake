package com.outshake.transport

import com.outshake.config.TransportConfig
import java.io.BufferedInputStream
import java.io.OutputStream
import java.net.Socket

/**
 * A live Shadowsocks TCP connection to a target host:port, tunneled through the SS server.
 * The caller supplies an already-connected (and, on Android, VpnService-protected) socket.
 */
class ShadowsocksTcpConnection(
    private val socket: Socket,
    private val encryptor: ShadowsocksEncryptor,
    private val decryptor: ShadowsocksDecryptor,
    private val out: OutputStream,
) {
    fun write(data: ByteArray, offset: Int, length: Int) {
        if (length <= 0) return
        out.write(encryptor.encrypt(data, offset, length))
        out.flush()
    }

    fun read(): ByteArray? = decryptor.readChunk()

    fun close() {
        try { socket.close() } catch (_: Exception) {}
    }
}

/** Creates prefix-aware Shadowsocks connections for a given transport config. */
class ShadowsocksClient(private val config: TransportConfig) {

    private val masterKey: ByteArray =
        ShadowsocksCrypto.deriveMasterKey(config.password, config.cipher.keySize)

    val serverHost: String get() = config.host
    val serverPort: Int get() = config.port

    /**
     * Perform the Shadowsocks handshake over [socket] and set up encryption toward [targetHost]:[targetPort].
     * The salt (prefixed if configured) plus the target address header are written immediately.
     */
    fun connect(socket: Socket, targetHost: String, targetPort: Int): ShadowsocksTcpConnection {
        val out = socket.getOutputStream()
        val input = BufferedInputStream(socket.getInputStream())
        val encryptor = ShadowsocksEncryptor(config.cipher, masterKey, config.prefix)
        val decryptor = ShadowsocksDecryptor(config.cipher, masterKey, input)

        val header = SocksAddress.build(targetHost, targetPort)
        out.write(encryptor.encrypt(header, 0, header.size))
        out.flush()
        return ShadowsocksTcpConnection(socket, encryptor, decryptor, out)
    }
}
