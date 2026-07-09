package com.outshake.transport

import com.outshake.config.Cipher
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

/**
 * Encrypts a Shadowsocks TCP stream: writes the salt (optionally prefixed) on first use,
 * then AEAD length+payload chunks. Prefix bytes overwrite the head of the salt, matching
 * Outline's PrefixSaltGenerator semantics.
 */
class ShadowsocksEncryptor(
    private val cipher: Cipher,
    private val masterKey: ByteArray,
    prefix: ByteArray?,
    random: SecureRandom = SecureRandom(),
) {
    val salt: ByteArray = ByteArray(cipher.saltSize).also { random.nextBytes(it) }
    private val subkey: ByteArray
    private val nonce = ByteArray(12)
    private var saltSent = false

    init {
        if (prefix != null) {
            if (prefix.size > cipher.saltSize) {
                throw IllegalArgumentException(
                    "Prefix (${prefix.size} bytes) is longer than the ${cipher.saltSize}-byte salt"
                )
            }
            System.arraycopy(prefix, 0, salt, 0, prefix.size)
        }
        subkey = ShadowsocksCrypto.hkdfSha1(masterKey, salt, cipher.keySize)
    }

    /** Encrypt [data] (<= MAX_PAYLOAD per call recommended) into wire bytes, prefixing the salt once. */
    fun encrypt(data: ByteArray, offset: Int, length: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        if (!saltSent) {
            out.write(salt)
            saltSent = true
        }
        var pos = offset
        val end = offset + length
        while (pos < end) {
            val n = minOf(ShadowsocksCrypto.MAX_PAYLOAD, end - pos)
            val lenBytes = byteArrayOf(((n shr 8) and 0xFF).toByte(), (n and 0xFF).toByte())
            out.write(ShadowsocksCrypto.seal(cipher, subkey, nonce, lenBytes))
            ShadowsocksCrypto.incrementNonce(nonce)
            out.write(ShadowsocksCrypto.seal(cipher, subkey, nonce, data.copyOfRange(pos, pos + n)))
            ShadowsocksCrypto.incrementNonce(nonce)
            pos += n
        }
        return out.toByteArray()
    }
}

/** Decrypts a Shadowsocks TCP stream read from [source]. Reads the salt lazily on first read. */
class ShadowsocksDecryptor(
    private val cipher: Cipher,
    private val masterKey: ByteArray,
    private val source: InputStream,
) {
    private var subkey: ByteArray? = null
    private val nonce = ByteArray(12)

    private fun ensureInit() {
        if (subkey != null) return
        val salt = readFully(cipher.saltSize)
        subkey = ShadowsocksCrypto.hkdfSha1(masterKey, salt, cipher.keySize)
    }

    /** Read and decrypt the next payload chunk, or null at clean end of stream. */
    fun readChunk(): ByteArray? {
        ensureInit()
        val key = subkey!!
        val lenCipher = try {
            readFully(2 + cipher.tagSize)
        } catch (e: EOFException) {
            return null
        }
        val lenBytes = ShadowsocksCrypto.open(cipher, key, nonce, lenCipher)
        ShadowsocksCrypto.incrementNonce(nonce)
        val payloadLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        if (payloadLen == 0 || payloadLen > ShadowsocksCrypto.MAX_PAYLOAD) {
            throw IllegalStateException("Invalid Shadowsocks chunk length: $payloadLen")
        }
        val payloadCipher = readFully(payloadLen + cipher.tagSize)
        val plain = ShadowsocksCrypto.open(cipher, key, nonce, payloadCipher)
        ShadowsocksCrypto.incrementNonce(nonce)
        return plain
    }

    private fun readFully(n: Int): ByteArray {
        val buf = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = source.read(buf, read, n - read)
            if (r < 0) {
                if (read == 0) throw EOFException()
                throw EOFException("Unexpected end of stream")
            }
            read += r
        }
        return buf
    }
}

/** Builds the Shadowsocks SOCKS5-style target address header (ATYP + addr + port). */
object SocksAddress {
    fun build(host: String, port: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val ipv4 = parseIpv4(host)
        val ipv6 = if (ipv4 == null) parseIpv6(host) else null
        when {
            ipv4 != null -> { out.write(0x01); out.write(ipv4) }
            ipv6 != null -> { out.write(0x04); out.write(ipv6) }
            else -> {
                val h = host.toByteArray(Charsets.US_ASCII)
                require(h.size <= 255) { "Hostname too long" }
                out.write(0x03); out.write(h.size); out.write(h)
            }
        }
        out.write((port shr 8) and 0xFF)
        out.write(port and 0xFF)
        return out.toByteArray()
    }

    /** The address header length for the given ATYP byte at [buf]\[off], or -1 if malformed/truncated. */
    fun headerLength(buf: ByteArray, off: Int): Int {
        if (off >= buf.size) return -1
        return when (buf[off].toInt() and 0xFF) {
            0x01 -> 1 + 4 + 2               // ATYP + IPv4 + port
            0x04 -> 1 + 16 + 2              // ATYP + IPv6 + port
            0x03 -> {
                if (off + 1 >= buf.size) return -1
                val hlen = buf[off + 1].toInt() and 0xFF
                1 + 1 + hlen + 2            // ATYP + len + host + port
            }
            else -> -1
        }
    }

    /** Parse an address header at [buf]\[off] into (host, port), or null if malformed/truncated. */
    fun parse(buf: ByteArray, off: Int): Pair<String, Int>? {
        val hlen = headerLength(buf, off)
        if (hlen < 0 || off + hlen > buf.size) return null
        return when (buf[off].toInt() and 0xFF) {
            0x01 -> {
                val host = (0 until 4).joinToString(".") { (buf[off + 1 + it].toInt() and 0xFF).toString() }
                host to portAt(buf, off + 1 + 4)
            }
            0x04 -> {
                val addr = java.net.InetAddress.getByAddress(buf.copyOfRange(off + 1, off + 1 + 16))
                (addr.hostAddress ?: return null) to portAt(buf, off + 1 + 16)
            }
            0x03 -> {
                val n = buf[off + 1].toInt() and 0xFF
                val host = String(buf, off + 2, n, Charsets.US_ASCII)
                host to portAt(buf, off + 2 + n)
            }
            else -> null
        }
    }

    private fun portAt(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    private fun parseIpv4(host: String): ByteArray? {
        val parts = host.split(".")
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255) return null
            bytes[i] = v.toByte()
        }
        return bytes
    }

    private fun parseIpv6(host: String): ByteArray? {
        if (!host.contains(':')) return null
        return try {
            val addr = java.net.InetAddress.getByName(host)
            if (addr.address.size == 16) addr.address else null
        } catch (e: Exception) {
            null
        }
    }
}
