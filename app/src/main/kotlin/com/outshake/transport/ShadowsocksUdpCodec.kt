package com.outshake.transport

import com.outshake.config.Cipher
import java.security.SecureRandom

/**
 * Shadowsocks AEAD UDP packet codec (SIP007), matching the Outline server.
 *
 * Wire format of one datagram:
 *
 *     [random salt (saltSize)][AEAD_seal(subkey, zero-nonce, [SOCKS5 addr header][payload])]
 *
 * A fresh salt is generated for every outgoing packet, the AEAD nonce is 12 zero bytes, and there
 * is a single seal/open per datagram (no length-prefixed chunking, unlike the TCP stream).
 *
 * The Outline prefix (PrefixSaltGenerator) applies to the *TCP* salt only, so it is deliberately
 * NOT used here — UDP salts stay fully random. See [ShadowsocksEncryptor] for the TCP path.
 *
 * Pure functions — fully unit-testable on the JVM.
 */
class ShadowsocksUdpCodec(
    private val cipher: Cipher,
    private val masterKey: ByteArray,
    private val random: SecureRandom = SecureRandom(),
) {
    private val zeroNonce = ByteArray(12)

    /** Encrypt one datagram destined for [targetHost]:[targetPort]. */
    fun encode(targetHost: String, targetPort: Int, payload: ByteArray): ByteArray {
        val salt = ByteArray(cipher.saltSize).also { random.nextBytes(it) }
        val subkey = ShadowsocksCrypto.hkdfSha1(masterKey, salt, cipher.keySize)
        val header = SocksAddress.build(targetHost, targetPort)
        val plain = header + payload
        val sealed = ShadowsocksCrypto.seal(cipher, subkey, zeroNonce, plain)
        return salt + sealed
    }

    /** A decrypted server reply: the origin address it came from plus the raw payload. */
    data class Decoded(val host: String, val port: Int, val payload: ByteArray)

    /**
     * Decrypt one datagram received from the server. Returns null if it is too short or the address
     * header is malformed (a hostile/garbage packet must never crash the relay).
     * Throws on AEAD authentication failure.
     */
    fun decode(datagram: ByteArray): Decoded? {
        val saltSize = cipher.saltSize
        if (datagram.size <= saltSize) return null
        val salt = datagram.copyOfRange(0, saltSize)
        val subkey = ShadowsocksCrypto.hkdfSha1(masterKey, salt, cipher.keySize)
        val ct = datagram.copyOfRange(saltSize, datagram.size)
        val plain = ShadowsocksCrypto.open(cipher, subkey, zeroNonce, ct)
        val hlen = SocksAddress.headerLength(plain, 0)
        if (hlen < 0 || hlen > plain.size) return null
        val (host, port) = SocksAddress.parse(plain, 0) ?: return null
        val payload = plain.copyOfRange(hlen, plain.size)
        return Decoded(host, port, payload)
    }
}
