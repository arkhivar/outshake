package com.outshake.transport

import com.outshake.config.Cipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ShadowsocksUdpCodecTest {

    private fun codec(cipher: Cipher): ShadowsocksUdpCodec {
        val key = ShadowsocksCrypto.deriveMasterKey("udp-test-pw", cipher.keySize)
        return ShadowsocksUdpCodec(cipher, key)
    }

    @Test
    fun `encode then decode round-trips payload and target for chacha20`() = roundTrip(Cipher.CHACHA20_IETF_POLY1305)

    @Test
    fun `encode then decode round-trips payload and target for aes256gcm`() = roundTrip(Cipher.AES_256_GCM)

    private fun roundTrip(cipher: Cipher) {
        val c = codec(cipher)
        val payload = "the quick brown fox".toByteArray()
        val wire = c.encode("8.8.8.8", 53, payload)
        // Wire = salt + sealed(header+payload+tag); must be larger than salt alone.
        assertTrue(wire.size > cipher.saltSize)
        val decoded = c.decode(wire)!!
        assertEquals("8.8.8.8", decoded.host)
        assertEquals(53, decoded.port)
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun `fresh random salt per datagram`() {
        val c = codec(Cipher.CHACHA20_IETF_POLY1305)
        val a = c.encode("1.1.1.1", 53, byteArrayOf(1, 2, 3))
        val b = c.encode("1.1.1.1", 53, byteArrayOf(1, 2, 3))
        val saltA = a.copyOf(Cipher.CHACHA20_IETF_POLY1305.saltSize)
        val saltB = b.copyOf(Cipher.CHACHA20_IETF_POLY1305.saltSize)
        assertNotEquals(saltA.toList(), saltB.toList())
    }

    @Test
    fun `domain target round-trips`() {
        val c = codec(Cipher.AES_256_GCM)
        val wire = c.encode("example.com", 443, byteArrayOf(9, 8, 7))
        val decoded = c.decode(wire)!!
        assertEquals("example.com", decoded.host)
        assertEquals(443, decoded.port)
    }

    @Test
    fun `too-short datagram decodes to null without throwing`() {
        val c = codec(Cipher.CHACHA20_IETF_POLY1305)
        assertNull(c.decode(ByteArray(4)))
        assertNull(c.decode(ByteArray(Cipher.CHACHA20_IETF_POLY1305.saltSize)))
    }

    @Test(expected = Exception::class)
    fun `tampered ciphertext fails authentication`() {
        val c = codec(Cipher.CHACHA20_IETF_POLY1305)
        val wire = c.encode("1.1.1.1", 53, byteArrayOf(1, 2, 3, 4))
        wire[wire.size - 1] = (wire[wire.size - 1] + 1).toByte()
        c.decode(wire)
    }
}
