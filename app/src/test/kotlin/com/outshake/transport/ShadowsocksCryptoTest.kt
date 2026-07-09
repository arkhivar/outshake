package com.outshake.transport

import com.outshake.config.Cipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class ShadowsocksCryptoTest {

    private fun roundTrip(cipher: Cipher, prefix: ByteArray?) {
        val password = "correct horse battery staple"
        val masterKey = ShadowsocksCrypto.deriveMasterKey(password, cipher.keySize)
        val encryptor = ShadowsocksEncryptor(cipher, masterKey, prefix)

        val payload = ByteArray(5000) { (it % 251).toByte() } // spans multiple 0x3FFF chunks? no, <16383, but multi-chunk via two writes
        val wire = java.io.ByteArrayOutputStream()
        wire.write(encryptor.encrypt(payload, 0, payload.size))
        wire.write(encryptor.encrypt("second".toByteArray(), 0, 6))

        val decryptor = ShadowsocksDecryptor(cipher, masterKey, ByteArrayInputStream(wire.toByteArray()))
        val recovered = java.io.ByteArrayOutputStream()
        var chunk = decryptor.readChunk()
        while (chunk != null) {
            recovered.write(chunk)
            chunk = decryptor.readChunk()
        }
        val all = recovered.toByteArray()
        assertArrayEquals(payload, all.copyOfRange(0, payload.size))
        assertEquals("second", String(all.copyOfRange(payload.size, all.size)))

        if (prefix != null) {
            assertArrayEquals(prefix, encryptor.salt.copyOf(prefix.size))
        }
    }

    @Test
    fun `chacha20 round trip`() = roundTrip(Cipher.CHACHA20_IETF_POLY1305, null)

    @Test
    fun `aes256gcm round trip`() = roundTrip(Cipher.AES_256_GCM, null)

    @Test
    fun `aes128gcm round trip`() = roundTrip(Cipher.AES_128_GCM, null)

    @Test
    fun `chacha20 round trip with prefix applied to salt`() =
        roundTrip(Cipher.CHACHA20_IETF_POLY1305, byteArrayOf(0x16, 0x03, 0x01, 0x00))

    @Test
    fun `prefix longer than salt is rejected`() {
        val cipher = Cipher.AES_128_GCM // saltSize 16
        val masterKey = ShadowsocksCrypto.deriveMasterKey("pw", cipher.keySize)
        assertThrows(IllegalArgumentException::class.java) {
            ShadowsocksEncryptor(cipher, masterKey, ByteArray(17))
        }
    }

    @Test
    fun `evp key derivation is deterministic and correct length`() {
        val k1 = ShadowsocksCrypto.deriveMasterKey("password", 32)
        val k2 = ShadowsocksCrypto.deriveMasterKey("password", 32)
        assertEquals(32, k1.size)
        assertArrayEquals(k1, k2)
    }

    @Test
    fun `nonce increments little endian`() {
        val nonce = ByteArray(12)
        ShadowsocksCrypto.incrementNonce(nonce)
        assertEquals(1, nonce[0].toInt())
        nonce[0] = 0xFF.toByte()
        ShadowsocksCrypto.incrementNonce(nonce)
        assertEquals(0, nonce[0].toInt())
        assertEquals(1, nonce[1].toInt())
    }

    @Test
    fun `socks address ipv4 and domain`() {
        val v4 = SocksAddress.build("1.2.3.4", 8388)
        assertArrayEquals(byteArrayOf(0x01, 1, 2, 3, 4, (8388 shr 8).toByte(), (8388 and 0xFF).toByte()), v4)

        val dom = SocksAddress.build("ex.com", 443)
        assertEquals(0x03, dom[0].toInt())
        assertEquals(6, dom[1].toInt())
        assertEquals("ex.com", String(dom.copyOfRange(2, 8)))
    }
}
