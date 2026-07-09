package com.outshake.transport

import com.outshake.config.Cipher
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.AEADCipher
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest

/**
 * Low-level Shadowsocks AEAD primitives (SIP004/SIP007 compatible), matching the Outline server.
 *
 * Pure functions — fully unit-testable on the JVM.
 */
object ShadowsocksCrypto {

    private val SS_SUBKEY_INFO = "ss-subkey".toByteArray(Charsets.US_ASCII)
    const val MAX_PAYLOAD = 0x3FFF // 16383, Shadowsocks chunk limit

    /** OpenSSL EVP_BytesToKey(MD5) key derivation from a password. */
    fun deriveMasterKey(password: String, keySize: Int): ByteArray {
        val pw = password.toByteArray(Charsets.UTF_8)
        val md5 = MessageDigest.getInstance("MD5")
        val key = ByteArray(keySize)
        var prev = ByteArray(0)
        var offset = 0
        while (offset < keySize) {
            md5.reset()
            md5.update(prev)
            md5.update(pw)
            prev = md5.digest()
            val n = minOf(prev.size, keySize - offset)
            System.arraycopy(prev, 0, key, offset, n)
            offset += n
        }
        return key
    }

    /** HKDF-SHA1 to derive the per-session subkey from master key + salt. */
    fun hkdfSha1(masterKey: ByteArray, salt: ByteArray, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA1Digest())
        hkdf.init(HKDFParameters(masterKey, salt, SS_SUBKEY_INFO))
        val out = ByteArray(length)
        hkdf.generateBytes(out, 0, length)
        return out
    }

    private fun newAead(cipher: Cipher): AEADCipher = when (cipher) {
        Cipher.CHACHA20_IETF_POLY1305 -> ChaCha20Poly1305()
        Cipher.AES_256_GCM, Cipher.AES_128_GCM -> GCMBlockCipher.newInstance(AESEngine.newInstance())
    }

    /** Encrypt one AEAD block: returns ciphertext||tag. */
    fun seal(cipher: Cipher, subkey: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val aead = newAead(cipher)
        aead.init(true, AEADParameters(KeyParameter(subkey), cipher.tagSize * 8, nonce))
        val out = ByteArray(aead.getOutputSize(plaintext.size))
        var len = aead.processBytes(plaintext, 0, plaintext.size, out, 0)
        len += aead.doFinal(out, len)
        return if (len == out.size) out else out.copyOf(len)
    }

    /** Decrypt one AEAD block (ciphertext||tag) back to plaintext; throws on auth failure. */
    fun open(cipher: Cipher, subkey: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val aead = newAead(cipher)
        aead.init(false, AEADParameters(KeyParameter(subkey), cipher.tagSize * 8, nonce))
        val out = ByteArray(aead.getOutputSize(ciphertext.size))
        var len = aead.processBytes(ciphertext, 0, ciphertext.size, out, 0)
        len += aead.doFinal(out, len)
        return if (len == out.size) out else out.copyOf(len)
    }

    /** Increment a 12-byte little-endian nonce in place. */
    fun incrementNonce(nonce: ByteArray) {
        var i = 0
        while (i < nonce.size) {
            val v = (nonce[i].toInt() and 0xFF) + 1
            nonce[i] = v.toByte()
            if (v <= 0xFF) break
            i++
        }
    }
}
