package com.outshake.config

/** Supported Shadowsocks AEAD ciphers. Anything else must fail clearly. */
enum class Cipher(val id: String, val keySize: Int, val saltSize: Int, val tagSize: Int) {
    CHACHA20_IETF_POLY1305("chacha20-ietf-poly1305", 32, 32, 16),
    AES_256_GCM("aes-256-gcm", 32, 32, 16),
    AES_128_GCM("aes-128-gcm", 16, 16, 16);

    companion object {
        fun fromId(id: String): Cipher? = entries.firstOrNull { it.id.equals(id, ignoreCase = true) }
    }
}

enum class SourceType { STATIC, DYNAMIC }

/**
 * Normalized Shadowsocks transport. [prefix] is the raw prefix byte string applied to the
 * Shadowsocks salt (Outline "prefix" semantics), or null when no prefix is configured.
 */
data class TransportConfig(
    val host: String,
    val port: Int,
    val cipher: Cipher,
    val password: String,
    val prefix: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransportConfig) return false
        return host == other.host && port == other.port && cipher == other.cipher &&
            password == other.password &&
            (prefix?.toList() ?: emptyList<Byte>()) == (other.prefix?.toList() ?: emptyList<Byte>())
    }

    override fun hashCode(): Int {
        var result = host.hashCode()
        result = 31 * result + port
        result = 31 * result + cipher.hashCode()
        result = 31 * result + password.hashCode()
        result = 31 * result + (prefix?.toList()?.hashCode() ?: 0)
        return result
    }
}

/** Result of parsing a key/config before it is persisted as a profile. */
data class ParsedConfig(
    val name: String,
    val transport: TransportConfig,
)

/** A saved, usable profile. */
data class Profile(
    val id: String,
    val name: String,
    val transport: TransportConfig,
    val sourceType: SourceType,
    /** Original ss:// or ssconf:// string as entered by the user. */
    val rawKey: String,
    /** For dynamic (ssconf) profiles, the resolved https URL used to fetch the config. */
    val remoteUrl: String? = null,
)

/** Thrown for malformed, unparseable, or unsupported configs. Message is user-facing. */
class ConfigException(message: String) : Exception(message)
