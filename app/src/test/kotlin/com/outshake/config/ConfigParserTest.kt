package com.outshake.config

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class ConfigParserTest {

    private fun b64url(s: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())

    @Test
    fun `plain static SIP002 key`() {
        val userinfo = b64url("chacha20-ietf-poly1305:pass123")
        val key = "ss://$userinfo@example.com:8388#My%20Server"
        val parsed = ConfigParser.parseStatic(key)

        assertEquals("My Server", parsed.name)
        assertEquals("example.com", parsed.transport.host)
        assertEquals(8388, parsed.transport.port)
        assertEquals(Cipher.CHACHA20_IETF_POLY1305, parsed.transport.cipher)
        assertEquals("pass123", parsed.transport.password)
        assertNull(parsed.transport.prefix)
    }

    @Test
    fun `static SIP002 key with prefix param`() {
        val userinfo = b64url("aes-256-gcm:secretpw")
        val key = "ss://$userinfo@1.2.3.4:9999/?prefix=%16%03%01%00%C2#Prefixed"
        val parsed = ConfigParser.parseStatic(key)

        assertEquals("1.2.3.4", parsed.transport.host)
        assertEquals(9999, parsed.transport.port)
        assertEquals(Cipher.AES_256_GCM, parsed.transport.cipher)
        assertArrayEquals(
            byteArrayOf(0x16, 0x03, 0x01, 0x00, 0xC2.toByte()),
            parsed.transport.prefix
        )
    }

    @Test
    fun `legacy base64 blob key`() {
        val blob = Base64.getEncoder().encodeToString("aes-128-gcm:hunter2@10.0.0.1:1080".toByteArray())
        val parsed = ConfigParser.parseStatic("ss://$blob#Legacy")

        assertEquals("10.0.0.1", parsed.transport.host)
        assertEquals(1080, parsed.transport.port)
        assertEquals(Cipher.AES_128_GCM, parsed.transport.cipher)
        assertEquals("hunter2", parsed.transport.password)
    }

    @Test
    fun `ssconf url resolution`() {
        assertEquals(
            "https://example.com/config/abc",
            ConfigParser.ssConfToUrl("ssconf://example.com/config/abc#Name")
        )
        assertEquals("Name", ConfigParser.ssConfName("ssconf://example.com/config/abc#Name"))
    }

    @Test
    fun `dynamic JSON config`() {
        val json = """
            {"server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-128-gcm"}
        """.trimIndent()
        val parsed = ConfigParser.parseDynamicBody(json, "Dyn")
        assertEquals("1.2.3.4", parsed.transport.host)
        assertEquals(8388, parsed.transport.port)
        assertEquals(Cipher.AES_128_GCM, parsed.transport.cipher)
        assertEquals("pw", parsed.transport.password)
        assertNull(parsed.transport.prefix)
    }

    @Test
    fun `dynamic JSON config with prefix`() {
        val json = "{\"server\":\"h.example\",\"server_port\":443,\"password\":\"pw\",\"method\":\"chacha20-ietf-poly1305\",\"prefix\":\"\\u00dc\"}"
        val parsed = ConfigParser.parseDynamicBody(json)
        assertArrayEquals(byteArrayOf(0xDC.toByte()), parsed.transport.prefix)
        assertEquals(443, parsed.transport.port)
    }

    @Test
    fun `dynamic YAML transport graph resolves shadowsocks tcp branch`() {
        val yaml = """
            transport:
              ${'$'}type: tcpudp
              tcp:
                ${'$'}type: shadowsocks
                endpoint: example.com:4321
                cipher: chacha20-ietf-poly1305
                secret: yaml-secret
                prefix: "POST"
              udp:
                ${'$'}type: shadowsocks
                endpoint: example.com:4321
                cipher: chacha20-ietf-poly1305
                secret: yaml-secret
        """.trimIndent()
        val parsed = ConfigParser.parseDynamicBody(yaml, "YamlProfile")
        assertEquals("example.com", parsed.transport.host)
        assertEquals(4321, parsed.transport.port)
        assertEquals(Cipher.CHACHA20_IETF_POLY1305, parsed.transport.cipher)
        assertEquals("yaml-secret", parsed.transport.password)
        assertArrayEquals("POST".toByteArray(), parsed.transport.prefix)
    }

    @Test
    fun `ssconf body may contain ss url`() {
        val userinfo = b64url("aes-256-gcm:pw")
        val body = "ss://$userinfo@9.9.9.9:8080#Inner"
        val parsed = ConfigParser.parseDynamicBody(body, "Outer")
        assertEquals("9.9.9.9", parsed.transport.host)
        assertEquals("Outer", parsed.name) // name hint overrides
    }

    @Test
    fun `unsupported cipher fails clearly`() {
        val userinfo = b64url("rc4-md5:pw")
        val ex = assertThrows(ConfigException::class.java) {
            ConfigParser.parseStatic("ss://$userinfo@1.2.3.4:8388")
        }
        assertTrue(ex.message!!.contains("Unsupported cipher"))
    }

    @Test
    fun `unsupported transport type fails clearly`() {
        val yaml = """
            transport:
              ${'$'}type: websocket
              url: wss://example.com/ws
        """.trimIndent()
        val ex = assertThrows(ConfigException::class.java) {
            ConfigParser.parseDynamicBody(yaml)
        }
        assertTrue(ex.message!!.contains("Unsupported transport type"))
    }

    @Test
    fun `malformed key fails clearly`() {
        assertThrows(ConfigException::class.java) { ConfigParser.parseStatic("ss://") }
        assertThrows(ConfigException::class.java) { ConfigParser.parseStatic("not-a-key") }
        assertThrows(ConfigException::class.java) { ConfigParser.parseDynamicBody("<html>nope</html>") }
    }

    @Test
    fun `prefix byte helpers`() {
        assertArrayEquals(
            byteArrayOf(0x16, 0x03, 0x01),
            ConfigParser.percentDecodeToBytes("%16%03%01")
        )
        assertArrayEquals(
            byteArrayOf('G'.code.toByte(), 'E'.code.toByte(), 'T'.code.toByte()),
            ConfigParser.prefixStringToBytes("GET")
        )
    }
}
