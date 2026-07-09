package com.outshake.vpn

import com.outshake.config.Cipher
import com.outshake.config.Profile
import com.outshake.config.SourceType
import com.outshake.config.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ConnectRetryTest {

    private fun profile(source: SourceType, name: String = "p", remote: String? = "https://x/y") = Profile(
        id = "id",
        name = name,
        transport = TransportConfig("h", 8388, Cipher.AES_256_GCM, "pw"),
        sourceType = source,
        rawKey = "raw",
        remoteUrl = if (source == SourceType.DYNAMIC) remote else null,
    )

    @Test
    fun `successful probe uses original profile and never refreshes`() {
        var refreshed = false
        val p = profile(SourceType.STATIC)
        val out = ConnectRetry.resolve(p, probe = { }, refresh = { refreshed = true; it })
        assertSame(p, out)
        assertTrue(!refreshed)
    }

    @Test
    fun `static profile probe failure throws without refresh`() {
        var refreshed = false
        val p = profile(SourceType.STATIC)
        try {
            ConnectRetry.resolve(p, probe = { throw RuntimeException("down") }, refresh = { refreshed = true; it })
            fail("expected exception")
        } catch (e: RuntimeException) {
            assertEquals("down", e.message)
        }
        assertTrue(!refreshed)
    }

    @Test
    fun `dynamic profile refreshes once then succeeds on retry`() {
        val original = profile(SourceType.DYNAMIC, name = "orig")
        val fresh = profile(SourceType.DYNAMIC, name = "fresh")
        var probes = 0
        var refreshes = 0
        val out = ConnectRetry.resolve(
            original,
            probe = { p -> probes++; if (p === original) throw RuntimeException("stale endpoint") },
            refresh = { refreshes++; fresh },
        )
        assertSame(fresh, out)
        assertEquals(2, probes)
        assertEquals(1, refreshes)
    }

    @Test
    fun `dynamic profile that keeps failing refreshes only once then throws`() {
        val original = profile(SourceType.DYNAMIC)
        var refreshes = 0
        var probes = 0
        try {
            ConnectRetry.resolve(
                original,
                probe = { probes++; throw RuntimeException("still down") },
                refresh = { refreshes++; profile(SourceType.DYNAMIC, name = "fresh") },
            )
            fail("expected exception")
        } catch (e: RuntimeException) {
            assertEquals("still down", e.message)
        }
        assertEquals(1, refreshes)
        assertEquals(2, probes) // original + one retry, no loop
    }
}
