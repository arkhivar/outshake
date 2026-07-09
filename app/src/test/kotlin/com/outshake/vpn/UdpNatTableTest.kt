package com.outshake.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UdpNatTableTest {

    @Test
    fun `getOrCreate creates once and reuses`() {
        val table = UdpNatTable<String>(idleMs = 1000)
        var creates = 0
        val a = table.getOrCreate("k", 0) { creates++; "session" }
        val b = table.getOrCreate("k", 10) { creates++; "other" }
        assertEquals("session", a)
        assertEquals("session", b)
        assertEquals(1, creates)
        assertEquals(1, table.size)
    }

    @Test
    fun `evictExpired removes only entries idle past threshold`() {
        val table = UdpNatTable<String>(idleMs = 100)
        table.getOrCreate("fresh", 1000) { "fresh" }
        table.getOrCreate("stale", 500) { "stale" }

        // now=1050: fresh idle 50ms (kept), stale idle 550ms (evicted)
        val evicted = table.evictExpired(1050)
        assertEquals(listOf("stale"), evicted)
        assertEquals(1, table.size)
        assertNull(table.get("stale"))
        assertEquals("fresh", table.get("fresh"))
    }

    @Test
    fun `touch keeps an entry alive`() {
        val table = UdpNatTable<String>(idleMs = 100)
        table.getOrCreate("k", 0) { "v" }
        table.touch("k", 1000)
        // now=1050: touched at 1000, idle 50ms → not evicted
        assertTrue(table.evictExpired(1050).isEmpty())
        assertEquals("v", table.get("k"))
    }

    @Test
    fun `remove drops the entry`() {
        val table = UdpNatTable<String>(idleMs = 100)
        table.getOrCreate("k", 0) { "v" }
        assertEquals("v", table.remove("k"))
        assertNull(table.get("k"))
        assertEquals(0, table.size)
    }
}
