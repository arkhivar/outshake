package com.outshake.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class ReconnectPolicyTest {

    private fun net(id: Long, isVpn: Boolean = false, hasInternet: Boolean = true) =
        ReconnectPolicy.Event(networkId = id, isVpn = isVpn, hasInternet = hasInternet)

    @Test
    fun `first underlying network is recorded but does not reconnect`() {
        val r = ReconnectPolicy.onNetwork(net(1), transitioning = false, now = 0, state = ReconnectPolicy.State())
        assertEquals(ReconnectPolicy.Action.IGNORE, r.action)
        assertEquals(1L, r.state.boundNetworkId)
    }

    @Test
    fun `same network is a no-op`() {
        val bound = ReconnectPolicy.State(boundNetworkId = 1)
        val r = ReconnectPolicy.onNetwork(net(1), transitioning = false, now = 10_000, state = bound)
        assertEquals(ReconnectPolicy.Action.IGNORE, r.action)
        assertEquals(1L, r.state.boundNetworkId)
    }

    @Test
    fun `the vpn's own network is ignored`() {
        // This is the regression: the tun network must never look like an underlying change.
        val bound = ReconnectPolicy.State(boundNetworkId = 1)
        val r = ReconnectPolicy.onNetwork(net(99, isVpn = true), transitioning = false, now = 10_000, state = bound)
        assertEquals(ReconnectPolicy.Action.IGNORE, r.action)
        assertEquals(1L, r.state.boundNetworkId)
    }

    @Test
    fun `a network without internet is ignored`() {
        val bound = ReconnectPolicy.State(boundNetworkId = 1)
        val r = ReconnectPolicy.onNetwork(net(2, hasInternet = false), transitioning = false, now = 10_000, state = bound)
        assertEquals(ReconnectPolicy.Action.IGNORE, r.action)
    }

    @Test
    fun `a real change to a different network reconnects once`() {
        val bound = ReconnectPolicy.State(boundNetworkId = 1)
        val r = ReconnectPolicy.onNetwork(net(2), transitioning = false, now = 10_000, state = bound)
        assertEquals(ReconnectPolicy.Action.RECONNECT, r.action)
        assertEquals(2L, r.state.boundNetworkId)

        // A re-delivered event for the network we just moved to is then a no-op.
        val again = ReconnectPolicy.onNetwork(net(2), transitioning = false, now = 10_100, state = r.state)
        assertEquals(ReconnectPolicy.Action.IGNORE, again.action)
    }

    @Test
    fun `changes while transitioning are ignored`() {
        val bound = ReconnectPolicy.State(boundNetworkId = 1)
        val r = ReconnectPolicy.onNetwork(net(2), transitioning = true, now = 10_000, state = bound)
        assertEquals(ReconnectPolicy.Action.IGNORE, r.action)
    }

    @Test
    fun `rapid consecutive changes are rate-limited then give up`() {
        var state = ReconnectPolicy.State(boundNetworkId = 1)
        var now = 100_000L

        // First well-spaced change: reconnects.
        val first = ReconnectPolicy.onNetwork(net(2), transitioning = false, now = now, state = state)
        assertEquals(ReconnectPolicy.Action.RECONNECT, first.action)
        state = first.state

        // Subsequent changes within MIN_INTERVAL are deferred (not stacked) but counted...
        var lastAction = ReconnectPolicy.Action.IGNORE
        repeat(ReconnectPolicy.MAX_RAPID_RECONNECTS + 1) { i ->
            now += 200 // < MIN_INTERVAL_MS apart
            val next = net((10 + i).toLong()) // each a different network id
            val r = ReconnectPolicy.onNetwork(next, transitioning = false, now = now, state = state)
            state = r.state
            lastAction = r.action
        }
        // ...until the loop guard fires and surfaces GIVE_UP instead of looping forever.
        assertEquals(ReconnectPolicy.Action.GIVE_UP, lastAction)
    }

    @Test
    fun `losing the bound network clears it so the next network rebinds`() {
        val bound = ReconnectPolicy.State(boundNetworkId = 5)
        val cleared = ReconnectPolicy.onLost(5, bound)
        assertEquals(null, cleared.boundNetworkId)

        // A different network's loss does not clear our binding.
        val unchanged = ReconnectPolicy.onLost(6, bound)
        assertEquals(5L, unchanged.boundNetworkId)
    }
}
