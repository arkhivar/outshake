package com.outshake.vpn

import android.service.quicksettings.Tile
import org.junit.Assert.assertEquals
import org.junit.Test

class OutshakeTileServiceTest {

    @Test
    fun `no active profile is always unavailable`() {
        for (state in ConnectionManager.State.entries) {
            assertEquals(
                Tile.STATE_UNAVAILABLE,
                OutshakeTileService.tileState(state, hasActiveProfile = false)
            )
        }
    }

    @Test
    fun `connected maps to active`() {
        assertEquals(
            Tile.STATE_ACTIVE,
            OutshakeTileService.tileState(ConnectionManager.State.CONNECTED, hasActiveProfile = true)
        )
    }

    @Test
    fun `non-connected states with a profile map to inactive`() {
        val nonConnected = listOf(
            ConnectionManager.State.DISCONNECTED,
            ConnectionManager.State.CONNECTING,
            ConnectionManager.State.DISCONNECTING,
            ConnectionManager.State.ERROR,
        )
        for (state in nonConnected) {
            assertEquals(
                Tile.STATE_INACTIVE,
                OutshakeTileService.tileState(state, hasActiveProfile = true)
            )
        }
    }
}
