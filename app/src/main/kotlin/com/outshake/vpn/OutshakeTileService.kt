package com.outshake.vpn

import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import com.outshake.store.ProfileStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Quick Settings tile that mirrors the shake toggle: tapping it toggles the active profile via the
 * shared [ConnectionManager]. Tile appearance tracks live connection state; no connect/disconnect
 * logic is duplicated here.
 */
class OutshakeTileService : TileService() {

    private var scope: CoroutineScope? = null

    override fun onStartListening() {
        super.onStartListening()
        val s = CoroutineScope(Dispatchers.Main + Job())
        scope = s
        s.launch {
            ConnectionManager.state.collect { render(it) }
        }
    }

    override fun onStopListening() {
        scope?.let { (it.coroutineContext[Job])?.cancel() }
        scope = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        val state = ConnectionManager.state.value
        // Ignore taps mid-transition, matching the shake toggle.
        if (state == ConnectionManager.State.CONNECTING || state == ConnectionManager.State.DISCONNECTING) {
            return
        }
        val hasActive = ProfileStore(this).activeProfile() != null
        if (!hasActive) {
            showToast("No active profile — pick one in Outshake")
            render(ConnectionManager.state.value)
            return
        }
        // If a VPN authorization prompt is still pending we cannot show it from a tile; the manager's
        // connect path assumes VpnService.prepare() has already been granted. Route the user to the
        // app to grant it the first time, otherwise toggle directly.
        if (state != ConnectionManager.State.CONNECTED && VpnService.prepare(this) != null) {
            showToast("Open Outshake once to grant VPN permission")
            openApp()
            return
        }
        ConnectionManager.toggle(this)
        render(ConnectionManager.state.value)
    }

    private fun render(state: ConnectionManager.State) {
        val tile = qsTile ?: return
        val hasActive = ProfileStore(this).activeProfile() != null
        tile.state = tileState(state, hasActive)
        tile.label = "Outshake"
        tile.contentDescription = when (state) {
            ConnectionManager.State.CONNECTED -> "Connected"
            ConnectionManager.State.CONNECTING -> "Connecting"
            ConnectionManager.State.DISCONNECTING -> "Disconnecting"
            ConnectionManager.State.ERROR -> "Error"
            ConnectionManager.State.DISCONNECTED -> "Disconnected"
        }
        tile.updateTile()
    }

    private fun showToast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    private fun openApp() {
        val intent = Intent(this, com.outshake.ui.MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pending = android.app.PendingIntent.getActivity(
                this, 0, intent,
                android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
            )
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
            startActivityAndCollapse(intent)
        }
    }

    companion object {
        /**
         * Pure mapping from connection state (+ whether an active profile exists) to a Quick Settings
         * tile state. With no active profile the tile is unavailable; otherwise Active iff connected.
         */
        fun tileState(state: ConnectionManager.State, hasActiveProfile: Boolean): Int {
            if (!hasActiveProfile) return Tile.STATE_UNAVAILABLE
            return when (state) {
                ConnectionManager.State.CONNECTED -> Tile.STATE_ACTIVE
                else -> Tile.STATE_INACTIVE
            }
        }
    }
}
