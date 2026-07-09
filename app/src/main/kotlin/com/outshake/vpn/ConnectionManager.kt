package com.outshake.vpn

import android.content.Context
import android.content.Intent
import android.os.Build
import com.outshake.store.ProfileStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Single source of truth for VPN connection state. Owns start/stop of [OutshakeVpnService] and
 * is the entry point for both the UI button and the shake gesture.
 */
object ConnectionManager {

    enum class State { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, DISCONNECTING, ERROR }

    private val _state = MutableStateFlow(State.DISCONNECTED)
    val state: StateFlow<State> = _state.asStateFlow()

    @Volatile var lastError: String? = null
        private set

    @Volatile var activeProfileId: String? = null
        private set

    fun connect(context: Context, profileId: String) {
        val app = context.applicationContext
        if (_state.value == State.CONNECTING || _state.value == State.CONNECTED) return
        lastError = null
        activeProfileId = profileId
        ProfileStore(app).activeProfileId = profileId
        _state.value = State.CONNECTING
        val intent = Intent(app, OutshakeVpnService::class.java).apply {
            action = OutshakeVpnService.ACTION_CONNECT
            putExtra(OutshakeVpnService.EXTRA_PROFILE_ID, profileId)
        }
        startService(app, intent)
    }

    fun disconnect(context: Context) {
        val app = context.applicationContext
        if (_state.value == State.DISCONNECTED || _state.value == State.DISCONNECTING) return
        _state.value = State.DISCONNECTING
        val intent = Intent(app, OutshakeVpnService::class.java).apply {
            action = OutshakeVpnService.ACTION_DISCONNECT
        }
        startService(app, intent)
    }

    /** Shake / tile entry point: toggle the active profile, ignoring transitions. */
    fun toggle(context: Context): String {
        return when (_state.value) {
            State.CONNECTED -> { disconnect(context); "Disconnecting" }
            State.DISCONNECTED, State.ERROR -> {
                val active = ProfileStore(context).activeProfile()
                    ?: return "No active profile"
                connect(context, active.id); "Connecting"
            }
            else -> "Busy — ignoring shake"
        }
    }

    private fun startService(context: Context, intent: Intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    // Called by the service as its lifecycle progresses.
    fun onConnected() { _state.value = State.CONNECTED }
    fun onReconnecting() { _state.value = State.RECONNECTING }
    fun onDisconnected() { _state.value = State.DISCONNECTED }
    fun onError(message: String) {
        lastError = message
        _state.value = State.ERROR
    }
}
