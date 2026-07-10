package com.outshake.vpn

/**
 * Pure decision logic for underlying-network changes, extracted so it can be unit-tested without
 * Android. [OutshakeVpnService] feeds it ConnectivityManager events; it decides whether an event is
 * a genuine change of the *underlying* (non-VPN) network worth reconnecting for.
 *
 * It exists because the naive approach — [android.net.ConnectivityManager.registerDefaultNetworkCallback]
 * plus "reconnect on any onAvailable" — loops forever once the tunnel is up: the VPN's own TUN
 * becomes the default network, fires onAvailable, we reconnect, the TUN drops, the real network
 * becomes default again, fires onAvailable, we reconnect… This gate ignores the VPN's own network,
 * same-network capability noise, mid-transition events, and rate-limits runaway reconnects.
 */
object ReconnectPolicy {

    /** Minimum spacing between reconnect attempts; changes arriving faster are deferred, not stacked. */
    const val MIN_INTERVAL_MS = 3_000L

    /** After this many rapid consecutive changes, give up and surface an error instead of looping. */
    const val MAX_RAPID_RECONNECTS = 4

    enum class Action { IGNORE, RECONNECT, GIVE_UP }

    data class State(
        /** The underlying network we're currently bound to; null until the first one is seen. */
        val boundNetworkId: Long? = null,
        val lastReconnectAt: Long = Long.MIN_VALUE,
        val rapidCount: Int = 0,
    )

    data class Event(
        val networkId: Long,
        /** Network carries TRANSPORT_VPN / lacks NET_CAPABILITY_NOT_VPN — i.e. our own tunnel. */
        val isVpn: Boolean,
        val hasInternet: Boolean,
    )

    data class Result(val action: Action, val state: State)

    /**
     * @param transitioning true while the VPN is mid connect/reconnect/disconnect — events are ignored
     *   so we never stack a reconnect on top of an in-flight one.
     * @param now monotonic timestamp in ms (e.g. SystemClock.elapsedRealtime()).
     */
    fun onNetwork(event: Event, transitioning: Boolean, now: Long, state: State): Result {
        // The VPN's own tun network, or a network with no internet, is never an underlying change.
        if (event.isVpn || !event.hasInternet) return Result(Action.IGNORE, state)

        // First underlying network we see: record it, don't reconnect (we're already on it).
        if (state.boundNetworkId == null) {
            return Result(Action.IGNORE, state.copy(boundNetworkId = event.networkId))
        }

        // Same underlying network (onCapabilitiesChanged / re-delivered onAvailable noise): ignore.
        if (event.networkId == state.boundNetworkId) return Result(Action.IGNORE, state)

        // Don't react while a transition is in flight.
        if (transitioning) return Result(Action.IGNORE, state)

        // Genuine change to a *different* underlying network. Rate-limit as a secondary safety net.
        // (Guard the sentinel: subtracting Long.MIN_VALUE would overflow and look "rapid".)
        val rapid = state.lastReconnectAt != Long.MIN_VALUE &&
            now - state.lastReconnectAt < MIN_INTERVAL_MS
        if (rapid) {
            val rapidCount = state.rapidCount + 1
            return if (rapidCount > MAX_RAPID_RECONNECTS) {
                Result(Action.GIVE_UP, state.copy(boundNetworkId = event.networkId, rapidCount = rapidCount))
            } else {
                // Defer: honor the minimum interval, but count it toward the loop guard.
                Result(Action.IGNORE, state.copy(rapidCount = rapidCount))
            }
        }
        return Result(
            Action.RECONNECT,
            state.copy(boundNetworkId = event.networkId, lastReconnectAt = now, rapidCount = 0),
        )
    }

    /** A network went away. If it was our bound underlying network, forget it so the next one rebinds. */
    fun onLost(networkId: Long, state: State): State =
        if (networkId == state.boundNetworkId) state.copy(boundNetworkId = null) else state
}
