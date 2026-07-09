package com.outshake.vpn

import com.outshake.config.Profile
import com.outshake.config.SourceType

/**
 * Resolves which [Profile] to connect with, retrying dynamic (ssconf) profiles exactly once against
 * a freshly-fetched config if the first reachability probe fails. Pure and dependency-injected so it
 * is unit-testable off-device; it never loops (at most one refresh + one retry).
 */
object ConnectRetry {

    /**
     * Probe [profile]; on failure, if it is dynamic, refetch its config once and probe again.
     * Returns the profile that succeeded (possibly the refreshed one). Throws the last failure if
     * both attempts fail, or immediately for a static profile whose single probe failed.
     */
    fun resolve(
        profile: Profile,
        probe: (Profile) -> Unit,
        refresh: (Profile) -> Profile,
    ): Profile {
        try {
            probe(profile)
            return profile
        } catch (first: Exception) {
            if (profile.sourceType != SourceType.DYNAMIC || profile.remoteUrl == null) throw first
            val refreshed = refresh(profile)
            probe(refreshed) // may throw — surfaced to the caller, no further retry
            return refreshed
        }
    }
}
