package com.outshake.config

import java.util.UUID

/** Turns a raw key string into a persisted-ready [Profile], fetching dynamic configs as needed. */
object ProfileImporter {

    /** Import a static ss:// or dynamic ssconf:// key. Blocking (call off the main thread). */
    fun import(rawKey: String): Profile {
        val key = rawKey.trim()
        return when {
            ConfigParser.isStatic(key) -> {
                val parsed = ConfigParser.parseStatic(key)
                Profile(
                    id = UUID.randomUUID().toString(),
                    name = parsed.name,
                    transport = parsed.transport,
                    sourceType = SourceType.STATIC,
                    rawKey = key,
                )
            }
            ConfigParser.isSsConf(key) -> {
                val url = ConfigParser.ssConfToUrl(key)
                val body = DynamicFetcher.fetch(url)
                val parsed = ConfigParser.parseDynamicBody(body, ConfigParser.ssConfName(key))
                Profile(
                    id = UUID.randomUUID().toString(),
                    name = parsed.name,
                    transport = parsed.transport,
                    sourceType = SourceType.DYNAMIC,
                    rawKey = key,
                    remoteUrl = url,
                )
            }
            else -> throw ConfigException("Unrecognized key. Expected an ss:// or ssconf:// link.")
        }
    }

    /** Re-fetch a dynamic profile's remote config, returning an updated profile (same id). */
    fun refresh(profile: Profile): Profile {
        if (profile.sourceType != SourceType.DYNAMIC || profile.remoteUrl == null) {
            throw ConfigException("Only dynamic (ssconf) profiles can be refreshed")
        }
        val body = DynamicFetcher.fetch(profile.remoteUrl)
        val parsed = ConfigParser.parseDynamicBody(body, profile.name)
        return profile.copy(name = parsed.name, transport = parsed.transport)
    }
}
