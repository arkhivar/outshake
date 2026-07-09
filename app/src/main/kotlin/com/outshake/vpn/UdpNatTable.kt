package com.outshake.vpn

import java.util.concurrent.ConcurrentHashMap

/**
 * A minimal UDP NAT/session table keyed by the app-side endpoint string. Each entry tracks a
 * last-active timestamp so idle flows can be evicted (UDP has no connection teardown). Pure and
 * clock-injected — [nowMs] is always supplied by the caller — so it is unit-testable off-device.
 */
class UdpNatTable<V>(private val idleMs: Long) {

    private class Entry<V>(val value: V, @Volatile var lastActive: Long)

    private val map = ConcurrentHashMap<String, Entry<V>>()

    fun get(key: String): V? = map[key]?.value

    /** Return the existing session for [key] (touching it) or create one via [factory]. */
    fun getOrCreate(key: String, nowMs: Long, factory: () -> V): V {
        map[key]?.let { it.lastActive = nowMs; return it.value }
        val entry = Entry(factory(), nowMs)
        val prev = map.putIfAbsent(key, entry)
        return if (prev != null) { prev.lastActive = nowMs; prev.value } else entry.value
    }

    fun touch(key: String, nowMs: Long) {
        map[key]?.lastActive = nowMs
    }

    /** Remove and return every session idle for longer than [idleMs] as of [nowMs]. */
    fun evictExpired(nowMs: Long): List<V> {
        val expired = ArrayList<V>()
        val it = map.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (nowMs - e.value.lastActive > idleMs) {
                expired.add(e.value.value)
                it.remove()
            }
        }
        return expired
    }

    fun remove(key: String): V? = map.remove(key)?.value

    fun values(): List<V> = map.values.map { it.value }

    val size: Int get() = map.size
}
