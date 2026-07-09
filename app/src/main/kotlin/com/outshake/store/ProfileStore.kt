package com.outshake.store

import android.content.Context
import android.util.Base64
import com.outshake.config.Cipher
import com.outshake.config.Profile
import com.outshake.config.SourceType
import com.outshake.config.TransportConfig
import org.json.JSONArray
import org.json.JSONObject

/** Local persistence for profiles + settings, backed by SharedPreferences (JSON encoded). */
class ProfileStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("outshake", Context.MODE_PRIVATE)

    fun getProfiles(): List<Profile> {
        val raw = prefs.getString(KEY_PROFILES, null) ?: return emptyList()
        val arr = JSONArray(raw)
        return (0 until arr.length()).mapNotNull { i -> fromJson(arr.getJSONObject(i)) }
    }

    fun saveProfiles(profiles: List<Profile>) {
        val arr = JSONArray()
        profiles.forEach { arr.put(toJson(it)) }
        prefs.edit().putString(KEY_PROFILES, arr.toString()).apply()
    }

    fun addOrUpdate(profile: Profile) {
        val list = getProfiles().toMutableList()
        val idx = list.indexOfFirst { it.id == profile.id }
        if (idx >= 0) list[idx] = profile else list.add(profile)
        saveProfiles(list)
    }

    fun delete(id: String) {
        saveProfiles(getProfiles().filter { it.id != id })
        if (activeProfileId == id) activeProfileId = null
    }

    var activeProfileId: String?
        get() = prefs.getString(KEY_ACTIVE, null)
        set(value) = prefs.edit().putString(KEY_ACTIVE, value).apply()

    fun activeProfile(): Profile? = activeProfileId?.let { id -> getProfiles().firstOrNull { it.id == id } }

    /**
     * Shake-to-toggle is ON by default. An existing user's explicit choice is preserved: once the
     * switch has been touched the stored value wins; only a never-set preference defaults to true.
     */
    var shakeEnabled: Boolean
        get() = prefs.getBoolean(KEY_SHAKE, true)
        set(value) = prefs.edit().putBoolean(KEY_SHAKE, value).apply()

    /** Shake sensitivity threshold in g-force above gravity (higher = harder shake required). */
    var shakeSensitivity: Float
        get() = prefs.getFloat(KEY_SHAKE_SENS, 2.7f)
        set(value) = prefs.edit().putFloat(KEY_SHAKE_SENS, value).apply()

    /** Connect the active profile automatically on device boot. OFF by default. */
    var connectOnBoot: Boolean
        get() = prefs.getBoolean(KEY_CONNECT_ON_BOOT, false)
        set(value) = prefs.edit().putBoolean(KEY_CONNECT_ON_BOOT, value).apply()

    /** Fire a short haptic tick at the accepted-toggle moment (same instant as the shake sound). ON by default. */
    var vibrateOnToggle: Boolean
        get() = prefs.getBoolean(KEY_VIBRATE, true)
        set(value) = prefs.edit().putBoolean(KEY_VIBRATE, value).apply()

    /**
     * The user's intent: true while the VPN should be up. Persisted so a process-death restart
     * (START_STICKY) can re-establish the tunnel and the UI can reflect the true desired state.
     */
    var shouldBeConnected: Boolean
        get() = prefs.getBoolean(KEY_SHOULD_CONNECT, false)
        set(value) = prefs.edit().putBoolean(KEY_SHOULD_CONNECT, value).apply()

    private fun toJson(p: Profile): JSONObject = JSONObject().apply {
        put("id", p.id)
        put("name", p.name)
        put("sourceType", p.sourceType.name)
        put("rawKey", p.rawKey)
        put("remoteUrl", p.remoteUrl ?: JSONObject.NULL)
        put("host", p.transport.host)
        put("port", p.transport.port)
        put("cipher", p.transport.cipher.id)
        put("password", p.transport.password)
        put("prefix", p.transport.prefix?.let { Base64.encodeToString(it, Base64.NO_WRAP) } ?: JSONObject.NULL)
    }

    private fun fromJson(o: JSONObject): Profile? {
        val cipher = Cipher.fromId(o.getString("cipher")) ?: return null
        val prefix = o.optString("prefix", "").takeIf { it.isNotEmpty() && !o.isNull("prefix") }
            ?.let { Base64.decode(it, Base64.NO_WRAP) }
        return Profile(
            id = o.getString("id"),
            name = o.getString("name"),
            transport = TransportConfig(
                host = o.getString("host"),
                port = o.getInt("port"),
                cipher = cipher,
                password = o.getString("password"),
                prefix = prefix,
            ),
            sourceType = SourceType.valueOf(o.getString("sourceType")),
            rawKey = o.getString("rawKey"),
            remoteUrl = if (o.isNull("remoteUrl")) null else o.getString("remoteUrl"),
        )
    }

    companion object {
        private const val KEY_PROFILES = "profiles"
        private const val KEY_ACTIVE = "active_profile"
        private const val KEY_SHAKE = "shake_enabled"
        private const val KEY_SHAKE_SENS = "shake_sensitivity"
        private const val KEY_CONNECT_ON_BOOT = "connect_on_boot"
        private const val KEY_SHOULD_CONNECT = "should_be_connected"
        private const val KEY_VIBRATE = "vibrate_on_toggle"
    }
}
