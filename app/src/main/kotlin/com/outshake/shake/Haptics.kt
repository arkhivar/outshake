package com.outshake.shake

import android.content.Context
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import com.outshake.store.ProfileStore

/**
 * Short toggle haptics fired at the accepted-toggle moment — the same instant as the shake sound —
 * so the shake, UI switch, and QS tile all feel identical. Distinct feel per direction: one crisp
 * tick for ON, a double-tick for OFF. Respects the "Vibrate on toggle" setting and never crashes
 * when the device has no vibrator.
 */
object Haptics {

    enum class Cue { ON, OFF }

    /** One crisp tick for ON; a quick double-tick for OFF. Timings in ms: [waitOff, on, gap, on]. */
    val ON_PATTERN = longArrayOf(0, 40)
    val OFF_PATTERN = longArrayOf(0, 30, 60, 30)

    /**
     * Pure gating + pattern selection, extracted for JVM tests. Returns the vibration timing pattern
     * for [cue], or null when [enabled] is false (setting off) so the caller vibrates nothing.
     */
    fun pattern(cue: Cue, enabled: Boolean): LongArray? {
        if (!enabled) return null
        return when (cue) {
            Cue.ON -> ON_PATTERN
            Cue.OFF -> OFF_PATTERN
        }
    }

    fun fire(context: Context, cue: Cue) {
        val timings = pattern(cue, ProfileStore(context).vibrateOnToggle) ?: return
        val vibrator = vibrator(context) ?: return
        if (!vibrator.hasVibrator()) return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createWaveform(timings, -1))
            } else {
                @Suppress("DEPRECATION") vibrator.vibrate(timings, -1)
            }
        } catch (_: Exception) {
            // A missing/odd vibrator must never take down a toggle.
        }
    }

    private fun vibrator(context: Context): Vibrator? {
        val app = context.applicationContext
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val mgr = app.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
            mgr?.defaultVibrator
        } else {
            @Suppress("DEPRECATION") app.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
        }
    }
}
