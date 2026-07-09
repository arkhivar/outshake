package com.outshake.shake

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioAttributes
import android.media.SoundPool
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.widget.Toast
import androidx.core.content.ContextCompat
import com.outshake.R
import com.outshake.store.ProfileStore
import com.outshake.ui.MainActivity
import com.outshake.vpn.ConnectionManager

/**
 * Long-lived foreground service that runs the accelerometer shake listener whenever shake mode is
 * enabled — independent of VPN state and surviving activity destruction. On a recognized shake it
 * toggles the active profile via the shared [ConnectionManager] (no connect/disconnect logic here)
 * and gives immediate sound + toast feedback at the moment the toggle is accepted.
 */
class ShakeService : Service() {

    private var detector: ShakeDetector? = null
    private var soundPool: SoundPool? = null
    private var onSoundId = 0
    private var offSoundId = 0
    private val main = Handler(Looper.getMainLooper())

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val attrs = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT) // notification stream → muted in silent/vibrate
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
        val pool = SoundPool.Builder().setMaxStreams(1).setAudioAttributes(attrs).build()
        onSoundId = pool.load(this, R.raw.shake_on, 1)
        offSoundId = pool.load(this, R.raw.shake_off, 1)
        soundPool = pool
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        if (!ProfileStore(this).shakeEnabled) {
            stopSelf()
            return START_NOT_STICKY
        }
        registerDetector()
        // START_STICKY: if the OS kills us under memory pressure, restart (while still enabled).
        return START_STICKY
    }

    private fun registerDetector() {
        if (detector != null) return
        val store = ProfileStore(this)
        val d = ShakeDetector(thresholdG = store.shakeSensitivity) { onShakeAccepted() }
        if (ShakeDetector.register(this, d)) detector = d
    }

    private fun onShakeAccepted() {
        // toggle() is the single source of truth; it returns the action it took.
        when (feedbackFor(ConnectionManager.toggle(this))) {
            Feedback.VPN_ON -> feedback(onSoundId, "VPN activated")
            Feedback.VPN_OFF -> feedback(offSoundId, "VPN off")
            Feedback.MESSAGE -> toast("No active profile — open Outshake to pick one")
            Feedback.NONE -> { /* busy mid-transition: shake not accepted, no feedback */ }
        }
    }

    private fun feedback(soundId: Int, message: String) {
        soundPool?.play(soundId, VOLUME, VOLUME, 1, 0, 1f)
        toast(message)
    }

    private fun toast(message: String) {
        // Text toasts from a foreground service are permitted on modern Android; never crash.
        main.post {
            try {
                Toast.makeText(applicationContext, message, Toast.LENGTH_SHORT).show()
            } catch (_: Exception) {
            }
        }
    }

    override fun onDestroy() {
        detector?.let { ShakeDetector.unregister(this, it) }
        detector = null
        soundPool?.release()
        soundPool = null
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Shake detection", NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Shows while Outshake listens for a shake to toggle the VPN." }
            nm.createNotificationChannel(channel)
        }
        val pending = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        return builder
            .setContentTitle("Outshake")
            .setContentText("Shake detection active")
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
    }

    /** Which sound/visual cue a shake produced, derived from [ConnectionManager.toggle]'s result. */
    enum class Feedback { VPN_ON, VPN_OFF, MESSAGE, NONE }

    companion object {
        /** Pure map from [ConnectionManager.toggle]'s return string to the feedback to present. */
        fun feedbackFor(toggleResult: String): Feedback = when (toggleResult) {
            "Connecting" -> Feedback.VPN_ON
            "Disconnecting" -> Feedback.VPN_OFF
            "No active profile" -> Feedback.MESSAGE
            else -> Feedback.NONE
        }

        private const val CHANNEL_ID = "outshake_shake"
        private const val NOTIFICATION_ID = 2
        private const val VOLUME = 0.35f

        /** Start the service iff shake mode is enabled. Safe to call repeatedly (idempotent). */
        fun start(context: Context) {
            if (!ProfileStore(context).shakeEnabled) return
            val app = context.applicationContext
            ContextCompat.startForegroundService(app, Intent(app, ShakeService::class.java))
        }

        fun stop(context: Context) {
            val app = context.applicationContext
            app.stopService(Intent(app, ShakeService::class.java))
        }

        /** Reflect the current setting: start if enabled, stop if disabled. */
        fun sync(context: Context) {
            if (ProfileStore(context).shakeEnabled) start(context) else stop(context)
        }
    }
}
