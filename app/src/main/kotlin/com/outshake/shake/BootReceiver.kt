package com.outshake.shake

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat
import com.outshake.R
import com.outshake.store.ProfileStore
import com.outshake.ui.MainActivity
import com.outshake.vpn.OutshakeVpnService

/**
 * On boot: re-arm shake detection (if enabled) and, when connect-on-boot is enabled, start the VPN
 * for the active profile. VPN consent must already be granted; if it is missing we cannot prompt
 * from a receiver, so we post a notification instead of crashing.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        ShakeService.start(context)

        val store = ProfileStore(context)
        if (!store.connectOnBoot) return
        val active = store.activeProfile() ?: return

        if (VpnService.prepare(context) != null) {
            // Consent not granted (or was revoked) — cannot show the system prompt at boot.
            notifyConsentNeeded(context)
            return
        }
        try {
            val svc = Intent(context, OutshakeVpnService::class.java).apply {
                action = OutshakeVpnService.ACTION_CONNECT
                putExtra(OutshakeVpnService.EXTRA_PROFILE_ID, active.id)
            }
            ContextCompat.startForegroundService(context, svc)
        } catch (_: Exception) {
            notifyConsentNeeded(context)
        }
    }

    private fun notifyConsentNeeded(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Connect on boot", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val pending = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(context, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(context)
        }
        val n = builder
            .setContentTitle("Outshake")
            .setContentText("Open Outshake to grant VPN permission for connect-on-boot")
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        try { nm.notify(NOTIFICATION_ID, n) } catch (_: Exception) {}
    }

    private companion object {
        const val CHANNEL_ID = "outshake_boot"
        const val NOTIFICATION_ID = 3
    }
}
