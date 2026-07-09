package com.outshake.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.outshake.R
import com.outshake.config.Profile
import com.outshake.store.ProfileStore
import com.outshake.transport.ShadowsocksClient
import com.outshake.ui.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream

/** Android VpnService that establishes the TUN and runs the tun2socks + Shadowsocks pipeline. */
class OutshakeVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var engine: Tun2SocksEngine? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val id = intent.getStringExtra(EXTRA_PROFILE_ID)
                startTunnel(id)
            }
            ACTION_DISCONNECT -> stopTunnel()
            else -> stopTunnel()
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(profileId: String?) {
        val profile: Profile? = profileId?.let { pid ->
            ProfileStore(this).getProfiles().firstOrNull { it.id == pid }
        }
        if (profile == null) {
            ConnectionManager.onError("Active profile not found")
            stopSelf()
            return
        }
        startForeground(NOTIFICATION_ID, buildNotification(profile.name))
        Thread {
            try {
                val builder = Builder()
                    .setSession(profile.name)
                    .setMtu(1500)
                    .addAddress("10.111.222.1", 24)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    .addRoute("0.0.0.0", 0)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
                }
                val pfd = builder.establish() ?: throw IllegalStateException("VPN not authorized")
                tun = pfd

                val client = ShadowsocksClient(profile.transport)
                val eng = Tun2SocksEngine(
                    FileInputStream(pfd.fileDescriptor),
                    FileOutputStream(pfd.fileDescriptor),
                    client,
                ) { socket -> protect(socket) }
                engine = eng
                eng.start()
                ConnectionManager.onConnected()
            } catch (e: Exception) {
                Log.e(TAG, "tunnel start failed", e)
                ConnectionManager.onError(e.message ?: "Failed to start VPN")
                stopTunnel()
            }
        }.start()
    }

    private fun stopTunnel() {
        engine?.stop()
        engine = null
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        ConnectionManager.onDisconnected()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION") stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        engine?.stop()
        try { tun?.close() } catch (_: Exception) {}
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    private fun buildNotification(profileName: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)
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
            .setContentTitle("Outshake connected")
            .setContentText("Tunneling via $profileName")
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_CONNECT = "com.outshake.CONNECT"
        const val ACTION_DISCONNECT = "com.outshake.DISCONNECT"
        const val EXTRA_PROFILE_ID = "profile_id"
        private const val CHANNEL_ID = "outshake_vpn"
        private const val NOTIFICATION_ID = 1
        private const val TAG = "OutshakeVpn"
    }
}
