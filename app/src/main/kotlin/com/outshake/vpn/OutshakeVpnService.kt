package com.outshake.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.outshake.R
import com.outshake.config.Profile
import com.outshake.config.ProfileImporter
import com.outshake.store.ProfileStore
import com.outshake.transport.ShadowsocksClient
import com.outshake.ui.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/** Android VpnService that establishes the TUN and runs the tun2socks + Shadowsocks pipeline. */
class OutshakeVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var engine: Tun2SocksEngine? = null
    @Volatile private var currentProfile: Profile? = null

    private var connectivity: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val sawInitialNetwork = AtomicBoolean(false)
    private val reconnecting = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                ProfileStore(this).shouldBeConnected = true
                startTunnel(intent.getStringExtra(EXTRA_PROFILE_ID))
                return START_STICKY
            }
            ACTION_DISCONNECT -> {
                ProfileStore(this).shouldBeConnected = false
                stopTunnel()
                return START_NOT_STICKY
            }
            else -> {
                // Null intent = the OS restarted us after a process-death/memory kill (START_STICKY).
                // Re-establish only if the user's persisted intent says we should be connected.
                val store = ProfileStore(this)
                val active = store.activeProfile()
                if (intent == null && store.shouldBeConnected && active != null) {
                    startTunnel(active.id)
                    return START_STICKY
                }
                stopTunnel()
                return START_NOT_STICKY
            }
        }
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
                // Upfront reachability probe. For dynamic (ssconf) profiles, a failure triggers a
                // single config re-fetch + retry before the error is surfaced (never loops).
                val resolved = ConnectRetry.resolve(
                    profile,
                    probe = { p -> probeServer(p) },
                    refresh = { p ->
                        val updated = ProfileImporter.refresh(p)
                        ProfileStore(this).addOrUpdate(updated)
                        updated
                    },
                )
                currentProfile = resolved
                if (!establishTunnel(resolved)) throw IllegalStateException("VPN not authorized")
                registerNetworkCallback()
                ConnectionManager.onConnected()
            } catch (e: Exception) {
                Log.e(TAG, "tunnel start failed", e)
                ConnectionManager.onError(e.message ?: "Failed to start VPN")
                stopTunnel()
            }
        }.start()
    }

    /** Open (and immediately close) a protected TCP socket to the server to confirm reachability. */
    private fun probeServer(profile: Profile) {
        val socket = Socket()
        try {
            protect(socket)
            socket.connect(
                InetSocketAddress(profile.transport.host, profile.transport.port), PROBE_TIMEOUT_MS
            )
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    /** Build a fresh TUN + engine for [profile], tearing down any previous one. */
    private fun establishTunnel(profile: Profile): Boolean {
        engine?.stop()
        engine = null
        try { tun?.close() } catch (_: Exception) {}
        tun = null

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
        val pfd = builder.establish() ?: return false
        tun = pfd

        val client = ShadowsocksClient(profile.transport)
        val protector = object : SocketProtector {
            override fun protect(socket: Socket): Boolean = this@OutshakeVpnService.protect(socket)
            override fun protect(socket: java.net.DatagramSocket): Boolean =
                this@OutshakeVpnService.protect(socket)
        }
        val eng = Tun2SocksEngine(
            FileInputStream(pfd.fileDescriptor),
            FileOutputStream(pfd.fileDescriptor),
            client,
            protector,
        )
        engine = eng
        eng.start()
        return true
    }

    /** Re-establish the tunnel on the new default network without user action. */
    private fun reconnect() {
        val profile = currentProfile ?: return
        if (!reconnecting.compareAndSet(false, true)) return
        ConnectionManager.onReconnecting()
        Thread {
            try {
                if (establishTunnel(profile)) ConnectionManager.onConnected()
                else throw IllegalStateException("VPN not authorized")
            } catch (e: Exception) {
                Log.w(TAG, "reconnect failed: ${e.message}")
                ConnectionManager.onError(e.message ?: "Reconnect failed")
                stopTunnel()
            } finally {
                reconnecting.set(false)
            }
        }.start()
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // The first callback is the network we're already on; only react to later changes.
                if (sawInitialNetwork.compareAndSet(false, true)) return
                reconnect()
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            connectivity = cm
            networkCallback = cb
        } catch (e: Exception) {
            Log.w(TAG, "network callback registration failed: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        val cm = connectivity
        val cb = networkCallback
        if (cm != null && cb != null) {
            try { cm.unregisterNetworkCallback(cb) } catch (_: Exception) {}
        }
        networkCallback = null
        connectivity = null
        sawInitialNetwork.set(false)
    }

    private fun stopTunnel() {
        unregisterNetworkCallback()
        engine?.stop()
        engine = null
        currentProfile = null
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
        unregisterNetworkCallback()
        engine?.stop()
        try { tun?.close() } catch (_: Exception) {}
        super.onDestroy()
    }

    override fun onRevoke() {
        ProfileStore(this).shouldBeConnected = false
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
        private const val PROBE_TIMEOUT_MS = 8000
        private const val TAG = "OutshakeVpn"
    }
}
