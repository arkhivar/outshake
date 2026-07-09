package com.outshake.shake

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Re-arms shake detection after a reboot if the user has shake mode enabled. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            ShakeService.start(context)
        }
    }
}
