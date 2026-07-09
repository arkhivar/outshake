package com.outshake.shake

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import kotlin.math.sqrt

/**
 * Detects deliberate shakes via the accelerometer. Ignores casual motion using a g-force
 * threshold and enforces a cooldown so one shake produces exactly one toggle.
 */
class ShakeDetector(
    private var thresholdG: Float = 2.7f,
    private val cooldownMs: Long = COOLDOWN_MS,
    private val requiredHits: Int = 2,
    private val onShake: () -> Unit,
) : SensorEventListener {

    private var lastTriggerMs = 0L
    private var hitCount = 0
    private var lastHitMs = 0L

    override fun onSensorChanged(event: SensorEvent) {
        if (event.sensor.type != Sensor.TYPE_ACCELEROMETER) return
        val x = event.values[0]
        val y = event.values[1]
        val z = event.values[2]
        val gForce = sqrt(x * x + y * y + z * z) / SensorManager.GRAVITY_EARTH

        val now = System.currentTimeMillis()
        if (gForce <= thresholdG) return

        // Count rapid successive spikes to distinguish a shake from a single bump.
        if (now - lastHitMs > 700) hitCount = 0
        hitCount++
        lastHitMs = now

        if (hitCount >= requiredHits && now - lastTriggerMs > cooldownMs) {
            lastTriggerMs = now
            hitCount = 0
            onShake()
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    fun setSensitivity(thresholdG: Float) { this.thresholdG = thresholdG }

    companion object {
        /** One shake = one toggle for this long, so a single shake can't rapidly flip state. */
        const val COOLDOWN_MS = 5000L

        fun register(context: Context, detector: ShakeDetector): Boolean {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val sensor = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) ?: return false
            return sm.registerListener(detector, sensor, SensorManager.SENSOR_DELAY_GAME)
        }

        fun unregister(context: Context, detector: ShakeDetector) {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            sm.unregisterListener(detector)
        }
    }
}
