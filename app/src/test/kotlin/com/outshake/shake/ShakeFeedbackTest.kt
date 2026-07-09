package com.outshake.shake

import org.junit.Assert.assertEquals
import org.junit.Test

class ShakeFeedbackTest {

    @Test
    fun `cooldown default is five seconds`() {
        assertEquals(5000L, ShakeDetector.COOLDOWN_MS)
    }

    @Test
    fun `connecting maps to vpn-on cue`() {
        assertEquals(ShakeService.Feedback.VPN_ON, ShakeService.feedbackFor("Connecting"))
    }

    @Test
    fun `disconnecting maps to vpn-off cue`() {
        assertEquals(ShakeService.Feedback.VPN_OFF, ShakeService.feedbackFor("Disconnecting"))
    }

    @Test
    fun `no active profile maps to a message`() {
        assertEquals(ShakeService.Feedback.MESSAGE, ShakeService.feedbackFor("No active profile"))
    }

    @Test
    fun `busy transition produces no cue`() {
        assertEquals(ShakeService.Feedback.NONE, ShakeService.feedbackFor("Busy — ignoring shake"))
    }
}
