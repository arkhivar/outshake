package com.outshake.shake

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HapticsTest {

    @Test
    fun `disabled setting produces no pattern for on`() {
        assertNull(Haptics.pattern(Haptics.Cue.ON, enabled = false))
    }

    @Test
    fun `disabled setting produces no pattern for off`() {
        assertNull(Haptics.pattern(Haptics.Cue.OFF, enabled = false))
    }

    @Test
    fun `enabled on cue is a single tick`() {
        assertArrayEquals(Haptics.ON_PATTERN, Haptics.pattern(Haptics.Cue.ON, enabled = true))
    }

    @Test
    fun `enabled off cue is a double tick`() {
        assertArrayEquals(Haptics.OFF_PATTERN, Haptics.pattern(Haptics.Cue.OFF, enabled = true))
    }

    @Test
    fun `on and off patterns are distinct`() {
        val on = Haptics.pattern(Haptics.Cue.ON, enabled = true)!!
        val off = Haptics.pattern(Haptics.Cue.OFF, enabled = true)!!
        assert(!on.contentEquals(off)) { "ON and OFF haptics must feel different" }
    }
}
