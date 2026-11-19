package dev.seekershark.capture

import org.junit.Assert.*
import org.junit.Test

class NearbyPolicyTest {
    @Test fun boundsRejectTruncatedAndOversizedCaptures() {
        assertFalse(NearbyPolicy.captureSize(23))
        assertTrue(NearbyPolicy.captureSize(24))
        assertTrue(NearbyPolicy.captureSize(NearbyPolicy.MAX_CAPTURE_BYTES))
        assertFalse(NearbyPolicy.captureSize(NearbyPolicy.MAX_CAPTURE_BYTES + 1))
        assertFalse(NearbyPolicy.captureSize(Long.MAX_VALUE))
    }

    @Test fun namesCannotBecomePathsOrHiddenFiles() {
        val name = NearbyPolicy.captureName("../../private/capture\u0000.pcap")
        assertFalse(name.startsWith('.'))
        assertFalse(name.contains('/'))
        assertFalse(name.contains('\u0000'))
        assertTrue(name.endsWith(".pcap"))
        assertTrue(NearbyPolicy.captureName("a".repeat(400)).length <= 105)
    }

    @Test fun recognisesClassicPcapButNotPcapngOrArbitraryFiles() {
        for (magic in listOf(0xd4c3b2a1L, 0xa1b2c3d4L, 0x4d3cb2a1L, 0xa1b23c4dL)) {
            val bytes = ByteArray(4) { ((magic shr ((3 - it) * 8)) and 255).toByte() }
            assertTrue(NearbyPolicy.pcapHeader(bytes))
        }
        assertFalse(NearbyPolicy.pcapHeader(byteArrayOf(10, 13, 13, 10)))
        assertFalse(NearbyPolicy.pcapHeader(byteArrayOf(1, 2, 3)))
    }

    @Test fun deviceNamesRequireVisibleBoundedText() {
        assertEquals("My Seeker", NearbyPolicy.deviceName("  My Seeker  "))
        assertEquals("x".repeat(32), NearbyPolicy.deviceName("x".repeat(32)))
        for (value in listOf("", " ", "a\nb", "x".repeat(33))) {
            assertThrows(IllegalArgumentException::class.java) { NearbyPolicy.deviceName(value) }
        }
    }
}
