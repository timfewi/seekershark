package dev.seekershark.capture

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class BleObservationStoreTest {
    private fun input(address: String = "AA:BB:CC:DD:EE:01", sid: Int? = null) = BleAdvertisementInput(
        address = address, name = "Sensor", rssi = -61, txPower = -8,
        connectable = true, legacy = true, primaryPhy = 1, secondaryPhy = 0,
        advertisingSid = sid, manufacturerIds = listOf(76),
        serviceUuids = listOf("0000180f-0000-1000-8000-00805f9b34fb"),
        advertisement = byteArrayOf(2, 1, 6),
    )

    @Test fun repeatedCallbacksGroupByCurrentAddressAndAdvertisingSid() {
        val store = BleObservationStore()
        store.observe(input(), 1_000)
        val original = store.snapshot().single()
        store.observe(input("aa:bb:cc:dd:ee:01").copy(rssi = -47), 2_000)
        store.observe(input(sid = 3), 3_000)
        val rows = store.snapshot()
        assertEquals(3L, store.advertisements)
        assertEquals(2, rows.size)
        assertEquals(3, rows.first().advertisingSid)
        val repeated = rows.last()
        assertEquals(original.id, repeated.id)
        assertEquals(2L, repeated.advertisements)
        assertEquals(1_000L, repeated.firstSeen)
        assertEquals(2_000L, repeated.lastSeen)
        assertEquals(-47, repeated.rssi)
        assertEquals(0L, store.droppedObservations)
    }

    @Test fun rotatedAddressesStaySeparateWithoutPhysicalDeviceInference() {
        val store = BleObservationStore()
        store.observe(input(), 1_000)
        store.observe(input("AA:BB:CC:DD:EE:02"), 2_000)
        assertEquals(2, store.snapshot().size)
        assertEquals(listOf(1L, 1L), store.snapshot().map { it.advertisements })
    }

    @Test fun evictsOldestObservationAndCountsOnlyEvictedRows() {
        val store = BleObservationStore(2)
        val first = input()
        val second = input("AA:BB:CC:DD:EE:02")
        store.observe(first, 1_000)
        store.observe(second, 2_000)
        store.observe(first, 3_000)
        store.observe(input("AA:BB:CC:DD:EE:03"), 4_000)
        assertEquals(listOf("AA:BB:CC:DD:EE:03", first.address), store.snapshot().map { it.address })
        assertEquals(1L, store.droppedObservations)
        assertEquals(4L, store.advertisements)
        store.observe(first, 5_000)
        assertEquals(1L, store.droppedObservations)
        assertEquals(5L, store.advertisements)
    }

    @Test fun tiesUseLatestCallbackAndBackwardClockDoesNotReverseRowTimes() {
        val store = BleObservationStore(2)
        val first = input()
        val second = input("AA:BB:CC:DD:EE:02")
        store.observe(first, 1_000)
        store.observe(second, 1_000)
        assertEquals(second.address, store.snapshot().first().address)
        store.observe(first, 500)
        val latest = store.snapshot().first()
        assertEquals(first.address, latest.address)
        assertEquals(1_000L, latest.firstSeen)
        assertEquals(1_000L, latest.lastSeen)
        store.observe(input("AA:BB:CC:DD:EE:03"), 1_000)
        assertFalse(store.snapshot().any { it.address == second.address })
    }

    @Test fun boundsAndSanitizesUntrustedAdvertisementFields() {
        val store = BleObservationStore()
        val uuids = (0 until 50).map { "%08x-0000-1000-8000-00805f9b34fb".format(it) }
        store.observe(input().copy(
            name = "\u0000\u202e" + "x".repeat(100),
            txPower = 127,
            manufacturerIds = (0 until 50).reversed().toList(),
            serviceUuids = uuids,
            advertisement = ByteArray(600) { it.toByte() },
        ), 1_000)
        val row = store.snapshot().single()
        assertTrue(row.name!!.length <= 64)
        assertFalse(row.name!!.any { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() })
        assertNull(row.txPower)
        assertEquals(32, row.manufacturerIds.size)
        assertEquals(row.manufacturerIds.sorted(), row.manufacturerIds)
        assertEquals(32, row.serviceUuids.size)
        assertEquals(1_024, row.advertisementHex.length)
        assertTrue(row.advertisementHex.startsWith("00010203"))
        assertTrue(row.payloadTruncated)
    }

    @Test fun latestCallbackDoesNotInheritAbsentNameOrAdvertisement() {
        val store = BleObservationStore()
        store.observe(input(), 1_000)
        store.observe(input().copy(name = null, advertisement = byteArrayOf(), manufacturerIds = emptyList(), serviceUuids = emptyList()), 2_000)
        val row = store.snapshot().single()
        assertNull(row.name)
        assertEquals("", row.advertisementHex)
        assertEquals(emptyList<Int>(), row.manufacturerIds)
        assertEquals(emptyList<String>(), row.serviceUuids)
        assertFalse(row.payloadTruncated)
    }

    @Test fun flagsPartialPayloadAndRejectsInvalidMetadataWithoutExtendingLists() {
        val store = BleObservationStore()
        store.observe(input(sid = 255).copy(
            name = "\u0000\n\u202e", manufacturerIds = listOf(-1, 76, 76, 65536),
            serviceUuids = listOf("not-a-uuid", "0000180F-0000-1000-8000-00805F9B34FB"),
            payloadTruncated = true,
        ), 1_000)
        val row = store.snapshot().single()
        assertNull(row.name)
        assertNull(row.advertisingSid)
        assertEquals(listOf(76), row.manufacturerIds)
        assertEquals(listOf("0000180f-0000-1000-8000-00805f9b34fb"), row.serviceUuids)
        assertTrue(row.payloadTruncated)
    }

    @Test fun clearingResetsCountersAndOpaqueIdentity() {
        val store = BleObservationStore(1)
        store.observe(input(), 1_000)
        val before = store.snapshot().single().id
        assertFalse(before.contains(input().address))
        store.observe(input("AA:BB:CC:DD:EE:02"), 2_000)
        store.clear()
        assertEquals(0L, store.advertisements)
        assertEquals(0L, store.droppedObservations)
        assertTrue(store.snapshot().isEmpty())
        store.observe(input(), 3_000)
        val after = store.snapshot().single().id
        assertNotEquals(before, after)
        val another = BleObservationStore().apply { observe(input(), 3_000) }
        assertNotEquals(after, another.snapshot().single().id)
    }

    @Test fun durationAndStorageLimitsAreValidated() {
        assertEquals(60, BlePolicy.DEFAULT_DURATION_SECONDS)
        for (seconds in listOf(10, 60, 120)) assertEquals(seconds, BlePolicy.validateDuration(seconds))
        for (seconds in listOf(Int.MIN_VALUE, 9, 121, Int.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { BlePolicy.validateDuration(seconds) }
        }
        for (limit in listOf(0, 257)) {
            assertThrows(IllegalArgumentException::class.java) { BleObservationStore(limit) }
        }
    }

    @Test fun concurrentCallbacksRetainExactBoundedCounts() {
        val store = BleObservationStore()
        val workers = Executors.newFixedThreadPool(4)
        try {
            val jobs = (0 until 4).map { worker -> workers.submit {
                repeat(100) { index ->
                    val address = "AA:BB:CC:DD:EE:%02X".format(index % 10)
                    store.observe(input(address), (worker * 100 + index).toLong())
                    assertTrue(store.snapshot().size <= 10)
                }
            } }
            jobs.forEach { it.get(10, TimeUnit.SECONDS) }
            assertEquals(400L, store.advertisements)
            assertEquals(0L, store.droppedObservations)
            assertEquals(10, store.snapshot().size)
            assertEquals(400L, store.snapshot().sumOf { it.advertisements })
        } finally { workers.shutdownNow() }
    }
}
