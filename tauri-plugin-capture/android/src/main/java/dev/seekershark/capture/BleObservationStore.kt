package dev.seekershark.capture

import java.util.Locale
import java.util.UUID

/** Resource limits for foreground Bluetooth LE advertisement observation. */
internal object BlePolicy {
    const val MAX_OBSERVATIONS = 256
    const val MAX_ADVERTISEMENT_BYTES = 512
    const val MAX_NAME_CHARACTERS = 64
    const val MAX_LIST_ITEMS = 32
    const val DEFAULT_DURATION_SECONDS = 60

    fun validateDuration(seconds: Int): Int {
        require(seconds in 10..120) { "Choose a BLE scan duration between 10 and 120 seconds." }
        return seconds
    }
}

/** One Android scan callback, not a count of physical devices or radio packets. */
internal data class BleAdvertisementInput(
    val address: String,
    val name: String?,
    val rssi: Int,
    val txPower: Int?,
    val connectable: Boolean,
    val legacy: Boolean,
    val primaryPhy: Int,
    val secondaryPhy: Int,
    val advertisingSid: Int?,
    val manufacturerIds: List<Int>,
    val serviceUuids: List<String>,
    val advertisement: ByteArray,
    val payloadTruncated: Boolean = false,
)

internal data class BleObservation(
    val id: String,
    val address: String,
    val name: String?,
    val rssi: Int,
    val txPower: Int?,
    val connectable: Boolean,
    val legacy: Boolean,
    val primaryPhy: Int,
    val secondaryPhy: Int,
    val advertisingSid: Int?,
    val manufacturerIds: List<Int>,
    val serviceUuids: List<String>,
    val advertisementHex: String,
    val payloadTruncated: Boolean,
    val firstSeen: Long,
    val lastSeen: Long,
    val advertisements: Long,
)

/**
 * Bounded scan-local aggregation. Addresses and advertising SIDs identify rows only
 * within this scan; random address rotation can produce several rows for one device.
 * The latest callback replaces its row's fields, including missing name/payload data.
 */
internal class BleObservationStore(val maxObservations: Int = BlePolicy.MAX_OBSERVATIONS) {
    private data class Key(val address: String, val advertisingSid: Int?)
    private data class Entry(val observation: BleObservation, val order: Long)

    private val rows = linkedMapOf<Key, Entry>()
    private var sessionId = UUID.randomUUID().toString()
    private var sequence = 0L

    @Volatile var advertisements = 0L
        private set
    @Volatile var droppedObservations = 0L
        private set

    init {
        require(maxObservations in 1..BlePolicy.MAX_OBSERVATIONS) { "The BLE observation limit must be between 1 and 256." }
    }

    @Synchronized
    fun observe(input: BleAdvertisementInput, nowMillis: Long) {
        advertisements = increment(advertisements)
        sequence = increment(sequence)
        val address = input.address.take(64).filterNot { it.isISOControl() }.uppercase(Locale.ROOT)
        val sid = input.advertisingSid?.takeIf { it in 0..15 }
        val key = Key(address, sid)
        val previous = rows[key]?.observation
        if (previous == null && rows.size >= maxObservations) {
            val oldest = rows.minWithOrNull(compareBy<Map.Entry<Key, Entry>> { it.value.observation.lastSeen }
                .thenBy { it.value.order })!!.key
            rows.remove(oldest)
            droppedObservations = increment(droppedObservations)
        }
        val observedAt = nowMillis.coerceAtLeast(0L)
        val observation = BleObservation(
            id = previous?.id ?: "$sessionId-$sequence",
            address = address,
            name = cleanName(input.name),
            rssi = input.rssi,
            txPower = input.txPower?.takeUnless { it == 127 },
            connectable = input.connectable,
            legacy = input.legacy,
            primaryPhy = input.primaryPhy,
            secondaryPhy = input.secondaryPhy,
            advertisingSid = sid,
            manufacturerIds = input.manufacturerIds.asSequence().take(BlePolicy.MAX_LIST_ITEMS)
                .filter { it in 0..65535 }.distinct().sorted().toList(),
            serviceUuids = input.serviceUuids.asSequence().take(BlePolicy.MAX_LIST_ITEMS)
                .mapNotNull { cleanUuid(it) }.distinct().sorted().toList(),
            advertisementHex = hex(input.advertisement),
            payloadTruncated = input.payloadTruncated || input.advertisement.size > BlePolicy.MAX_ADVERTISEMENT_BYTES,
            firstSeen = previous?.firstSeen ?: observedAt,
            lastSeen = maxOf(previous?.lastSeen ?: observedAt, observedAt),
            advertisements = increment(previous?.advertisements ?: 0L),
        )
        rows[key] = Entry(observation, sequence)
    }

    @Synchronized
    fun clear() {
        rows.clear()
        advertisements = 0L
        droppedObservations = 0L
        sequence = 0L
        sessionId = UUID.randomUUID().toString()
    }

    @Synchronized
    fun snapshot(): List<BleObservation> = rows.values
        .sortedWith(compareByDescending<Entry> { it.observation.lastSeen }.thenByDescending { it.order })
        .map { it.observation }

    private fun cleanName(value: String?): String? {
        var name = value?.take(BlePolicy.MAX_NAME_CHARACTERS)?.filterNot {
            it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt()
        }?.trim() ?: return null
        // Do not leave half of a UTF-16 surrogate pair at the display boundary.
        if (name.lastOrNull()?.isHighSurrogate() == true) name = name.dropLast(1)
        return name.takeIf { it.isNotEmpty() }
    }

    private fun cleanUuid(value: String): String? {
        if (value.length != 36) return null
        return try { UUID.fromString(value).toString() } catch (_: IllegalArgumentException) { null }
    }

    private fun hex(value: ByteArray): String {
        val size = minOf(value.size, BlePolicy.MAX_ADVERTISEMENT_BYTES)
        val result = CharArray(size * 2)
        for (index in 0 until size) {
            val byte = value[index].toInt() and 255
            result[index * 2] = HEX[byte ushr 4]
            result[index * 2 + 1] = HEX[byte and 15]
        }
        return String(result)
    }

    private fun increment(value: Long) = if (value == Long.MAX_VALUE) value else value + 1

    companion object { private const val HEX = "0123456789abcdef" }
}
