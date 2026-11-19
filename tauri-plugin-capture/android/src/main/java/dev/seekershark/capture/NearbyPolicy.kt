package dev.seekershark.capture

/** Limits shared by discovery, temporary capture storage, and transfer validation. */
internal object NearbyPolicy {
    const val MAX_CAPTURE_BYTES = 40L * 1024 * 1024
    const val MAX_PEERS = 32
    const val MAX_INBOX = 3
    const val MAX_TRANSFERS = 8
    const val MAX_METADATA_BYTES = 1024

    fun deviceName(value: String): String {
        val name = value.trim()
        require(name.isNotEmpty() && name.length <= 32 && name.none { it.isISOControl() }) {
            "Choose a device name with 1–32 visible characters."
        }
        return name
    }

    fun captureName(value: String): String {
        var name = value.replace(Regex("[^A-Za-z0-9_.-]"), "_").take(100)
            .trimStart('.')
        if (name.isEmpty()) name = "capture"
        if (!name.endsWith(".pcap", ignoreCase = true)) name += ".pcap"
        return name
    }

    fun captureSize(size: Long): Boolean = size in 24..MAX_CAPTURE_BYTES

    fun pcapHeader(header: ByteArray): Boolean {
        if (header.size < 4) return false
        val magic = header.take(4).map { it.toInt() and 255 }
        return magic == listOf(0xd4, 0xc3, 0xb2, 0xa1) ||
            magic == listOf(0xa1, 0xb2, 0xc3, 0xd4) ||
            magic == listOf(0x4d, 0x3c, 0xb2, 0xa1) ||
            magic == listOf(0xa1, 0xb2, 0x3c, 0x4d)
    }
}
