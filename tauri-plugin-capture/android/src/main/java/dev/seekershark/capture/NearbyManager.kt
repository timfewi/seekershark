package dev.seekershark.capture

import android.app.Activity
import android.bluetooth.BluetoothManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Base64
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import app.tauri.plugin.JSObject
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsStatusCodes
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Foreground, explicitly paired PCAP exchange. This never captures another device. */
internal class NearbyManager(private val activity: Activity) : DefaultLifecycleObserver {
    private data class Peer(val id: String, var name: String, var state: String, var code: String? = null)
    private data class Transfer(
        val id: String, val endpointId: String, val peerName: String,
        var name: String, var bytes: Long, var total: Long, var state: String,
        var error: String? = null, var file: File? = null, var payload: Payload? = null,
    )
    private data class Incoming(
        val endpointId: String, var payload: Payload? = null,
        var expectedSize: Long? = null, var complete: Boolean = false, var copying: Boolean = false,
    )

    private val lock = Any()
    private val main = Handler(Looper.getMainLooper())
    private val client by lazy { Nearby.getConnectionsClient(activity) }
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, ArrayBlockingQueue(2))
    private val peers = linkedMapOf<String, Peer>()
    private val transfers = linkedMapOf<String, Transfer>()
    private val incoming = mutableMapOf<Long, Incoming>()
    private val preparingFiles = mutableSetOf<File>()
    private val timeouts = mutableMapOf<String, Runnable>()
    private var active = false
    private var discovering = false
    private var generation = 0L
    private var name = "SeekerShark"
    private var lastError: String? = null
    private var sendPreparing = false
    private val cache = File(activity.cacheDir, "nearby-captures")

    init {
        (activity as? LifecycleOwner)?.lifecycle?.addObserver(this)
        // Only our ephemeral directory is touched; no Downloads or user-selected paths.
        io({}) { cache.deleteRecursively(); cache.mkdirs() }
    }

    private fun available() = GoogleApiAvailability.getInstance()
        .isGooglePlayServicesAvailable(activity) == ConnectionResult.SUCCESS

    fun status(): JSObject = synchronized(lock) { snapshotLocked() }

    fun isActive(): Boolean = synchronized(lock) { active }

    private fun snapshotLocked() = JSObject().apply {
        put("supported", available())
        put("active", active)
        put("name", name)
        put("lastError", lastError ?: JSONObject.NULL)
        put("peers", JSONArray().apply {
            peers.values.forEach { peer -> put(JSONObject().apply {
                put("id", peer.id); put("name", peer.name); put("state", peer.state)
                put("authenticationCode", peer.code ?: JSONObject.NULL)
            }) }
        })
        put("transfers", JSONArray().apply {
            transfers.values.forEach { transfer -> put(JSONObject().apply {
                put("id", transfer.id); put("peerName", transfer.peerName); put("name", transfer.name)
                put("bytes", transfer.bytes); put("totalBytes", transfer.total)
                put("state", transfer.state); put("error", transfer.error ?: JSONObject.NULL)
            }) }
        })
    }

    fun start(requestedName: String): JSObject = synchronized(lock) {
        check(available()) { "Nearby requires an up-to-date Google Play services installation." }
        check(!active) { "Nearby is already active. Stop it before changing the device name." }
        name = NearbyPolicy.deviceName(requestedName)
        val bluetooth = activity.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        check(bluetooth.adapter?.isEnabled == true) { "Turn on Bluetooth and Wi-Fi, then start Nearby again." }
        lastError = null
        active = true
        val session = ++generation
        try {
            resumeDiscoveryLocked(session)
        } catch (error: Exception) {
            stopLocked()
            throw IllegalStateException("Could not start Nearby. Check Bluetooth, Wi-Fi and permissions.", error)
        }
        snapshotLocked()
    }

    private fun resumeDiscoveryLocked(session: Long) {
        if (!active || discovering || generation != session || peers.values.any { it.state == "connected" }) return
        discovering = true
        client.startAdvertising(name, SERVICE_ID, connectionCallback(session),
            AdvertisingOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build())
            .addOnFailureListener { error -> startupFailed(session, error) }
        client.startDiscovery(SERVICE_ID, discoveryCallback(session),
            DiscoveryOptions.Builder().setStrategy(Strategy.P2P_POINT_TO_POINT).build())
            .addOnFailureListener { error -> startupFailed(session, error) }
    }

    private fun startupFailed(session: Long, error: Exception) = synchronized(lock) {
        if (generation != session || !active) return@synchronized
        stopLocked()
        lastError = "Nearby could not start. Check Bluetooth, Wi-Fi, location settings and permissions. ${error.message.orEmpty().take(180)}"
    }

    fun stop(): JSObject = synchronized(lock) { stopLocked(); snapshotLocked() }

    private fun stopLocked() {
        active = false
        discovering = false
        generation++
        sendPreparing = false
        timeouts.values.forEach { main.removeCallbacks(it) }; timeouts.clear()
        try {
            client.stopAdvertising(); client.stopDiscovery(); client.stopAllEndpoints()
            incoming.keys.forEach { client.cancelPayload(it) }
        } catch (_: Exception) { /* Permission revocation must still clear local state. */ }
        incoming.values.mapNotNull { it.payload }.forEach { releasePayload(it) }
        incoming.clear()
        transfers.values.mapNotNull { it.payload }.forEach { releasePayload(it) }
        transfers.values.mapNotNull { it.file }.forEach { it.delete() }
        preparingFiles.forEach { it.delete() }; preparingFiles.clear()
        peers.clear(); transfers.clear()
        // A worker may still hold an old generation. It deletes its output before returning.
    }

    override fun onStop(owner: LifecycleOwner) { stop() }
    override fun onDestroy(owner: LifecycleOwner) {
        stop(); worker.shutdown()
        owner.lifecycle.removeObserver(this)
    }

    fun connect(endpointId: String): JSObject = synchronized(lock) {
        check(active) { "Start Nearby first." }
        val peer = peers[endpointId] ?: error("This device is no longer nearby.")
        check(peer.state == "found") { "A connection to this device is already in progress." }
        check(peers.values.none { it.state != "found" }) { "Disconnect the current device before pairing another." }
        peer.state = "connecting"; lastError = null
        val session = generation
        client.requestConnection(name, endpointId, connectionCallback(session))
            .addOnFailureListener { error -> synchronized(lock) {
                if (generation == session) {
                    peers[endpointId]?.let { it.state = "found"; it.code = null }
                    lastError = "Could not connect. ${error.message.orEmpty().take(180)}"
                }
            } }
        snapshotLocked()
    }

    fun confirm(endpointId: String, accept: Boolean): JSObject = synchronized(lock) {
        val peer = peers[endpointId] ?: error("The pairing request has expired.")
        check(active && peer.state == "confirming") { "There is no pairing request to confirm." }
        if (!accept) {
            cancelTimeoutLocked("pair:$endpointId")
            client.rejectConnection(endpointId)
            peer.state = "found"; peer.code = null
        } else {
            check(!peer.code.isNullOrEmpty()) { "No verification code is available. Reject and reconnect." }
            // Both devices must explicitly accept; there is never an automatic accept path.
            peer.state = "connecting"; peer.code = null
            val session = generation
            client.acceptConnection(endpointId, payloadCallback(session))
                .addOnFailureListener { error -> synchronized(lock) {
                    if (generation == session) {
                        client.disconnectFromEndpoint(endpointId)
                        peers.remove(endpointId)
                        lastError = "Pairing failed. ${error.message.orEmpty().take(180)}"
                    }
                } }
        }
        snapshotLocked()
    }

    fun disconnect(endpointId: String): JSObject = synchronized(lock) {
        client.disconnectFromEndpoint(endpointId)
        disconnectedLocked(endpointId)
        snapshotLocked()
    }

    private fun discoveryCallback(session: Long) = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) = synchronized(lock) {
            if (!active || generation != session || info.serviceId != SERVICE_ID) return@synchronized
            if (peers.size >= NearbyPolicy.MAX_PEERS && !peers.containsKey(endpointId)) return@synchronized
            peers.getOrPut(endpointId) { Peer(endpointId, info.endpointName.take(80), "found") }
            Unit
        }
        override fun onEndpointLost(endpointId: String) = synchronized(lock) {
            if (generation == session && peers[endpointId]?.state == "found") peers.remove(endpointId)
            Unit
        }
    }

    private fun connectionCallback(session: Long) = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) = synchronized(lock) {
            if (!active || generation != session) return@synchronized
            if (peers.values.any { it.id != endpointId && it.state != "found" } ||
                (peers.size >= NearbyPolicy.MAX_PEERS && !peers.containsKey(endpointId))) {
                client.rejectConnection(endpointId); return@synchronized
            }
            val code = info.authenticationDigits
            if (code.isNullOrEmpty()) {
                client.rejectConnection(endpointId)
                lastError = "Pairing was rejected because no verification code was available."
                return@synchronized
            }
            val pending = Peer(endpointId, info.endpointName.take(80), "confirming", code)
            peers[endpointId] = pending
            // Pending requests expire instead of remaining trusted indefinitely.
            scheduleLocked("pair:$endpointId", PAIRING_TIMEOUT_MS) {
                if (generation == session && peers[endpointId] === pending && pending.state in listOf("confirming", "connecting")) {
                    client.rejectConnection(endpointId); client.disconnectFromEndpoint(endpointId)
                    peers.remove(endpointId)
                    lastError = "Pairing expired. Find the device and try again."
                }
            }
            Unit
        }
        override fun onConnectionResult(endpointId: String, result: ConnectionResolution) = synchronized(lock) {
            if (!active || generation != session) return@synchronized
            cancelTimeoutLocked("pair:$endpointId")
            val peer = peers[endpointId] ?: run { client.disconnectFromEndpoint(endpointId); return@synchronized }
            if (result.status.statusCode == ConnectionsStatusCodes.STATUS_OK && peer.state == "connecting") {
                peer.state = "connected"; peer.code = null
                discovering = false
                client.stopAdvertising(); client.stopDiscovery()
            } else {
                client.disconnectFromEndpoint(endpointId)
                peers.remove(endpointId)
                lastError = "The connection was rejected or could not be established. Stop Nearby and try again."
            }
        }
        override fun onDisconnected(endpointId: String) = synchronized(lock) {
            if (generation == session) disconnectedLocked(endpointId)
        }
    }

    private fun disconnectedLocked(endpointId: String) {
        cancelTimeoutLocked("pair:$endpointId")
        peers.remove(endpointId)
        transfers.values.filter { it.endpointId == endpointId && it.state in listOf("sending", "receiving") }
            .forEach { transfer -> failLocked(transfer.id.toLong(), "The device disconnected.") }
        try { resumeDiscoveryLocked(generation) }
        catch (_: Exception) {
            stopLocked(); lastError = "Nearby discovery could not resume. Check Bluetooth and Wi-Fi, then start Nearby again."
        }
    }

    private fun payloadCallback(session: Long) = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) = synchronized(lock) {
            if (generation != session || !active || peers[endpointId]?.state != "connected") {
                client.cancelPayload(payload.id); releasePayload(payload); return@synchronized
            }
            try {
                when (payload.type) {
                    Payload.Type.BYTES -> receiveMetadataLocked(endpointId, payload)
                    Payload.Type.FILE -> {
                        val size = payload.asFile()?.size ?: -1
                        if (size >= 0 && !NearbyPolicy.captureSize(size)) {
                            client.cancelPayload(payload.id); releasePayload(payload)
                            failLocked(payload.id, "The incoming file is not a PCAP capture within the 40 MiB limit.")
                            return@synchronized
                        }
                        val item = incoming[payload.id]
                        if (item != null && item.endpointId != endpointId) { client.cancelPayload(payload.id); releasePayload(payload); return@synchronized }
                        val value = item ?: reserveIncomingLocked(endpointId, payload.id)
                        if (value == null || value.payload != null) {
                            client.cancelPayload(payload.id); releasePayload(payload); return@synchronized
                        }
                        value.payload = payload
                        finishIncomingLocked(payload.id, session)
                    }
                    else -> { client.cancelPayload(payload.id); releasePayload(payload) }
                }
            } catch (_: Exception) {
                client.cancelPayload(payload.id); releasePayload(payload)
                lastError = "A device sent an invalid capture message."
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) = synchronized(lock) {
            if (generation != session || !active) return@synchronized
            val transfer = transfers[update.payloadId.toString()] ?: return@synchronized
            if (transfer.endpointId != endpointId || transfer.state !in listOf("sending", "receiving")) return@synchronized
            if (update.totalBytes > NearbyPolicy.MAX_CAPTURE_BYTES || update.bytesTransferred > NearbyPolicy.MAX_CAPTURE_BYTES ||
                update.totalBytes < 0 || update.bytesTransferred < 0) {
                client.cancelPayload(update.payloadId)
                failLocked(update.payloadId, "Capture exceeds the 40 MiB transfer limit.")
                return@synchronized
            }
            val expected = incoming[update.payloadId]?.expectedSize
            if (expected != null && update.totalBytes > 0 && update.totalBytes != expected) {
                client.cancelPayload(update.payloadId)
                failLocked(update.payloadId, "The incoming capture size does not match its announcement.")
                return@synchronized
            }
            transfer.bytes = update.bytesTransferred
            if (update.totalBytes > 0) transfer.total = update.totalBytes
            when (update.status) {
                PayloadTransferUpdate.Status.SUCCESS -> {
                    if (transfer.state == "sending") {
                        transfer.state = "sent"
                        transfer.payload?.let { releasePayload(it) }; transfer.payload = null
                        transfer.file?.delete(); transfer.file = null
                    } else {
                        incoming[update.payloadId]?.complete = true
                        finishIncomingLocked(update.payloadId, session)
                    }
                }
                PayloadTransferUpdate.Status.FAILURE, PayloadTransferUpdate.Status.CANCELED ->
                    failLocked(update.payloadId, "Capture transfer failed or was cancelled.")
            }
        }
    }

    private fun receiveMetadataLocked(endpointId: String, payload: Payload) {
        val bytes = payload.asBytes() ?: return
        if (bytes.size > NearbyPolicy.MAX_METADATA_BYTES) return
        val data = JSONObject(String(bytes, Charsets.UTF_8))
        if (data.optString("type") != "seekershark-pcap" || data.optInt("version") != 1) return
        val id = data.getString("payloadId").toLongOrNull() ?: return
        val size = data.getLong("size")
        if (!NearbyPolicy.captureSize(size)) { client.cancelPayload(id); return }
        val value = incoming[id] ?: reserveIncomingLocked(endpointId, id) ?: run { client.cancelPayload(id); return }
        if (value.endpointId != endpointId || value.expectedSize != null) return
        value.expectedSize = size
        transfers[id.toString()]?.let { transfer ->
            transfer.name = NearbyPolicy.captureName(data.optString("name", "capture.pcap"))
            transfer.total = size
        }
        finishIncomingLocked(id, generation)
    }

    private fun reserveIncomingLocked(endpointId: String, id: Long): Incoming? {
        if (transfers.containsKey(id.toString()) ||
            transfers.values.count { it.state in listOf("receiving", "received") } >= NearbyPolicy.MAX_INBOX) {
            lastError = "The Nearby inbox is full. Open or discard a capture before receiving another."
            return null
        }
        trimTransfersLocked()
        val peer = peers[endpointId] ?: return null
        transfers[id.toString()] = Transfer(id.toString(), endpointId, peer.name, "Incoming capture.pcap", 0, 0, "receiving")
        val item = Incoming(endpointId)
        incoming[id] = item
        val session = generation
        scheduleLocked("capture:$id", PAIRING_TIMEOUT_MS) {
            if (generation == session && incoming[id] === item &&
                (item.expectedSize == null || item.payload == null)) {
                client.cancelPayload(id)
                failLocked(id, "The capture announcement expired. Ask the other device to share again.")
            }
        }
        return item
    }

    private fun finishIncomingLocked(id: Long, session: Long) {
        val item = incoming[id] ?: return
        val expected = item.expectedSize ?: return
        val payload = item.payload ?: return
        cancelTimeoutLocked("capture:$id")
        if (!item.complete || item.copying) return
        item.copying = true
        io({ error -> synchronized(lock) {
            if (generation == session) failLocked(id, error.message ?: "Could not store the received capture.")
        } }) {
            val destination = File(cache, UUID.randomUUID().toString() + ".pcap")
            try {
                val output = synchronized(lock) {
                    check(generation == session && active) { "Nearby stopped before the capture could be stored." }
                    cache.mkdirs()
                    // Open while holding the session lock. Stop can unlink an open file,
                    // but a queued worker must never recreate a path after Stop deletes it.
                    destination.outputStream().also { preparingFiles.add(destination) }
                }
                output.use { stream ->
                    openPayload(payload).use { input ->
                        val buffer = ByteArray(32 * 1024)
                        var count = 0L
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            count += read
                            check(count <= expected && count <= NearbyPolicy.MAX_CAPTURE_BYTES) { "The received capture size does not match its announcement." }
                            stream.write(buffer, 0, read)
                        }
                        check(count == expected) { "The received capture is incomplete." }
                    }
                }
                check(destination.inputStream().use { stream ->
                    val header = ByteArray(4)
                    stream.read(header) == 4 && NearbyPolicy.pcapHeader(header)
                }) { "Only classic PCAP captures can be received." }
                synchronized(lock) {
                    if (generation != session || transfers[id.toString()]?.state != "receiving") {
                        destination.delete()
                    } else {
                        transfers[id.toString()]?.apply {
                            file = destination; state = "received"; bytes = expected; total = expected
                        }
                        incoming.remove(id)
                    }
                }
            } catch (error: Exception) {
                destination.delete(); throw error
            } finally {
                synchronized(lock) { preparingFiles.remove(destination) }
                releasePayload(payload)
            }
        }
    }

    private fun openPayload(payload: Payload): InputStream {
        val file = payload.asFile() ?: error("The received capture file is missing.")
        val uri = file.asUri()
        if (uri != null) return activity.contentResolver.openInputStream(uri) ?: error("Could not open the received capture.")
        return file.asJavaFile()?.inputStream() ?: error("Could not open the received capture.")
    }

    private fun releasePayload(payload: Payload) {
        if (payload.type != Payload.Type.FILE && payload.type != Payload.Type.STREAM) return
        // Nearby's temporary file belongs to its content provider on modern Android.
        val cleanup = Runnable {
            if (payload.type == Payload.Type.STREAM) {
                try { payload.asStream()?.close() } catch (_: Exception) {}
                return@Runnable
            }
            val file = payload.asFile()
            try {
                val uri = file?.asUri()
                if (uri != null) activity.contentResolver.delete(uri, null, null)
                else file?.asJavaFile()?.delete()
            } catch (_: Exception) { /* Some providers revoke the grant immediately after cancellation. */ }
            finally { try { file?.close() } catch (_: Exception) {} }
        }
        try { worker.execute(cleanup) }
        catch (_: RejectedExecutionException) { cleanup.run() }
    }

    fun sendCapture(endpointId: String, filename: String, dataBase64: String,
                    done: (JSObject) -> Unit, failure: (String) -> Unit) {
        val session: Long
        synchronized(lock) {
            check(active && peers[endpointId]?.state == "connected") { "Pair a Nearby device before sharing a capture." }
            check(!sendPreparing && transfers.values.none { it.state == "sending" }) { "A capture is already being sent." }
            require(dataBase64.length <= ((NearbyPolicy.MAX_CAPTURE_BYTES + 2) / 3 * 4).toInt()) { "Capture exceeds the 40 MiB transfer limit." }
            sendPreparing = true; session = generation
        }
        io({ error -> synchronized(lock) { if (generation == session) sendPreparing = false }; failure(error.message ?: "Could not prepare the capture.") }) {
            val data = Base64.decode(dataBase64, Base64.DEFAULT)
            require(NearbyPolicy.captureSize(data.size.toLong()) && NearbyPolicy.pcapHeader(data)) { "Only classic PCAP captures up to 40 MiB can be shared." }
            val file = File(cache, UUID.randomUUID().toString() + ".pcap")
            val output = synchronized(lock) {
                check(generation == session && active) { "Nearby stopped before the capture could be prepared." }
                cache.mkdirs()
                file.outputStream().also { preparingFiles.add(file) }
            }
            try { output.use { it.write(data) } }
            catch (error: Exception) { file.delete(); synchronized(lock) { preparingFiles.remove(file) }; throw error }
            val posted = main.post {
                synchronized(lock) {
                    if (generation != session || !active || peers[endpointId]?.state != "connected") {
                        if (generation == session) sendPreparing = false
                        preparingFiles.remove(file)
                        file.delete(); failure("The Nearby connection ended before sharing started."); return@synchronized
                    }
                    sendPreparing = false
                    var createdPayloadId: Long? = null
                    try {
                        val payload = Payload.fromFile(file)
                        val id = payload.id
                        val safeName = NearbyPolicy.captureName(filename)
                        trimTransfersLocked()
                        transfers[id.toString()] = Transfer(id.toString(), endpointId, peers[endpointId]!!.name,
                            safeName, 0, data.size.toLong(), "sending", file = file, payload = payload)
                        createdPayloadId = id
                        preparingFiles.remove(file)
                        val metadata = JSONObject().apply {
                            put("type", "seekershark-pcap"); put("version", 1); put("payloadId", id.toString())
                            put("name", safeName); put("size", data.size)
                        }.toString().toByteArray(Charsets.UTF_8)
                        client.sendPayload(endpointId, Payload.fromBytes(metadata))
                            .addOnSuccessListener {
                                synchronized(lock) {
                                    if (generation == session && transfers[id.toString()]?.state == "sending") {
                                        try {
                                            client.sendPayload(endpointId, payload).addOnFailureListener { error -> synchronized(lock) {
                                                if (generation == session) failLocked(id, "Could not send the capture. ${error.message.orEmpty().take(120)}")
                                            } }
                                        } catch (error: Exception) {
                                            failLocked(id, "Could not send the capture. ${error.message.orEmpty().take(120)}")
                                        }
                                    }
                                }
                            }
                            .addOnFailureListener { error -> synchronized(lock) {
                                if (generation == session) failLocked(id, "Could not announce the capture. ${error.message.orEmpty().take(120)}")
                            } }
                        done(snapshotLocked())
                    } catch (error: Exception) {
                        createdPayloadId?.let { failLocked(it, error.message ?: "Could not start capture sharing.") }
                        preparingFiles.remove(file)
                        file.delete(); failure(error.message ?: "Could not start capture sharing.")
                    }
                }
            }
            if (!posted) {
                synchronized(lock) { preparingFiles.remove(file); if (generation == session) sendPreparing = false }
                file.delete(); failure("The app closed before sharing started.")
            }
        }
    }

    fun readCapture(id: String, done: (JSObject) -> Unit, failure: (String) -> Unit) {
        val session: Long
        val file: File
        val transfer: Transfer
        synchronized(lock) {
            transfer = transfers[id]?.takeIf { it.state == "received" } ?: error("This received capture is no longer available.")
            file = transfer.file ?: error("The capture file is missing.")
            session = generation
        }
        io({ error -> failure(error.message ?: "Could not read the received capture.") }) {
            check(NearbyPolicy.captureSize(file.length())) { "The capture file size is invalid." }
            val data = file.readBytes()
            synchronized(lock) {
                check(generation == session && transfers[id]?.file == file) { "Nearby stopped before the capture could be opened." }
                done(JSObject().apply {
                    put("dataBase64", Base64.encodeToString(data, Base64.NO_WRAP))
                    put("name", transfer.name); put("peerName", transfer.peerName)
                })
            }
        }
    }

    fun discardCapture(id: String): JSObject = synchronized(lock) {
        val transfer = transfers[id] ?: error("This capture is no longer available.")
        cancelTimeoutLocked("capture:$id")
        if (transfer.state in listOf("sending", "receiving")) {
            client.cancelPayload(id.toLong())
            incoming.remove(id.toLong())?.payload?.let { releasePayload(it) }
        }
        transfer.payload?.let { releasePayload(it) }; transfer.payload = null
        transfer.file?.delete(); transfers.remove(id)
        snapshotLocked()
    }

    private fun failLocked(id: Long, message: String) {
        cancelTimeoutLocked("capture:$id")
        incoming.remove(id)?.payload?.let { releasePayload(it) }
        transfers[id.toString()]?.apply {
            payload?.let { releasePayload(it) }; payload = null
            state = "failed"; error = message.take(240); file?.delete(); file = null
        }
    }

    private fun trimTransfersLocked() {
        while (transfers.size >= NearbyPolicy.MAX_TRANSFERS) {
            val key = transfers.entries.firstOrNull { it.value.state in listOf("sent", "failed") }?.key ?: return
            transfers.remove(key)?.file?.delete()
        }
    }

    private fun scheduleLocked(key: String, delayMs: Long, task: () -> Unit) {
        cancelTimeoutLocked(key)
        val runnable = Runnable { synchronized(lock) { timeouts.remove(key); task() } }
        timeouts[key] = runnable
        main.postDelayed(runnable, delayMs)
    }

    private fun cancelTimeoutLocked(key: String) { timeouts.remove(key)?.let { main.removeCallbacks(it) } }

    private fun io(failure: (Exception) -> Unit, task: () -> Unit) {
        try {
            worker.execute { try { task() } catch (error: Exception) { failure(error) } }
        } catch (error: RejectedExecutionException) {
            failure(IllegalStateException("Nearby is busy. Wait for the current capture operation to finish.", error))
        }
    }

    companion object {
        private const val SERVICE_ID = "dev.seekershark.capture.nearby.v1"
        private const val PAIRING_TIMEOUT_MS = 60_000L
    }
}
