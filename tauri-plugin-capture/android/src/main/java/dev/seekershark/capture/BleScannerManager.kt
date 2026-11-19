package dev.seekershark.capture

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import app.tauri.plugin.JSObject
import org.json.JSONArray
import org.json.JSONObject

/** Timed foreground observation of Android BLE scan reports; never connects to a device. */
internal class BleScannerManager(private val activity: Activity) : DefaultLifecycleObserver {
    private data class ReportBackup(
        val store: BleObservationStore,
        val startedAt: Long?,
        val startElapsed: Long,
        val stoppedElapsed: Long,
        val durationSeconds: Int,
    )

    private val lock = Any()
    private val main = Handler(Looper.getMainLooper())
    private val bluetooth = activity.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val location = activity.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
    private val supported = activity.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) && bluetooth != null
    private var store = BleObservationStore()
    private var active = false
    private var generation = 0L
    private var scanner: BluetoothLeScanner? = null
    private var callback: ScanCallback? = null
    private var watchdog: Runnable? = null
    private var startedAt: Long? = null
    private var startElapsed = 0L
    private var stoppedElapsed = 0L
    private var durationSeconds = BlePolicy.DEFAULT_DURATION_SECONDS
    private var lastError: String? = null
    private var startupBackup: ReportBackup? = null

    init { (activity as? LifecycleOwner)?.lifecycle?.addObserver(this) }

    fun isActive(): Boolean = synchronized(lock) { active }

    fun status(): JSObject = synchronized(lock) {
        checkHealthLocked()
        snapshotLocked()
    }

    fun start(seconds: Int): JSObject = synchronized(lock) {
        BlePolicy.validateDuration(seconds)
        check(!active) { "A BLE observation is already running. Stop it before starting another." }
        check(supported) { "This device does not support Bluetooth LE observation." }
        check(hasPermissions()) { "Allow precise location and Nearby devices permissions before observing BLE advertisements." }
        check(locationEnabled()) { "Turn on Android Location services before observing BLE advertisements. SeekerShark does not request your coordinates." }
        val owner = activity as? LifecycleOwner
        check(owner == null || owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            "Keep SeekerShark in the foreground to observe BLE advertisements."
        }
        val adapter = bluetooth?.adapter ?: error("Bluetooth LE hardware is unavailable.")
        check(adapter.isEnabled) { "Turn on Bluetooth before observing BLE advertisements." }
        val nextScanner = adapter.bluetoothLeScanner ?: error("Bluetooth LE scanning is unavailable. Check Bluetooth and try again.")
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setReportDelay(0L)
            .setLegacy(!adapter.isLeExtendedAdvertisingSupported)
            .setPhy(ScanSettings.PHY_LE_ALL_SUPPORTED)
            .build()

        // Permission denial and synchronous start errors must preserve the previous report.
        startupBackup = ReportBackup(store, startedAt, startElapsed, stoppedElapsed, durationSeconds)
        val session = ++generation
        val nextCallback = scanCallback(session)
        store = BleObservationStore()
        startedAt = System.currentTimeMillis()
        startElapsed = SystemClock.elapsedRealtime()
        stoppedElapsed = 0
        durationSeconds = seconds
        lastError = null
        scanner = nextScanner
        callback = nextCallback
        active = true
        try {
            // An empty filter list observes general advertisements Android exposes.
            // Android may send scan requests; this is not an RF-passive sniffer.
            nextScanner.startScan(emptyList(), settings, nextCallback)
            scheduleWatchdogLocked(session)
        } catch (error: Exception) {
            failLocked("BLE observation could not start. Check Bluetooth, location settings and permissions.")
            throw IllegalStateException(lastError, error)
        }
        snapshotLocked()
    }

    fun stop(): JSObject = synchronized(lock) { stopLocked(); snapshotLocked() }

    fun clear(): JSObject = synchronized(lock) {
        check(!active) { "Stop BLE observation before clearing the report." }
        store.clear()
        startedAt = null
        startElapsed = 0
        stoppedElapsed = 0
        lastError = null
        snapshotLocked()
    }

    private fun elapsedLocked(): Long = if (active) {
        (SystemClock.elapsedRealtime() - startElapsed).coerceIn(0L, durationSeconds * 1000L)
    } else stoppedElapsed

    private fun stopLocked(error: String? = null) {
        if (active) stoppedElapsed = elapsedLocked()
        active = false
        generation++
        startupBackup = null
        watchdog?.let { main.removeCallbacks(it) }; watchdog = null
        val oldScanner = scanner
        val oldCallback = callback
        scanner = null; callback = null
        if (oldScanner != null && oldCallback != null) {
            try { oldScanner.stopScan(oldCallback) }
            catch (_: Exception) {
                if (error == null) lastError = "BLE observation stopped. Android no longer allows access to the Bluetooth scanner."
            }
        }
        if (error != null) lastError = error
    }

    private fun failLocked(message: String) {
        // startScan has no success callback. Retain the old report until Android
        // delivers a valid result, so asynchronous registration/throttling failures
        // do not erase a previously completed observation.
        val backup = startupBackup
        stopLocked(message)
        if (backup != null) {
            store = backup.store
            startedAt = backup.startedAt
            startElapsed = backup.startElapsed
            stoppedElapsed = backup.stoppedElapsed
            durationSeconds = backup.durationSeconds
        }
    }

    private fun locationEnabled(): Boolean = location?.isLocationEnabled == true

    private fun hasPermissions(): Boolean {
        fun granted(permission: String) = activity.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
        return granted(Manifest.permission.ACCESS_FINE_LOCATION) &&
            (Build.VERSION.SDK_INT < 31 ||
                (granted(Manifest.permission.BLUETOOTH_SCAN) && granted(Manifest.permission.BLUETOOTH_CONNECT)))
    }

    private fun checkHealthLocked() {
        if (!active) return
        if (!hasPermissions()) {
            failLocked("BLE observation stopped because a required permission was revoked.")
            return
        }
        if (!locationEnabled()) {
            failLocked("BLE observation stopped because Android Location services were turned off.")
            return
        }
        try {
            if (bluetooth?.adapter?.isEnabled != true) {
                failLocked("BLE observation stopped because Bluetooth was turned off.")
                return
            }
        } catch (_: SecurityException) {
            failLocked("BLE observation stopped because Android no longer permits Bluetooth access.")
            return
        }
        if (SystemClock.elapsedRealtime() - startElapsed >= durationSeconds * 1000L) stopLocked()
    }

    private fun scheduleWatchdogLocked(session: Long) {
        val task = object : Runnable {
            override fun run() = synchronized(lock) {
                if (!active || generation != session) return@synchronized
                checkHealthLocked()
                if (active && generation == session) {
                    val remaining = durationSeconds * 1000L - (SystemClock.elapsedRealtime() - startElapsed)
                    main.postDelayed(this, remaining.coerceIn(1L, 1000L))
                }
                Unit
            }
        }
        watchdog = task
        main.postDelayed(task, minOf(1000L, durationSeconds * 1000L))
    }

    private fun scanCallback(session: Long) = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) { observe(session, result) }

        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            for (result in results) observe(session, result)
        }

        override fun onScanFailed(errorCode: Int) = synchronized(lock) {
            if (!active || generation != session) return@synchronized
            val message = when (errorCode) {
                SCAN_FAILED_ALREADY_STARTED -> "Android reports that this BLE observation is already registered. Stop and retry."
                SCAN_FAILED_APPLICATION_REGISTRATION_FAILED -> "Android could not register the BLE observation. Wait and try again."
                SCAN_FAILED_FEATURE_UNSUPPORTED -> "The Bluetooth hardware does not support the requested BLE observation mode."
                SCAN_FAILED_INTERNAL_ERROR -> "Android reported an internal Bluetooth scanning error. Check Bluetooth and retry."
                5 -> "Android has no hardware resources available for another BLE observation."
                6 -> "Android is limiting frequent scan starts. Wait before starting another BLE observation."
                else -> "Android could not start BLE observation (error $errorCode)."
            }
            failLocked(message)
        }
    }

    private fun observe(session: Long, result: ScanResult) = synchronized(lock) {
        if (!active || generation != session) return@synchronized
        checkHealthLocked()
        if (!active || generation != session) return@synchronized
        try {
            val record = result.scanRecord
            val manufacturerIds = ArrayList<Int>(BlePolicy.MAX_LIST_ITEMS)
            record?.manufacturerSpecificData?.let { data ->
                for (index in 0 until minOf(data.size(), BlePolicy.MAX_LIST_ITEMS)) manufacturerIds.add(data.keyAt(index))
            }
            val serviceUuids = ArrayList<String>(BlePolicy.MAX_LIST_ITEMS)
            record?.serviceUuids?.let { data ->
                for (index in 0 until minOf(data.size, BlePolicy.MAX_LIST_ITEMS)) serviceUuids.add(data[index].toString())
            }
            val power = result.txPower.takeUnless { it == 127 }
                ?: record?.txPowerLevel?.takeUnless { it == Int.MIN_VALUE }
            val input = BleAdvertisementInput(
                address = result.device.address,
                name = record?.deviceName,
                rssi = result.rssi,
                txPower = power,
                connectable = result.isConnectable,
                legacy = result.isLegacy,
                primaryPhy = result.primaryPhy,
                secondaryPhy = result.secondaryPhy,
                advertisingSid = result.advertisingSid.takeUnless { it == 255 },
                manufacturerIds = manufacturerIds,
                serviceUuids = serviceUuids,
                advertisement = record?.bytes ?: byteArrayOf(),
                payloadTruncated = result.dataStatus == ScanResult.DATA_TRUNCATED,
            )
            // No task is queued per advertisement; memory is bounded by the observation store.
            store.observe(input, System.currentTimeMillis())
            startupBackup = null
        } catch (_: SecurityException) {
            failLocked("BLE observation stopped because Android no longer permits Bluetooth access.")
        } catch (_: Exception) {
            failLocked("Android supplied a BLE observation that could not be read. The retained report remains available.")
        }
    }

    private fun snapshotLocked() = JSObject().apply {
        put("supported", supported); put("active", active)
        put("startedAt", startedAt ?: JSONObject.NULL)
        put("elapsedMs", elapsedLocked()); put("durationSeconds", durationSeconds)
        put("advertisements", store.advertisements); put("droppedObservations", store.droppedObservations)
        put("maxObservations", store.maxObservations); put("lastError", lastError ?: JSONObject.NULL)
        put("observations", JSONArray().apply {
            store.snapshot().forEach { row -> put(JSONObject().apply {
                put("id", row.id); put("address", row.address); put("name", row.name ?: JSONObject.NULL)
                put("rssi", row.rssi); put("txPower", row.txPower ?: JSONObject.NULL)
                put("connectable", row.connectable); put("legacy", row.legacy)
                put("primaryPhy", row.primaryPhy); put("secondaryPhy", row.secondaryPhy)
                put("advertisingSid", row.advertisingSid ?: JSONObject.NULL)
                put("manufacturerIds", JSONArray(row.manufacturerIds)); put("serviceUuids", JSONArray(row.serviceUuids))
                put("advertisementHex", row.advertisementHex); put("payloadTruncated", row.payloadTruncated)
                put("firstSeen", row.firstSeen); put("lastSeen", row.lastSeen); put("advertisements", row.advertisements)
            }) }
        })
    }

    override fun onStop(owner: LifecycleOwner) { stop() }
    override fun onDestroy(owner: LifecycleOwner) { stop(); owner.lifecycle.removeObserver(this) }
}
