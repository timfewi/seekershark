package dev.seekershark.capture

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.ContentValues
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Environment
import android.provider.MediaStore
import android.util.Base64
import androidx.activity.result.ActivityResult
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.PermissionState
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File

@InvokeArg
class ExportOptions {
    lateinit var dataBase64: String
    var name: String = "seekershark.pcap"
}

@InvokeArg
class NearbyNameOptions { var name: String = "SeekerShark" }

@InvokeArg
class NearbyEndpointOptions { lateinit var endpointId: String }

@InvokeArg
class NearbyConfirmOptions { lateinit var endpointId: String; var accept: Boolean = false }

@InvokeArg
class NearbyCaptureOptions {
    lateinit var endpointId: String
    lateinit var dataBase64: String
    var name: String = "capture.pcap"
}

@InvokeArg
class NearbyIdOptions { lateinit var id: String }

@InvokeArg
class BleStartOptions { var durationSeconds: Int = BlePolicy.DEFAULT_DURATION_SECONDS }

@TauriPlugin(permissions = [
    Permission(strings = [Manifest.permission.POST_NOTIFICATIONS], alias = "notifications"),
    Permission(strings = [Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.BLUETOOTH_ADVERTISE], alias = "nearbyBluetooth"),
    Permission(strings = [Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT], alias = "bleBluetooth"),
    Permission(strings = [Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION], alias = "nearbyLocation"),
    Permission(strings = [Manifest.permission.NEARBY_WIFI_DEVICES], alias = "nearbyWifi"),
    Permission(strings = [Manifest.permission.READ_EXTERNAL_STORAGE], alias = "nearbyFiles"),
])
class CapturePlugin(private val activity: Activity) : Plugin(activity) {
    private val handler = Handler(Looper.getMainLooper())
    private var starting = false
    private val nearbyDelegate = lazy { NearbyManager(activity) }
    private val nearby by nearbyDelegate
    private val bleDelegate = lazy { BleScannerManager(activity) }
    private val ble by bleDelegate
    private enum class RadioMode { NEARBY, BLE }
    @Volatile private var radioStarting: RadioMode? = null
    private var radioPendingPermission: String? = null

    private fun nearbyActive() = nearbyDelegate.isInitialized() && nearby.isActive()
    private fun bleActive() = bleDelegate.isInitialized() && ble.isActive()

    @Command
    fun nearbyStart(invoke: Invoke) { activity.runOnUiThread { beginRadioStart(invoke, RadioMode.NEARBY) } }

    @Command
    fun bleStart(invoke: Invoke) { activity.runOnUiThread { beginRadioStart(invoke, RadioMode.BLE) } }

    private fun beginRadioStart(invoke: Invoke, mode: RadioMode) {
        try {
            check(radioStarting == null) { "Finish the current radio permission request before starting another mode." }
            check(!starting) { "Finish the capture permission request before starting radio discovery." }
            checkModeAvailable(mode)
            if (mode == RadioMode.NEARBY) {
                NearbyPolicy.deviceName(invoke.parseArgs(NearbyNameOptions::class.java).name)
                check(nearby.status().getBoolean("supported")) { "Nearby requires an up-to-date Google Play services installation." }
            } else {
                BlePolicy.validateDuration(invoke.parseArgs(BleStartOptions::class.java).durationSeconds)
                check(ble.status().getBoolean("supported")) { "This device does not support Bluetooth LE observation." }
            }
            radioStarting = mode
            ensureRadioPermissions(invoke, mode)
        } catch (error: Exception) {
            // A competing call must not clear the permission request already in progress.
            if (radioStarting == mode && radioPendingPermission == null) radioStarting = null
            invoke.reject(error.message ?: "Could not start radio discovery.")
        }
    }

    private fun checkModeAvailable(mode: RadioMode) {
        val owner = activity as? LifecycleOwner
        check(owner == null || owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            "Keep SeekerShark in the foreground to start radio discovery."
        }
        if (mode == RadioMode.NEARBY) {
            check(!bleActive()) { "Stop BLE observation before starting Nearby sharing." }
            check(!nearbyActive()) { "Nearby sharing is already active." }
        } else {
            check(!nearbyActive()) { "Stop Nearby sharing before observing BLE advertisements." }
            check(!bleActive()) { "BLE observation is already active." }
        }
    }

    private fun requiredRadioPermissions(mode: RadioMode): List<String> = buildList {
        if (Build.VERSION.SDK_INT >= 31) add(if (mode == RadioMode.BLE) "bleBluetooth" else "nearbyBluetooth")
        // The shared BLUETOOTH_SCAN declaration deliberately has no neverForLocation
        // assertion: Android would otherwise hide some beacons from general BLE scans.
        add("nearbyLocation")
        if (mode == RadioMode.NEARBY) {
            if (Build.VERSION.SDK_INT >= 33) add("nearbyWifi") else add("nearbyFiles")
        }
    }

    private fun ensureRadioPermissions(invoke: Invoke, mode: RadioMode) {
        val permission = requiredRadioPermissions(mode).firstOrNull { getPermissionState(it) != PermissionState.GRANTED }
        if (permission != null) {
            radioPendingPermission = permission
            try { requestPermissionForAlias(permission, invoke, "radioPermissionResult") }
            catch (error: Exception) { radioStarting = null; radioPendingPermission = null; throw error }
        } else {
            radioPendingPermission = null
            try {
                checkModeAvailable(mode)
                val result = if (mode == RadioMode.NEARBY) nearby.start(invoke.parseArgs(NearbyNameOptions::class.java).name)
                    else ble.start(invoke.parseArgs(BleStartOptions::class.java).durationSeconds)
                invoke.resolve(result)
            } finally { radioStarting = null }
        }
    }

    @PermissionCallback
    fun radioPermissionResult(invoke: Invoke) {
        try {
            val mode = radioStarting ?: error("The radio permission request is no longer active.")
            val permission = radioPendingPermission
            if (permission == null || getPermissionState(permission) != PermissionState.GRANTED) {
                radioStarting = null; radioPendingPermission = null
                invoke.reject("Radio permission was denied. Allow precise location and Nearby devices in Android settings. Nearby sharing also needs file access on Android 12 or earlier.")
                return
            }
            ensureRadioPermissions(invoke, mode)
        } catch (error: Exception) {
            radioStarting = null; radioPendingPermission = null
            invoke.reject(error.message ?: "Could not request radio permissions.")
        }
    }

    @Command
    fun bleStatus(invoke: Invoke) = bleResult(invoke) { ble.status() }

    @Command
    fun bleStop(invoke: Invoke) = bleResult(invoke) { ble.stop() }

    @Command
    fun bleClear(invoke: Invoke) = bleResult(invoke) { ble.clear() }

    private fun bleResult(invoke: Invoke, action: () -> JSObject) {
        activity.runOnUiThread {
            try { invoke.resolve(action()) }
            catch (error: Exception) { invoke.reject(error.message ?: "BLE observation operation failed.") }
        }
    }

    @Command
    fun nearbyStatus(invoke: Invoke) = nearbyResult(invoke) { nearby.status() }

    @Command
    fun nearbyStop(invoke: Invoke) = nearbyResult(invoke) { nearby.stop() }

    @Command
    fun nearbyConnect(invoke: Invoke) = nearbyResult(invoke) {
        nearby.connect(invoke.parseArgs(NearbyEndpointOptions::class.java).endpointId)
    }

    @Command
    fun nearbyConfirm(invoke: Invoke) = nearbyResult(invoke) {
        val options = invoke.parseArgs(NearbyConfirmOptions::class.java)
        nearby.confirm(options.endpointId, options.accept)
    }

    @Command
    fun nearbyDisconnect(invoke: Invoke) = nearbyResult(invoke) {
        nearby.disconnect(invoke.parseArgs(NearbyEndpointOptions::class.java).endpointId)
    }

    @Command
    fun nearbySendCapture(invoke: Invoke) {
        try {
            val options = invoke.parseArgs(NearbyCaptureOptions::class.java)
            nearby.sendCapture(options.endpointId, options.name, options.dataBase64,
                { result -> invoke.resolve(result) }, { error -> invoke.reject(error) })
        } catch (error: Exception) { invoke.reject(error.message ?: "Could not share the capture.") }
    }

    @Command
    fun nearbyReadCapture(invoke: Invoke) {
        try {
            nearby.readCapture(invoke.parseArgs(NearbyIdOptions::class.java).id,
                { result -> invoke.resolve(result) }, { error -> invoke.reject(error) })
        } catch (error: Exception) { invoke.reject(error.message ?: "Could not open the received capture.") }
    }

    @Command
    fun nearbyDiscardCapture(invoke: Invoke) = nearbyResult(invoke) {
        nearby.discardCapture(invoke.parseArgs(NearbyIdOptions::class.java).id)
    }

    private fun nearbyResult(invoke: Invoke, action: () -> JSObject) {
        activity.runOnUiThread {
            try { invoke.resolve(action()) }
            catch (error: Exception) { invoke.reject(error.message ?: "Nearby operation failed.") }
        }
    }

    @Command
    fun startCapture(invoke: Invoke) {
        if (radioStarting != null) { invoke.reject("Finish the radio permission request before starting capture."); return }
        if (CaptureVpnService.running) {
            invoke.resolve(CaptureVpnService.status())
            return
        }
        if (starting) { invoke.reject("A VPN request is already in progress."); return }
        starting = true
        if (Build.VERSION.SDK_INT >= 33 && getPermissionState("notifications") != PermissionState.GRANTED) {
            requestPermissionForAlias("notifications", invoke, "notificationPermissionResult")
        } else beginVpnConsent(invoke)
    }

    @PermissionCallback
    fun notificationPermissionResult(invoke: Invoke) {
        // Notification denial must not prevent the user from using the VPN.
        // Android still lists a foreground service in its active-app controls.
        beginVpnConsent(invoke)
    }

    private fun beginVpnConsent(invoke: Invoke) {
        val consent = VpnService.prepare(activity)
        if (consent != null) {
            startActivityForResult(invoke, consent, "vpnPermissionResult")
        } else {
            startAfterConsent(invoke)
        }
    }

    @ActivityCallback
    private fun vpnPermissionResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK) {
            starting = false
            invoke.reject("VPN permission was not granted. No capture was started.")
            return
        }
        startAfterConsent(invoke)
    }

    private fun startAfterConsent(invoke: Invoke) {
        try {
            CaptureVpnService.lastError = null
            val intent = Intent(activity, CaptureVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) activity.startForegroundService(intent)
            else activity.startService(intent)
            awaitStarted(invoke, 0)
        } catch (e: Exception) {
            starting = false
            invoke.reject(e.message ?: "Could not start the VPN service.")
        }
    }

    private fun awaitStarted(invoke: Invoke, attempt: Int) {
        if (CaptureVpnService.running) {
            starting = false
            invoke.resolve(CaptureVpnService.status())
        } else if (CaptureVpnService.lastError != null || attempt >= 150) {
            starting = false
            invoke.reject(CaptureVpnService.lastError ?: "Timed out while starting the VPN service.")
        } else handler.postDelayed({ awaitStarted(invoke, attempt + 1) }, 100)
    }

    @Command
    fun stopCapture(invoke: Invoke) {
        activity.stopService(Intent(activity, CaptureVpnService::class.java))
        CaptureVpnService.stopNative()
        invoke.resolve(CaptureVpnService.status())
    }

    @Command
    fun captureStatus(invoke: Invoke) { invoke.resolve(CaptureVpnService.status()) }

    @Command
    fun savePcap(invoke: Invoke) { saveExport(invoke, false) }

    @Command
    fun saveReport(invoke: Invoke) { saveExport(invoke, true) }

    private fun saveExport(invoke: Invoke, report: Boolean) {
        Thread {
            try {
                val options = invoke.parseArgs(ExportOptions::class.java)
                val limit = if (report) 8 else 40
                if (options.dataBase64.length > (limit * 4 / 3 + 2) * 1024 * 1024) throw IllegalArgumentException("Export exceeds $limit MiB.")
                val data = Base64.decode(options.dataBase64, Base64.DEFAULT)
                if (data.size > limit * 1024 * 1024) throw IllegalArgumentException("Export exceeds $limit MiB.")
                var name = options.name.replace(Regex("[^A-Za-z0-9_.-]"), "_").take(120)
                val extension = if (report) ".json" else ".pcap"
                if (!name.endsWith(extension)) name += extension
                val uri: String
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val resolver = activity.contentResolver
                    val values = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, name)
                        put(MediaStore.Downloads.MIME_TYPE, if (report) "application/json" else "application/vnd.tcpdump.pcap")
                        put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SeekerShark")
                        put(MediaStore.Downloads.IS_PENDING, 1)
                    }
                    val location = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                        ?: throw IllegalStateException("Could not create the file in Downloads.")
                    try {
                        resolver.openOutputStream(location)?.use { it.write(data) }
                            ?: throw IllegalStateException("Could not open the file in Downloads.")
                        values.clear()
                        values.put(MediaStore.Downloads.IS_PENDING, 0)
                        resolver.update(location, values, null, null)
                        uri = location.toString()
                    } catch (e: Exception) {
                        resolver.delete(location, null, null)
                        throw e
                    }
                } else {
                    val directory = File(activity.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), "SeekerShark")
                    if (!directory.exists() && !directory.mkdirs()) throw IllegalStateException("Could not create the export directory.")
                    val location = File(directory, "${System.currentTimeMillis()}-$name")
                    location.outputStream().use { it.write(data) }
                    uri = location.absolutePath
                }
                invoke.resolve(JSObject().apply { put("uri", uri) })
            } catch (e: Exception) {
                invoke.reject(e.message ?: "File export failed.")
            }
        }.start()
    }
}
