package dev.seekershark.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import app.tauri.plugin.JSObject
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A local VPN only: packets remain on-device. The Rust userspace TCP/UDP stack
 * opens ordinary network sockets. Excluding our own UID from the VPN prevents
 * those sockets from entering the TUN again. No remote VPN server is involved.
 */
class CaptureVpnService : VpnService() {
    private val worker = Executors.newSingleThreadExecutor()
    private val stopping = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())
    private val healthCheck = object : Runnable {
        override fun run() {
            if (stopping.get()) return
            try {
                val native = JSONObject(nativeStatus())
                if (!native.optBoolean("running")) {
                    lastError = native.optString("lastError").takeUnless { it.isEmpty() || it == "null" }
                        ?: "Packet forwarding stopped."
                    stopSelf()
                    return
                }
            } catch (e: Exception) {
                lastError = e.message ?: "Packet forwarding status is unavailable."
                stopSelf()
                return
            }
            handler.postDelayed(this, 1000)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopSelf(); return START_NOT_STICKY }
        if (running || stopping.get()) return START_NOT_STICKY
        try { showForegroundNotification() } catch (e: Exception) {
            lastError = e.message ?: "Could not start the foreground service."
            stopSelf()
            return START_NOT_STICKY
        }
        worker.execute {
            try {
                if (prepare(this) != null) throw IllegalStateException("Android VPN permission is missing.")
                val builder = Builder()
                    .setSession("SeekerShark · local analysis")
                    .setMtu(1500)
                    .addAddress("10.89.0.2", 32)
                    .addAddress("fd89:7368:6172:6b::2", 128)
                    .addRoute("0.0.0.0", 0)
                    .addRoute("::", 0)
                    .addDisallowedApplication(packageName)
                    .setBlocking(false)

                val connectivity = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
                val network = connectivity.activeNetwork
                val dns = network?.let { connectivity.getLinkProperties(it)?.dnsServers }.orEmpty()
                if (dns.isEmpty()) builder.addDnsServer("1.1.1.1")
                else dns.forEach { builder.addDnsServer(it) }
                // Leave underlyingNetworks null so Android follows the current
                // default network across Wi-Fi/mobile handovers.

                val tun = builder.establish() ?: throw IllegalStateException("Android could not establish the VPN.")
                // Native owns and closes this detached FD, including error paths.
                val fd = tun.detachFd()
                tun.close()
                val error = nativeStart(fd)
                if (error != null) throw IllegalStateException(error)
                if (stopping.get()) { stopNative(); return@execute }
                running = true
                handler.post { healthCheck.run() }
            } catch (e: Exception) {
                lastError = e.message ?: "Could not start VPN packet capture."
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun showForegroundNotification() {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Local packet capture", NotificationManager.IMPORTANCE_LOW))
        }
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val content = launchIntent?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT) }
        val stopIntent = PendingIntent.getService(this, 1, Intent(this, CaptureVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, CHANNEL_ID) else Notification.Builder(this)
        val notification = builder
            .setSmallIcon(R.drawable.ic_capture)
            .setContentTitle("SeekerShark is capturing network packets")
            .setContentText("Local analysis · Tap Stop to disconnect the VPN.")
            .setContentIntent(content)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(android.R.drawable.ic_media_pause, "Stop", stopIntent).build())
            .build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(NOTIFICATION_ID, notification)
    }

    override fun onRevoke() { stopSelf(); super.onRevoke() }

    override fun onDestroy() {
        stopping.set(true)
        handler.removeCallbacks(healthCheck)
        stopNative()
        worker.shutdown()
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
        else @Suppress("DEPRECATION") stopForeground(true)
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "dev.seekershark.capture.STOP"
        private const val CHANNEL_ID = "seekershark-capture"
        private const val NOTIFICATION_ID = 8071
        @Volatile var running = false
        @Volatile var lastError: String? = null
        @JvmStatic private external fun nativeStart(fd: Int): String?
        @JvmStatic private external fun nativeStop()
        @JvmStatic private external fun nativeStatus(): String

        fun stopNative() {
            running = false
            nativeStop()
        }

        fun status(): JSObject {
            val native = try { JSONObject(nativeStatus()) } catch (_: Exception) { JSONObject() }
            return JSObject().apply {
                put("running", running && native.optBoolean("running", false))
                put("lastError", lastError ?: native.optString("lastError").takeUnless { it.isEmpty() || it == "null" } ?: JSONObject.NULL)
                put("receivedPackets", native.optLong("receivedPackets"))
                put("receivedBytes", native.optLong("receivedBytes"))
                put("droppedPackets", native.optLong("droppedPackets"))
                put("queuedPackets", native.optLong("queuedPackets"))
                put("queuedBytes", native.optLong("queuedBytes"))
            }
        }
    }
}
