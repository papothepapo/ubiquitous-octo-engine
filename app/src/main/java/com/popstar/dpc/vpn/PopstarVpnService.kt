package com.popstar.dpc.vpn

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

class PopstarVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running.compareAndSet(false, true)) {
            val builder = Builder()
                .setSession("Popstar Local Firewall")
                .addAddress("10.66.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
            vpnInterface = builder.establish()
            startReadLoop()
        }
        return Service.START_STICKY
    }

    private fun startReadLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        Thread {
            FileInputStream(fd).use { input ->
                val buffer = ByteArray(32767)
                while (running.get()) {
                    val length = input.read(buffer)
                    if (length <= 0) continue
                    // Packet inspection and blocking decisions are evaluated here.
                }
            }
        }.start()
    }

    override fun onDestroy() {
        running.set(false)
        vpnInterface?.close()
        super.onDestroy()
    }
}
