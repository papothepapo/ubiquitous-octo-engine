package com.popstar.dpc.data.firewall

import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.VpnLogEntry
import java.util.concurrent.CopyOnWriteArrayList

object FirewallRuntime {
    @Volatile
    var rules: List<FirewallRule> = emptyList()

    @Volatile
    var blockedPackages: Set<String> = emptySet()

    private val blockedEvents = CopyOnWriteArrayList<VpnLogEntry>()

    fun logBlocked(category: String, appPackage: String? = null, site: String? = null, details: String) {
        blockedEvents.add(
            0,
            VpnLogEntry(
                timestamp = System.currentTimeMillis(),
                category = category,
                appPackage = appPackage,
                site = site,
                details = details
            )
        )
        if (blockedEvents.size > 500) {
            blockedEvents.removeAt(blockedEvents.lastIndex)
        }
    }

    fun restore(events: List<VpnLogEntry>) {
        blockedEvents.clear()
        blockedEvents.addAll(events.take(500))
    }

    fun clear() {
        blockedEvents.clear()
    }

    fun events(): List<VpnLogEntry> = blockedEvents.toList()
}
