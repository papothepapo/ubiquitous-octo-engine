package com.popstar.dpc.data.firewall

import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.VpnLogEntry
import java.util.ArrayDeque

object FirewallRuntime {
    private const val MAX_BLOCKED_EVENTS = 500

    @Volatile
    var rules: List<FirewallRule> = emptyList()

    @Volatile
    var blockedPackages: Set<String> = emptySet()

    private val blockedEvents = ArrayDeque<VpnLogEntry>(MAX_BLOCKED_EVENTS)

    fun logBlocked(category: String, appPackage: String? = null, site: String? = null, details: String) {
        synchronized(blockedEvents) {
            blockedEvents.addFirst(
                VpnLogEntry(
                    timestamp = System.currentTimeMillis(),
                    category = category,
                    appPackage = appPackage,
                    site = site,
                    details = details
                )
            )
            while (blockedEvents.size > MAX_BLOCKED_EVENTS) {
                blockedEvents.removeLast()
            }
        }
    }

    fun restore(events: List<VpnLogEntry>) {
        synchronized(blockedEvents) {
            blockedEvents.clear()
            events.take(MAX_BLOCKED_EVENTS).forEach { blockedEvents.addLast(it) }
        }
    }

    fun clear() {
        synchronized(blockedEvents) {
            blockedEvents.clear()
        }
    }

    fun events(): List<VpnLogEntry> {
        return synchronized(blockedEvents) {
            blockedEvents.toList()
        }
    }
}
