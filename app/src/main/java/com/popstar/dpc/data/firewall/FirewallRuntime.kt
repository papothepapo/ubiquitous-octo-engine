package com.popstar.dpc.data.firewall

import com.popstar.dpc.data.model.FirewallRule
import java.util.concurrent.CopyOnWriteArrayList

object FirewallRuntime {
    @Volatile
    var rules: List<FirewallRule> = emptyList()

    private val blockedEvents = CopyOnWriteArrayList<String>()

    fun logBlocked(event: String) {
        blockedEvents.add(0, event)
        if (blockedEvents.size > 200) {
            blockedEvents.removeAt(blockedEvents.lastIndex)
        }
    }

    fun events(): List<String> = blockedEvents.toList()
}
