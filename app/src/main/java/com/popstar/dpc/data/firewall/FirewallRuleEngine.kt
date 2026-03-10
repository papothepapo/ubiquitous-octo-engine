package com.popstar.dpc.data.firewall

import com.popstar.dpc.data.model.FirewallRule

class FirewallRuleEngine {
    fun shouldBlock(host: String, appPackage: String?, rules: List<FirewallRule>): Boolean {
        val ordered = rules.sortedBy { it.priority }
        for (rule in ordered) {
            if (!matches(host, rule.pattern)) continue
            if (rule.appPackage == null || rule.appPackage == appPackage) {
                return rule.block
            }
        }
        return false
    }

    private fun matches(host: String, pattern: String): Boolean {
        if (pattern == "*") return true
        if (pattern.startsWith("*")) return host.endsWith(pattern.removePrefix("*"))
        return host.equals(pattern, ignoreCase = true)
    }
}
