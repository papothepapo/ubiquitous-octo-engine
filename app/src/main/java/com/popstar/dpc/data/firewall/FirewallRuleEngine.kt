package com.popstar.dpc.data.firewall

import com.popstar.dpc.data.model.FirewallRule

class FirewallRuleEngine {
    fun shouldBlock(host: String, appPackage: String?, rules: List<FirewallRule>): Boolean {
        val normalizedHost = normalizeHost(host) ?: return false
        val ordered = rules.sortedBy { it.priority }
        for (rule in ordered) {
            if (!matches(normalizedHost, rule.pattern)) continue
            if (rule.appPackage == null || rule.appPackage == appPackage) {
                return rule.block
            }
        }
        return false
    }

    private fun matches(host: String, pattern: String): Boolean {
        val normalizedPattern = normalizePattern(pattern) ?: return false
        if (normalizedPattern == "*") return true
        if (normalizedPattern.startsWith("*.")) {
            val suffix = normalizedPattern.removePrefix("*.")
            return host == suffix || host.endsWith(".$suffix")
        }
        if (normalizedPattern.startsWith("*")) {
            return host.endsWith(normalizedPattern.removePrefix("*"))
        }
        return host == normalizedPattern
    }

    private fun normalizePattern(pattern: String): String? {
        val trimmed = pattern.trim().lowercase()
        if (trimmed == "*") return trimmed
        val wildcardPrefix = if (trimmed.startsWith("*.")) "*." else if (trimmed.startsWith("*")) "*" else ""
        val host = normalizeHost(trimmed.removePrefix(wildcardPrefix)) ?: return null
        return wildcardPrefix + host
    }

    private fun normalizeHost(value: String): String? {
        val withoutScheme = value.substringAfter("://", value)
        val host = withoutScheme
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .trim()
            .trimEnd('.')
            .lowercase()
        return host.takeIf { it.isNotBlank() }
    }
}
