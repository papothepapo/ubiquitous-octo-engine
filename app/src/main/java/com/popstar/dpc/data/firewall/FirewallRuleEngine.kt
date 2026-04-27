package com.popstar.dpc.data.firewall

import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.FirewallRuleType

class FirewallRuleEngine {
    data class Decision(
        val block: Boolean,
        val rule: FirewallRule
    )

    data class Route(
        val address: String,
        val prefixLength: Int,
        val pattern: String
    )

    fun shouldBlock(host: String, appPackage: String?, rules: List<FirewallRule>): Boolean {
        return evaluateDomain(host, appPackage, rules)?.block == true
    }

    fun evaluateDomain(host: String, appPackage: String?, rules: List<FirewallRule>): Decision? {
        val normalizedHost = normalizeHost(host) ?: return null
        return orderedRules(rules)
            .filter { it.type == FirewallRuleType.DOMAIN }
            .firstOrNull { rule ->
                matchesApp(rule, appPackage) && matchesDomain(normalizedHost, rule.pattern)
            }?.let { Decision(block = it.block, rule = it) }
    }

    fun evaluateIp(destIp: String, appPackage: String?, rules: List<FirewallRule>): Decision? {
        val ip = parseIpv4(destIp) ?: return null
        return orderedRules(rules)
            .filter { it.type == FirewallRuleType.IP }
            .firstOrNull { rule ->
                matchesApp(rule, appPackage) && matchesIp(ip, rule.pattern)
            }?.let { Decision(block = it.block, rule = it) }
    }

    fun isValidPattern(type: FirewallRuleType, pattern: String): Boolean {
        return when (type) {
            FirewallRuleType.DOMAIN -> normalizePattern(pattern) != null
            FirewallRuleType.IP -> parseCidr(pattern) != null
        }
    }

    fun routedIpRules(rules: List<FirewallRule>): List<Route> {
        return rules
            .asSequence()
            .filter { it.enabled && it.type == FirewallRuleType.IP }
            .filter { it.block && it.appPackage == null }
            .mapNotNull { rule ->
                val network = parseCidr(rule.pattern) ?: return@mapNotNull null
                Route(
                    address = ipv4ToString(network.network),
                    prefixLength = network.prefixLength,
                    pattern = rule.pattern.trim()
                )
            }
            .distinctBy { "${it.address}/${it.prefixLength}" }
            .toList()
    }

    private fun orderedRules(rules: List<FirewallRule>): List<FirewallRule> {
        return rules
            .asSequence()
            .filter { it.enabled }
            .sortedBy { it.priority }
            .toList()
    }

    private fun matchesApp(rule: FirewallRule, appPackage: String?): Boolean {
        return rule.appPackage == null || rule.appPackage == appPackage
    }

    private fun matchesDomain(host: String, pattern: String): Boolean {
        val normalizedPattern = normalizePattern(pattern) ?: return false
        if (normalizedPattern == "*") return true
        if (normalizedPattern.startsWith("*.")) {
            val suffix = normalizedPattern.removePrefix("*.")
            return host == suffix || host.endsWith(".$suffix")
        }
        if (normalizedPattern.startsWith("*")) {
            val suffix = normalizedPattern.removePrefix("*")
            return host == suffix || host.endsWith(".$suffix")
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
            .substringBefore(':')
            .trim()
            .trimEnd('.')
            .lowercase()
        return host.takeIf { it.isNotBlank() }
    }

    private fun matchesIp(ip: Long, pattern: String): Boolean {
        val network = parseCidr(pattern) ?: return false
        return (ip and network.mask) == (network.network and network.mask)
    }

    private fun parseCidr(value: String): Cidr? {
        val trimmed = value.trim()
        val parts = trimmed.split('/', limit = 2)
        val ip = parseIpv4(parts.first()) ?: return null
        val prefixLength = when (parts.size) {
            1 -> 32
            2 -> parts[1].toIntOrNull() ?: return null
            else -> return null
        }
        if (prefixLength !in 1..32) return null
        val mask = if (prefixLength == 32) IPV4_MASK else (IPV4_MASK shl (32 - prefixLength)) and IPV4_MASK
        return Cidr(network = ip and mask, mask = mask, prefixLength = prefixLength)
    }

    private fun parseIpv4(value: String): Long? {
        val parts = value.trim().split('.')
        if (parts.size != 4) return null
        var out = 0L
        parts.forEach { part ->
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            out = (out shl 8) or octet.toLong()
        }
        return out and IPV4_MASK
    }

    private fun ipv4ToString(value: Long): String {
        return listOf(
            (value ushr 24) and 0xFF,
            (value ushr 16) and 0xFF,
            (value ushr 8) and 0xFF,
            value and 0xFF
        ).joinToString(".")
    }

    private data class Cidr(val network: Long, val mask: Long, val prefixLength: Int)

    private companion object {
        const val IPV4_MASK = 0xFFFF_FFFFL
    }
}
