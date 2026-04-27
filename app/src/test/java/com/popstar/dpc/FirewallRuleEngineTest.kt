package com.popstar.dpc

import com.popstar.dpc.data.firewall.FirewallRuleEngine
import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.FirewallRuleType
import org.junit.Assert.*
import org.junit.Test

class FirewallRuleEngineTest {
    private val engine = FirewallRuleEngine()

    @Test
    fun wildcardDomainMatches() {
        val rules = listOf(FirewallRule("1", "*.example.com", block = true, priority = 1))
        assertTrue(engine.shouldBlock("cdn.example.com", null, rules))
    }

    @Test
    fun wildcardDoesNotMatchLookalikeSuffix() {
        val rules = listOf(FirewallRule("1", "*.example.com", block = true, priority = 1))
        assertFalse(engine.shouldBlock("badexample.com", null, rules))
    }

    @Test
    fun starPrefixRequiresDomainBoundary() {
        val rules = listOf(FirewallRule("1", "*example.com", block = true, priority = 1))
        assertTrue(engine.shouldBlock("example.com", null, rules))
        assertTrue(engine.shouldBlock("cdn.example.com", null, rules))
        assertFalse(engine.shouldBlock("badexample.com", null, rules))
    }

    @Test
    fun normalizesUrlPatternAndHost() {
        val rules = listOf(FirewallRule("1", "https://Example.com/path", block = true, priority = 1))
        assertTrue(engine.shouldBlock("example.com.", null, rules))
    }

    @Test
    fun normalizesUrlPatternAndHostWithPorts() {
        val rules = listOf(FirewallRule("1", "https://Example.com:443/path", block = true, priority = 1))
        assertTrue(engine.shouldBlock("example.com:443/index", null, rules))
    }

    @Test
    fun appSpecificRule() {
        val rules = listOf(FirewallRule("1", "api.safe.com", appPackage = "a", block = true, priority = 1))
        assertFalse(engine.shouldBlock("api.safe.com", "b", rules))
    }

    @Test
    fun earlierAllowRuleOverridesLaterBlock() {
        val rules = listOf(
            FirewallRule("1", "*.example.com", block = false, priority = 1),
            FirewallRule("2", "*", block = true, priority = 2)
        )
        assertFalse(engine.shouldBlock("cdn.example.com", null, rules))
    }

    @Test
    fun ipCidrRuleMatchesDestination() {
        val rules = listOf(
            FirewallRule("1", "203.0.113.0/24", block = true, priority = 1, type = FirewallRuleType.IP)
        )
        assertTrue(engine.evaluateIp("203.0.113.10", null, rules)?.block == true)
        assertNull(engine.evaluateIp("203.0.114.10", null, rules))
    }

    @Test
    fun appSpecificIpRuleOnlyMatchesSelectedApp() {
        val rules = listOf(
            FirewallRule("1", "203.0.113.10", appPackage = "a", block = true, priority = 1, type = FirewallRuleType.IP)
        )
        assertTrue(engine.evaluateIp("203.0.113.10", "a", rules)?.block == true)
        assertNull(engine.evaluateIp("203.0.113.10", "b", rules))
    }

    @Test
    fun routedIpRulesOnlyIncludesGlobalBlocks() {
        val rules = listOf(
            FirewallRule("1", "203.0.113.0/24", block = true, priority = 1, type = FirewallRuleType.IP),
            FirewallRule("2", "198.51.100.0/24", appPackage = "a", block = true, priority = 2, type = FirewallRuleType.IP),
            FirewallRule("3", "192.0.2.1", block = false, priority = 3, type = FirewallRuleType.IP)
        )
        val routes = engine.routedIpRules(rules)
        assertEquals(1, routes.size)
        assertEquals("203.0.113.0", routes.single().address)
        assertEquals(24, routes.single().prefixLength)
    }

    @Test
    fun rejectsDefaultRouteForIpRules() {
        assertFalse(engine.isValidPattern(FirewallRuleType.IP, "0.0.0.0/0"))
    }
}
