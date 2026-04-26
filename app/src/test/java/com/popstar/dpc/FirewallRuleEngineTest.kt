package com.popstar.dpc

import com.popstar.dpc.data.firewall.FirewallRuleEngine
import com.popstar.dpc.data.model.FirewallRule
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
    fun normalizesUrlPatternAndHost() {
        val rules = listOf(FirewallRule("1", "https://Example.com/path", block = true, priority = 1))
        assertTrue(engine.shouldBlock("example.com.", null, rules))
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
}
