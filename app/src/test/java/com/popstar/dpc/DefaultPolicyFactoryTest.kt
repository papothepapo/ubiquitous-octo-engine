package com.popstar.dpc

import com.popstar.dpc.data.model.FirewallRuleType
import com.popstar.dpc.data.policy.DefaultPolicyFactory
import org.junit.Assert.*
import org.junit.Test

class DefaultPolicyFactoryTest {
    @Test
    fun firstRunPolicyStartsInDefaultDenyLockdown() {
        val bundle = DefaultPolicyFactory.defaultDeny(
            installedPackages = listOf(
                "com.popstar.dpc",
                "com.example.browser",
                "com.example.chat",
                "com.example.browser"
            ),
            ownPackage = "com.popstar.dpc"
        )

        assertTrue(bundle.vpnAutoStart)
        assertTrue(bundle.vpnLockdown.enabled)
        assertEquals("com.popstar.dpc", bundle.vpnLockdown.selectedVpnPackage)

        val restrictions = bundle.restrictionPolicy
        assertTrue(restrictions.wifiBlocked)
        assertTrue(restrictions.smsBlocked)
        assertTrue(restrictions.mobileDataBlocked)
        assertTrue(restrictions.deviceResetBlocked)
        assertTrue(restrictions.networkResetBlocked)
        assertTrue(restrictions.appResetBlocked)
        assertTrue(restrictions.developerOptionsBlocked)
        assertTrue(restrictions.appInstallBlocked)
        assertTrue(restrictions.safeBootBlocked)
        assertTrue(restrictions.accountManagementBlocked)

        assertEquals(
            listOf("com.example.browser", "com.example.chat"),
            bundle.appRules.map { it.packageName }
        )
        assertTrue(bundle.appRules.all { it.networkBlocked })

        assertTrue(bundle.firewallRules.any { it.type == FirewallRuleType.DOMAIN && it.pattern == "*" })
        assertTrue(bundle.firewallRules.any { it.type == FirewallRuleType.IP && it.pattern == "0.0.0.0/1" })
        assertTrue(bundle.firewallRules.any { it.type == FirewallRuleType.IP && it.pattern == "128.0.0.0/1" })
    }
}
