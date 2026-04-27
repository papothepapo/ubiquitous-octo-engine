package com.popstar.dpc.data.policy

import com.popstar.dpc.data.model.AppRule
import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.FirewallRuleType
import com.popstar.dpc.data.model.PolicyBundle
import com.popstar.dpc.data.model.RestrictionPolicy
import com.popstar.dpc.data.model.VpnLockdownConfig

object DefaultPolicyFactory {
    private const val DEFAULT_DENY_PRIORITY = 10_000

    fun defaultDeny(installedPackages: Collection<String>, ownPackage: String): PolicyBundle {
        val blockedApps = installedPackages
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() && it != ownPackage }
            .distinct()
            .sorted()
            .map { packageName ->
                AppRule(
                    packageName = packageName,
                    networkBlocked = true
                )
            }
            .toList()

        return PolicyBundle(
            vpnAutoStart = true,
            restrictionPolicy = RestrictionPolicy(
                wifiBlocked = true,
                smsBlocked = true,
                mobileDataBlocked = true,
                deviceResetBlocked = true,
                networkResetBlocked = true,
                appResetBlocked = true,
                developerOptionsBlocked = true,
                appInstallBlocked = true,
                safeBootBlocked = true,
                accountManagementBlocked = true,
                supportShortMessage = "Restricted by Popstar DPC",
                supportLongMessage = "This device starts in lockdown mode. Enable only the apps, domains, and system controls that should be allowed."
            ),
            appRules = blockedApps,
            firewallRules = listOf(
                FirewallRule(
                    id = "default-deny-domain",
                    pattern = "*",
                    block = true,
                    priority = DEFAULT_DENY_PRIORITY,
                    type = FirewallRuleType.DOMAIN
                ),
                FirewallRule(
                    id = "default-deny-ip-low",
                    pattern = "0.0.0.0/1",
                    block = true,
                    priority = DEFAULT_DENY_PRIORITY + 1,
                    type = FirewallRuleType.IP
                ),
                FirewallRule(
                    id = "default-deny-ip-high",
                    pattern = "128.0.0.0/1",
                    block = true,
                    priority = DEFAULT_DENY_PRIORITY + 2,
                    type = FirewallRuleType.IP
                )
            ),
            vpnLockdown = VpnLockdownConfig(
                enabled = true,
                selectedVpnPackage = ownPackage
            )
        )
    }
}
