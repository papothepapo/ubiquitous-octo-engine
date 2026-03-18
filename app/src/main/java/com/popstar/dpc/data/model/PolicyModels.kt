package com.popstar.dpc.data.model

import kotlinx.serialization.Serializable

@Serializable
enum class PasswordEnforcementMode { TIMED, PERSISTENT, DISABLED }

@Serializable
enum class AppThemeMode { SYSTEM, LIGHT, DARK }

@Serializable
data class PasswordPolicy(
    val mode: PasswordEnforcementMode = PasswordEnforcementMode.DISABLED,
    val timedDays: Int = 0,
    val enabledAtEpochMs: Long = 0L
)

@Serializable
data class AppRule(
    val packageName: String,
    val blocked: Boolean = false,
    val suspended: Boolean = false,
    val networkBlocked: Boolean = false,
    val priority: Int = 0
)

@Serializable
data class RestrictionPolicy(
    val wifiBlocked: Boolean = false,
    val smsBlocked: Boolean = false,
    val mobileDataBlocked: Boolean = false,
    val deviceResetBlocked: Boolean = false,
    val networkResetBlocked: Boolean = false,
    val appResetBlocked: Boolean = false,
    val developerOptionsBlocked: Boolean = false,
    val appInstallBlocked: Boolean = false,
    val safeBootBlocked: Boolean = false,
    val accountManagementBlocked: Boolean = false,
    val supportShortMessage: String = "",
    val supportLongMessage: String = "",
    val customRestrictions: List<String> = emptyList()
)

@Serializable
data class FirewallRule(
    val id: String,
    val pattern: String,
    val appPackage: String? = null,
    val block: Boolean = true,
    val priority: Int = 100
)

@Serializable
data class AuditLogEntry(
    val timestamp: Long,
    val actor: String,
    val action: String,
    val details: String
)

@Serializable
data class VpnLockdownConfig(
    val enabled: Boolean = false,
    val selectedVpnPackage: String? = null
)

@Serializable
data class VpnLogEntry(
    val timestamp: Long,
    val category: String,
    val appPackage: String? = null,
    val site: String? = null,
    val details: String
)

@Serializable
data class PolicyBundle(
    val themeMode: AppThemeMode = AppThemeMode.SYSTEM,
    val vpnAutoStart: Boolean = false,
    val passwordPolicy: PasswordPolicy = PasswordPolicy(),
    val restrictionPolicy: RestrictionPolicy = RestrictionPolicy(),
    val appRules: List<AppRule> = emptyList(),
    val firewallRules: List<FirewallRule> = emptyList(),
    val logs: List<AuditLogEntry> = emptyList(),
    val vpnLogs: List<VpnLogEntry> = emptyList(),
    val vpnLockdown: VpnLockdownConfig = VpnLockdownConfig()
)
