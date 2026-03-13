package com.popstar.dpc.data.model

import kotlinx.serialization.Serializable

@Serializable
enum class PasswordEnforcementMode { TIMED, PERSISTENT, DISABLED }

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
    val appResetBlocked: Boolean = false
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
data class PolicyBundle(
    val passwordPolicy: PasswordPolicy = PasswordPolicy(),
    val restrictionPolicy: RestrictionPolicy = RestrictionPolicy(),
    val appRules: List<AppRule> = emptyList(),
    val firewallRules: List<FirewallRule> = emptyList(),
    val logs: List<AuditLogEntry> = emptyList()
)
