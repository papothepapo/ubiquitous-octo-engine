package com.popstar.dpc.data.policy

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.os.UserManager
import com.popstar.dpc.admin.PopstarDeviceAdminReceiver
import com.popstar.dpc.data.model.AppRule
import com.popstar.dpc.data.model.RestrictionPolicy
import com.popstar.dpc.data.model.VpnLockdownConfig


data class DeviceAdminEntry(
    val componentName: ComponentName,
    val packageName: String,
    val label: String,
    val isThisApp: Boolean
)

class DevicePolicyEngine(private val context: Context) {
    private val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val admin = ComponentName(context, PopstarDeviceAdminReceiver::class.java)

    fun applyRestrictions(policy: RestrictionPolicy): List<String> {
        if (!isAdminActive()) return listOf("Device admin is not active")
        val failures = mutableListOf<String>()

        applyRestriction(UserManager.DISALLOW_CONFIG_WIFI, policy.wifiBlocked, failures)
        applyRestriction(UserManager.DISALLOW_SMS, policy.smsBlocked, failures)
        applyRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS, policy.mobileDataBlocked, failures)
        applyRestriction(UserManager.DISALLOW_FACTORY_RESET, policy.deviceResetBlocked, failures)
        applyRestriction(UserManager.DISALLOW_NETWORK_RESET, policy.networkResetBlocked, failures)
        applyRestriction(UserManager.DISALLOW_APPS_CONTROL, policy.appResetBlocked, failures)
        applyRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES, policy.developerOptionsBlocked, failures)
        applyRestriction(UserManager.DISALLOW_SAFE_BOOT, policy.safeBootBlocked, failures)
        applyRestriction(UserManager.DISALLOW_ADD_USER, policy.deviceResetBlocked, failures)
        applyRestriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, policy.appResetBlocked, failures)
        applyRestriction(UserManager.DISALLOW_INSTALL_APPS, policy.appInstallBlocked, failures)
        applyRestriction(UserManager.DISALLOW_MODIFY_ACCOUNTS, policy.accountManagementBlocked, failures)
        applyRestriction(UserManager.DISALLOW_USB_FILE_TRANSFER, policy.mobileDataBlocked, failures)
        policy.customRestrictions.filter { it.isNotBlank() }.distinct().forEach { key ->
            applyRestriction(key.trim(), true, failures)
        }

        runCatching {
            dpm.setShortSupportMessage(admin, policy.supportShortMessage.ifBlank { null })
            dpm.setLongSupportMessage(admin, policy.supportLongMessage.ifBlank { null })
        }.onFailure {
            failures.add("Setting support messages failed: ${it.message}")
        }

        return failures
    }

    fun applyAppControlRules(rules: List<AppRule>): List<String> {
        if (!isAdminActive()) return listOf("Device admin is not active")
        val failures = mutableListOf<String>()

        rules.forEach { rule ->
            if (rule.packageName == context.packageName) {
                if (rule.blocked || rule.suspended) {
                    failures.add("Skipping control of host DPC app: ${rule.packageName}")
                }
                return@forEach
            }

            runCatching {
                dpm.setApplicationHidden(admin, rule.packageName, rule.blocked)
            }.onFailure {
                failures.add("Block ${rule.packageName} failed: ${it.message}")
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                runCatching {
                    dpm.setPackagesSuspended(admin, arrayOf(rule.packageName), rule.suspended)
                }.onFailure {
                    failures.add("Suspend ${rule.packageName} failed: ${it.message}")
                }
            } else if (rule.suspended) {
                failures.add("Suspend ${rule.packageName} requires Android 7.0+")
            }
        }

        return failures
    }

    fun applyVpnLockdown(config: VpnLockdownConfig): List<String> {
        if (!config.enabled) return emptyList()
        if (!isAdminActive()) return listOf("Device admin is not active")
        val packageName = config.selectedVpnPackage ?: return listOf("Select a VPN package before enabling lockdown")
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                dpm.setAlwaysOnVpnPackage(admin, packageName, true)
                emptyList()
            } else {
                listOf("Always-on VPN lockdown requires Android 7.0+")
            }
        }.getOrElse { listOf("Always-on VPN failed: ${it.message}") }
    }

    fun getActiveAdmins(): List<DeviceAdminEntry> {
        val activeAdmins = dpm.activeAdmins ?: emptyList()
        return activeAdmins.map { component ->
            val label = runCatching {
                val info = context.packageManager.getReceiverInfo(component, 0)
                info.loadLabel(context.packageManager).toString()
            }.getOrElse { component.flattenToShortString() }
            DeviceAdminEntry(
                componentName = component,
                packageName = component.packageName,
                label = label,
                isThisApp = component == admin
            )
        }.sortedBy { it.label.lowercase() }
    }

    fun removeAdmin(entry: DeviceAdminEntry): String {
        return if (entry.isThisApp) {
            removeAdminOrOwner()
        } else {
            "Open Device Admin settings to remove ${entry.label}. Android only allows direct self-removal here."
        }
    }

    fun createAdminSettingsIntent(): Intent = Intent(Settings.ACTION_DEVICE_ADMIN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    fun removeAdminOrOwner(): String {
        return when {
            isDeviceOwnerApp() -> runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    dpm.clearDeviceOwnerApp(context.packageName)
                    "Device owner removal requested"
                } else {
                    "Device owner removal requires Android 7.0+"
                }
            }.getOrElse { "Device owner removal failed: ${it.message}" }
            isAdminActive() -> {
                dpm.removeActiveAdmin(admin)
                "Device admin removal requested"
            }
            else -> "No active admin or owner to remove"
        }
    }

    fun isDeviceOwnerApp(): Boolean = dpm.isDeviceOwnerApp(context.packageName)

    fun isProfileOwnerApp(): Boolean = dpm.isProfileOwnerApp(context.packageName)

    fun isAdminActive(): Boolean = dpm.isAdminActive(admin)

    private fun applyRestriction(key: String, enabled: Boolean, failures: MutableList<String>) {
        runCatching {
            if (enabled) dpm.addUserRestriction(admin, key) else dpm.clearUserRestriction(admin, key)
        }.onFailure {
            failures.add("$key failed: ${it.message}")
        }
    }
}
