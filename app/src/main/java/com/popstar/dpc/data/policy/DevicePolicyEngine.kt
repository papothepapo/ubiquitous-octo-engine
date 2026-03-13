package com.popstar.dpc.data.policy

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager
import com.popstar.dpc.admin.PopstarDeviceAdminReceiver
import com.popstar.dpc.data.model.AppRule
import com.popstar.dpc.data.model.RestrictionPolicy

class DevicePolicyEngine(private val context: Context) {
    private val dpm = context.getSystemService(DevicePolicyManager::class.java)
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

        // Additional hardening commonly used on managed devices.
        applyRestriction(UserManager.DISALLOW_SAFE_BOOT, policy.safeBootBlocked, failures)
        applyRestriction(UserManager.DISALLOW_ADD_USER, policy.deviceResetBlocked, failures)
        applyRestriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, policy.appResetBlocked, failures)
        applyRestriction(UserManager.DISALLOW_INSTALL_APPS, policy.appInstallBlocked, failures)
        applyRestriction(UserManager.DISALLOW_MODIFY_ACCOUNTS, policy.accountManagementBlocked, failures)
        applyRestriction(UserManager.DISALLOW_USB_FILE_TRANSFER, policy.mobileDataBlocked, failures)

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

            runCatching {
                dpm.setPackagesSuspended(admin, arrayOf(rule.packageName), rule.suspended)
            }.onFailure {
                failures.add("Suspend ${rule.packageName} failed: ${it.message}")
            }
        }

        return failures
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
