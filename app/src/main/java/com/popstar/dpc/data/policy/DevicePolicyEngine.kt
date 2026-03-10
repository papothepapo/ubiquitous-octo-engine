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

    fun applyRestrictions(policy: RestrictionPolicy) {
        setRestriction(UserManager.DISALLOW_CONFIG_WIFI, policy.wifiBlocked)
        setRestriction(UserManager.DISALLOW_SMS, policy.smsBlocked)
        setRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS, policy.mobileDataBlocked)
        setRestriction(UserManager.DISALLOW_FACTORY_RESET, policy.deviceResetBlocked)
        setRestriction(UserManager.DISALLOW_NETWORK_RESET, policy.networkResetBlocked)
    }

    fun suspendPackages(rules: List<AppRule>) {
        val targets = rules.filter { it.suspended }.map { it.packageName }.toTypedArray()
        if (targets.isNotEmpty()) dpm.setPackagesSuspended(admin, targets, true)
    }

    fun isAdminActive(): Boolean = dpm.isAdminActive(admin)

    private fun setRestriction(key: String, enabled: Boolean) {
        if (enabled) dpm.addUserRestriction(admin, key) else dpm.clearUserRestriction(admin, key)
    }
}
