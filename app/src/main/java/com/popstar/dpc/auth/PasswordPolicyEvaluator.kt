package com.popstar.dpc.auth

import com.popstar.dpc.data.model.PasswordEnforcementMode
import com.popstar.dpc.data.model.PasswordPolicy
import java.util.concurrent.TimeUnit

object PasswordPolicyEvaluator {
    fun isPasswordRequired(policy: PasswordPolicy, nowMs: Long): Boolean {
        return when (policy.mode) {
            PasswordEnforcementMode.DISABLED -> false
            PasswordEnforcementMode.PERSISTENT -> true
            PasswordEnforcementMode.TIMED -> {
                val elapsedDays = TimeUnit.MILLISECONDS.toDays(nowMs - policy.enabledAtEpochMs)
                elapsedDays < policy.timedDays
            }
        }
    }
}
