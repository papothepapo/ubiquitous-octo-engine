package com.popstar.dpc

import com.popstar.dpc.auth.PasswordPolicyEvaluator
import com.popstar.dpc.data.model.PasswordEnforcementMode
import com.popstar.dpc.data.model.PasswordPolicy
import org.junit.Assert.*
import org.junit.Test

class PasswordPolicyEvaluatorTest {
    @Test
    fun timedPolicyExpires() {
        val now = 10L * 24 * 60 * 60 * 1000
        val policy = PasswordPolicy(PasswordEnforcementMode.TIMED, timedDays = 5, enabledAtEpochMs = 0)
        assertFalse(PasswordPolicyEvaluator.isPasswordRequired(policy, now))
    }

    @Test
    fun persistentAlwaysRequires() {
        val policy = PasswordPolicy(PasswordEnforcementMode.PERSISTENT)
        assertTrue(PasswordPolicyEvaluator.isPasswordRequired(policy, 1L))
    }
}
