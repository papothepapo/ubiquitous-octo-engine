package com.popstar.dpc

import com.popstar.dpc.data.security.PasswordHasher
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordHasherTest {
    @Test
    fun verifiesCorrectPassword() {
        val record = PasswordHasher.create("super-secret")
        assertTrue(PasswordHasher.verify("super-secret", record.hashBase64, record.saltBase64))
    }

    @Test
    fun rejectsWrongPassword() {
        val record = PasswordHasher.create("super-secret")
        assertFalse(PasswordHasher.verify("wrong", record.hashBase64, record.saltBase64))
    }
}
