package com.popstar.dpc

import com.popstar.dpc.data.security.PasswordHasher
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordHasherTest {
    @Test
    fun verifiesCorrectPassword() {
        val record = PasswordHasher.create("Super-secret-2026")
        assertTrue(PasswordHasher.verify("Super-secret-2026", record.hashBase64, record.saltBase64))
    }

    @Test
    fun rejectsWrongPassword() {
        val record = PasswordHasher.create("Super-secret-2026")
        assertFalse(PasswordHasher.verify("wrong", record.hashBase64, record.saltBase64))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsWeakPasswordAtCreation() {
        PasswordHasher.create("short")
    }

    @Test
    fun rejectsMalformedStoredHash() {
        assertFalse(PasswordHasher.verify("anything", "not-base64", "also-not-base64"))
    }
}
