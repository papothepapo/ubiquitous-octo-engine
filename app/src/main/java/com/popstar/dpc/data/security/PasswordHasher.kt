package com.popstar.dpc.data.security

import java.util.Base64
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

data class PasswordRecord(val hashBase64: String, val saltBase64: String)

object PasswordHasher {
    private const val ITERATIONS = 120_000
    private const val KEY_LENGTH_BITS = 256

    fun create(password: String): PasswordRecord {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        val hash = pbkdf2(password, salt)
        return PasswordRecord(
            hashBase64 = Base64.getEncoder().encodeToString(hash),
            saltBase64 = Base64.getEncoder().encodeToString(salt)
        )
    }

    fun verify(password: String, hashBase64: String, saltBase64: String): Boolean {
        val expected = Base64.getDecoder().decode(hashBase64)
        val salt = Base64.getDecoder().decode(saltBase64)
        val actual = pbkdf2(password, salt)
        return expected.contentEquals(actual)
    }

    private fun pbkdf2(password: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH_BITS)
        val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return f.generateSecret(spec).encoded
    }
}
