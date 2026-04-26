package com.popstar.dpc.data.security

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

data class PasswordRecord(val hashBase64: String, val saltBase64: String)

object PasswordHasher {
    const val MIN_PASSWORD_LENGTH = 12
    private const val ITERATIONS = 210_000
    private const val KEY_LENGTH_BITS = 256
    private const val SALT_BYTES = 32

    fun validationError(password: String): String? {
        if (password.length < MIN_PASSWORD_LENGTH) {
            return "Password must be at least $MIN_PASSWORD_LENGTH characters"
        }

        val classes = listOf(
            password.any(Char::isLowerCase),
            password.any(Char::isUpperCase),
            password.any(Char::isDigit),
            password.any { !it.isLetterOrDigit() }
        ).count { it }

        return if (password.length < 16 && classes < 3) {
            "Use at least 3 of uppercase, lowercase, numbers, and symbols"
        } else {
            null
        }
    }

    fun create(password: String): PasswordRecord {
        validationError(password)?.let { throw IllegalArgumentException(it) }
        val salt = ByteArray(SALT_BYTES)
        SecureRandom().nextBytes(salt)
        val hash = pbkdf2(password, salt)
        return PasswordRecord(
            hashBase64 = Base64.getEncoder().encodeToString(hash),
            saltBase64 = Base64.getEncoder().encodeToString(salt)
        )
    }

    fun verify(password: String, hashBase64: String, saltBase64: String): Boolean {
        val expected = runCatching { Base64.getDecoder().decode(hashBase64) }.getOrNull() ?: return false
        val salt = runCatching { Base64.getDecoder().decode(saltBase64) }.getOrNull() ?: return false
        val actual = pbkdf2(password, salt)
        return MessageDigest.isEqual(expected, actual)
    }

    private fun pbkdf2(password: String, salt: ByteArray): ByteArray {
        val chars = password.toCharArray()
        val spec = PBEKeySpec(chars, salt, ITERATIONS, KEY_LENGTH_BITS)
        return try {
            val f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            f.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
        }
    }
}
