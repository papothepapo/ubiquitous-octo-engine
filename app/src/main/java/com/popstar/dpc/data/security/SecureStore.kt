package com.popstar.dpc.data.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecureStore(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "secure_popstar_store",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun savePasswordRecord(record: PasswordRecord) {
        val saved = prefs.edit()
            .putString(KEY_PASSWORD_HASH, record.hashBase64)
            .putString(KEY_PASSWORD_SALT, record.saltBase64)
            .commit()
        check(saved) { "Secure password storage write failed" }
    }

    fun getPasswordRecord(): PasswordRecord? {
        val hash = prefs.getString(KEY_PASSWORD_HASH, null) ?: return null
        val salt = prefs.getString(KEY_PASSWORD_SALT, null) ?: return null
        return PasswordRecord(hash, salt)
    }

    fun clearPasswordRecord() {
        val cleared = prefs.edit().remove(KEY_PASSWORD_HASH).remove(KEY_PASSWORD_SALT).commit()
        check(cleared) { "Secure password storage clear failed" }
    }

    fun saveEncryptedPolicy(blob: String) {
        val saved = prefs.edit().putString(KEY_POLICY_BLOB, blob).commit()
        check(saved) { "Secure policy storage write failed" }
    }

    fun getEncryptedPolicy(): String? = prefs.getString(KEY_POLICY_BLOB, null)

    companion object {
        private const val KEY_PASSWORD_HASH = "password_hash"
        private const val KEY_PASSWORD_SALT = "password_salt"
        private const val KEY_POLICY_BLOB = "policy_blob"
    }
}
