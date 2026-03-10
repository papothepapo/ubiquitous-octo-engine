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

    fun savePasswordHash(hash: String) = prefs.edit().putString(KEY_PASSWORD_HASH, hash).apply()
    fun getPasswordHash(): String? = prefs.getString(KEY_PASSWORD_HASH, null)

    fun saveEncryptedPolicy(blob: String) = prefs.edit().putString(KEY_POLICY_BLOB, blob).apply()
    fun getEncryptedPolicy(): String? = prefs.getString(KEY_POLICY_BLOB, null)

    companion object {
        private const val KEY_PASSWORD_HASH = "password_hash"
        private const val KEY_POLICY_BLOB = "policy_blob"
    }
}
