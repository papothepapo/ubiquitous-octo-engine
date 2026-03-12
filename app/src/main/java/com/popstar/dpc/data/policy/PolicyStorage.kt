package com.popstar.dpc.data.policy

import com.popstar.dpc.data.model.PolicyBundle
import com.popstar.dpc.data.security.CryptoManager
import com.popstar.dpc.data.security.SecureStore
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class ExportedPolicy(
    val version: Int = 1,
    val algorithm: String = "AES/GCM/NoPadding",
    val ciphertext: String
)

class PolicyStorage(
    private val secureStore: SecureStore,
    private val cryptoManager: CryptoManager,
    private val json: Json = Json { ignoreUnknownKeys = true; prettyPrint = true }
) {
    fun load(): PolicyBundle {
        val encrypted = secureStore.getEncryptedPolicy() ?: return PolicyBundle()
        return decodeBundle(encrypted) ?: PolicyBundle()
    }

    fun save(bundle: PolicyBundle) {
        val encrypted = encodeBundle(bundle)
        secureStore.saveEncryptedPolicy(encrypted)
    }

    fun exportEncryptedPolicy(bundle: PolicyBundle): String {
        val payload = ExportedPolicy(ciphertext = encodeBundle(bundle))
        return json.encodeToString(payload)
    }

    fun importEncryptedPolicy(payload: String): PolicyBundle? {
        val parsed = runCatching { json.decodeFromString<ExportedPolicy>(payload) }.getOrNull() ?: return null
        return decodeBundle(parsed.ciphertext)
    }

    private fun encodeBundle(bundle: PolicyBundle): String {
        val clear = json.encodeToString(bundle)
        return cryptoManager.encrypt(clear)
    }

    private fun decodeBundle(encrypted: String): PolicyBundle? {
        return runCatching {
            val clear = cryptoManager.decrypt(encrypted)
            json.decodeFromString<PolicyBundle>(clear)
        }.getOrNull()
    }
}
