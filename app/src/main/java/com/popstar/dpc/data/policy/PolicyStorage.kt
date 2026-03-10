package com.popstar.dpc.data.policy

import com.popstar.dpc.data.model.PolicyBundle
import com.popstar.dpc.data.security.CryptoManager
import com.popstar.dpc.data.security.SecureStore
import kotlinx.serialization.json.Json

class PolicyStorage(
    private val secureStore: SecureStore,
    private val cryptoManager: CryptoManager,
    private val json: Json = Json { ignoreUnknownKeys = true; prettyPrint = true }
) {
    fun load(): PolicyBundle {
        val encrypted = secureStore.getEncryptedPolicy() ?: return PolicyBundle()
        return runCatching {
            val clear = cryptoManager.decrypt(encrypted)
            json.decodeFromString<PolicyBundle>(clear)
        }.getOrElse { PolicyBundle() }
    }

    fun save(bundle: PolicyBundle) {
        val clear = json.encodeToString(bundle)
        val encrypted = cryptoManager.encrypt(clear)
        secureStore.saveEncryptedPolicy(encrypted)
    }
}
