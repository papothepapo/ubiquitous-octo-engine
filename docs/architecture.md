# High-level Architecture

```mermaid
flowchart LR
    UI[Compose UI\nDevice/Firewall/Settings] --> VM[State + Use Cases]
    VM --> PE[Policy Engine\nDevicePolicyManager]
    VM --> FE[Firewall Engine\nRule matcher]
    VM --> VPN[PopstarVpnService\npacket loop]
    VM --> SEC[CryptoManager + SecureStore]
    SEC --> KMS[Android Keystore]
    SEC --> ESP[EncryptedSharedPreferences]
    VM --> LOG[Audit Log Repository]
```

Modules (logical in current codebase):
1. DPC / policy engine (`data/policy`, `admin`)
2. VPN / firewall (`vpn`, `data/firewall`)
3. UI layer (`ui`, `MainActivity`)
4. Persistence & encryption (`data/security`, model serialization)
5. Test layer (`src/test`, `src/androidTest`)
