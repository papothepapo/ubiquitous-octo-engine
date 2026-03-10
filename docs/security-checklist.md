# Security Checklist

- [x] Password/policy data encrypted at rest.
- [x] AES-GCM key material stored in Android Keystore.
- [x] Device admin receiver protected with `BIND_DEVICE_ADMIN`.
- [x] VPN service protected with `BIND_VPN_SERVICE`.
- [x] No biometric fallback included.
- [x] Restriction actions intended to require explicit confirmation in UI.
- [x] Audit log model present for all admin actions.
- [x] Backup export marked encrypted-only.

## Attack surface review
- DPC and VPN capabilities should be enterprise-distributed only.
- `QUERY_ALL_PACKAGES` must be justified for admin app control visibility.
- Avoid exporting internal activities/services unless required.
