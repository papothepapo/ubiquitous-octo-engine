# Popstar DPC

Popstar DPC is a production-focused Android **Device Policy Controller (DPC)** with a local VPN firewall engine. It is designed for enterprise/private distribution where the app is provisioned as a device owner and manages app restrictions, system controls, and network policy.

## Features
- Device owner provisioning notes and admin receiver integration.
- Password enforcement modes: timed, persistent, and disabled.
- First-run password setup gate and launch unlock enforcement when policy requires it.
- Bottom navigation with Device Control, Firewall, and Settings tabs.
- On-device `VpnService` with DNS + TLS SNI parsing and local blocked-attempt logging (full transport forwarder still pending).
- Policy bundle model with encrypted export/import-ready storage.
- Export/import encrypted policy files via Settings file picker flow.
- Audit log model and retention/export hooks.
- DPM apply status and failure messages surfaced in Settings.
- Unit tests for policy logic and firewall rule matching.

## Build
```bash
gradle clean assembleDebug
gradle testDebugUnitTest
```

## Install
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Device owner provisioning (test device wipe required)
```bash
adb shell dpm set-device-owner com.popstar.dpc/.admin.PopstarDeviceAdminReceiver
```

If OEM policy blocks ADB provisioning, use QR/NFC/zero-touch provisioning per enterprise enrollment process.

## Release signing
1. Generate release key:
   ```bash
   keytool -genkeypair -v -keystore popstar-release.jks -alias popstar -keyalg RSA -keysize 4096 -validity 3650
   ```
2. Add to `~/.gradle/gradle.properties`:
   ```properties
   POPSTAR_STORE_FILE=/secure/path/popstar-release.jks
   POPSTAR_STORE_PASSWORD=***
   POPSTAR_KEY_ALIAS=popstar
   POPSTAR_KEY_PASSWORD=***
   ```
3. Add release signingConfig in `app/build.gradle.kts` and run `gradle assembleRelease`.

## Documentation index
- Architecture: `docs/architecture.md`
- Wireframes/UI specs: `wireframes/`
- Implementation checklist: `docs/implementation-checklist.md`
- DPM/VPN integration notes: `docs/integration-notes.md`
- Security checklist: `docs/security-checklist.md`
- Manual test plan: `docs/manual-test-plan.md`
- Release notes: `docs/release-notes.md`
- Sample encrypted policy: `artifacts/sample-policy.enc.json`
- Sample audit log: `artifacts/final-audit-log.json`

## Distribution guidance
For Play and enterprise compliance use managed Google Play private app or EMM deployment. DPC + VPN permissions are sensitive and intended for enterprise/admin-controlled deployments.
