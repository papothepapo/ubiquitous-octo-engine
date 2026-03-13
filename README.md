# Popstar DPC

Popstar DPC is a production-focused Android **Device Policy Controller (DPC)** with a local VPN firewall engine. It is designed for enterprise/private distribution where the app is provisioned as a device owner and manages app restrictions, system controls, and network policy.

## Features
- Device owner provisioning notes and admin receiver integration.
- Password enforcement modes: timed, persistent, and disabled.
- First-run password setup gate and launch unlock enforcement when policy requires it.
- Bottom navigation with Device Control, Firewall, and Settings tabs.
- Device Control now includes launchable-app inventory, search, bulk selection, and app rule toggles (block/suspend/network).
- On-device `VpnService` with app-level packet owner checks, DNS + TLS SNI host matching, DNS/UDP forwarding for allowed traffic, and blocked-attempt logging (full TCP stream forwarder still pending).
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


## Build debug APK with GitHub CI/CD (step-by-step)
1. Create `.github/workflows/build-debug-apk.yml` with a workflow that checks out code, sets up JDK 17 + Android SDK, runs unit tests, builds `assembleDebug`, and uploads `app-debug.apk` as an artifact.
   - This repository workflow uses `gradle` in CI (instead of `./gradlew`) so it does not depend on a checked-in `gradle-wrapper.jar`.
2. Commit and push your branch to GitHub.
3. Open **Actions** in GitHub and run **Build Debug APK** manually via **Run workflow** (or let it run automatically on push/PR).
4. Wait for the workflow to finish successfully.
5. Open the workflow run and download the `app-debug-apk` artifact.
6. Unzip the artifact and install the APK:
   ```bash
   adb install -r app-debug.apk
   ```

This repository already includes the workflow at `.github/workflows/build-debug-apk.yml`, so you can use these steps immediately.

## Distribution guidance
For Play and enterprise compliance use managed Google Play private app or EMM deployment. DPC + VPN permissions are sensitive and intended for enterprise/admin-controlled deployments.
