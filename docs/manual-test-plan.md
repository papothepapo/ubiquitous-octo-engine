# Manual Testing Plan

## Matrix
- Android 11, 12, 13, 14
- Samsung Knox, Pixel AOSP, Xiaomi MIUI

## Core scenarios
1. Provision as device owner and verify admin active state.
2. Toggle each restriction and validate OS behavior.
3. Suspend selected packages and confirm launch failure.
4. Start VPN and validate blocked domain behavior.
5. Switch password mode across timed/persistent/disabled.
6. Export/import encrypted policy and compare resulting state.
7. Generate audit entries and verify retention/export.

## Failure handling
- Validate clear error when device-owner provisioning denied.
- Validate clear error when VPN permission denied.
