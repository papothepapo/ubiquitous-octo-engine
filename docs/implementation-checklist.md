# Implementation Checklist & Prioritized Plan

## P0 (implemented scaffold)
- [x] Android project setup + CI pipeline.
- [x] Device admin receiver and DPM engine surface.
- [x] VPN service with tun setup loop.
- [x] Bottom-nav UI and three tabs.
- [x] Password mode evaluator (timed/persistent/disabled).
- [x] Encrypted storage primitives (Keystore + encrypted prefs).
- [x] Unit test coverage for core policy logic.

## P1 (hardening next)
- [ ] Full app inventory with bulk-select and real package actions.
- [~] DPM restrictions expanded with additional safe restrictions + error reporting; OEM/API matrix still pending.
- [~] VPN DNS + TLS SNI parsing and blocked-event logging implemented; full packet forwarder/QUIC handling still pending.
- [~] Foreground VPN notification + stop action + revoke handling implemented; advanced reliability tuning still pending.
- [x] Encrypted policy import/export UX with file picker implemented.

## P2 (enterprise polish)
- [ ] Managed configurations support.
- [ ] OEM compatibility matrix automation.
- [ ] Remote audit export adapter (optional, enterprise-managed).
