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
- [ ] Complete DPM restrictions mapped to OEM/API-specific safe calls.
- [ ] Full VPN packet parsing (DNS + SNI + QUIC handling).
- [ ] Foreground service notifications + reliability improvements.
- [ ] Encrypted policy import/export UX with file picker.

## P2 (enterprise polish)
- [ ] Managed configurations support.
- [ ] OEM compatibility matrix automation.
- [ ] Remote audit export adapter (optional, enterprise-managed).
