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
- [~] Launchable app inventory + search + bulk select + app rule toggles implemented; deeper package action UX polish pending.
- [~] DPM restrictions expanded with additional safe restrictions + error reporting; OEM/API matrix still pending.
- [~] VPN DNS + TLS SNI parsing, DNS forward/reply path, generic UDP request/response forwarding, and blocked-event logging implemented; full TCP stream proxying/QUIC-specific handling still pending.
- [~] Foreground VPN notification + stop action + revoke handling implemented; advanced reliability tuning still pending.
- [ ] Full app inventory with bulk-select and real package actions.
- [ ] Complete DPM restrictions mapped to OEM/API-specific safe calls.
- [ ] Full VPN packet parsing (DNS + SNI + QUIC handling).
- [ ] Foreground service reliability improvements (notification resiliency and restart handling).

## P2 (enterprise polish)
- [ ] Managed configurations support.
- [ ] OEM compatibility matrix automation.
- [ ] Remote audit export adapter (optional, enterprise-managed).
