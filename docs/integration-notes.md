# DevicePolicyManager + VpnService Integration Notes

## Admin provisioning
- Receiver: `com.popstar.dpc.admin.PopstarDeviceAdminReceiver`
- Provision test command:
  `adb shell dpm set-device-owner com.popstar.dpc/.admin.PopstarDeviceAdminReceiver`

## Suspending packages
`DevicePolicyEngine.suspendPackages` calls `DevicePolicyManager.setPackagesSuspended(admin, packages, true)`.

## Blocking reset operations
Use `DevicePolicyManager.addUserRestriction(admin, UserManager.DISALLOW_FACTORY_RESET)` and `DISALLOW_NETWORK_RESET` when active.

## Force VPN
`RestrictionPolicy.forceVpn` is represented in policy model and should be mapped to `setAlwaysOnVpnPackage` in fully provisioned builds.

## Packet filtering
`PopstarVpnService` establishes tun interface and starts read loop. `FirewallRuleEngine` performs ordered wildcard matching for domain/app rules.
