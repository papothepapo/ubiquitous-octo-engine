package com.popstar.dpc

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.popstar.dpc.auth.PasswordPolicyEvaluator
import com.popstar.dpc.data.firewall.FirewallRuntime
import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.PasswordEnforcementMode
import com.popstar.dpc.data.model.PasswordPolicy
import com.popstar.dpc.data.model.PolicyBundle
import com.popstar.dpc.data.policy.DevicePolicyEngine
import com.popstar.dpc.data.policy.PolicyStorage
import com.popstar.dpc.data.security.CryptoManager
import com.popstar.dpc.data.security.PasswordHasher
import com.popstar.dpc.data.security.SecureStore
import com.popstar.dpc.ui.screens.DeviceControlScreen
import com.popstar.dpc.ui.screens.FirewallScreen
import com.popstar.dpc.ui.screens.InstalledAppInfo
import com.popstar.dpc.ui.screens.SettingsScreen
import com.popstar.dpc.ui.screens.SetupPasswordScreen
import com.popstar.dpc.ui.screens.UnlockScreen
import com.popstar.dpc.ui.theme.PopstarTheme

private enum class AuthState { LOADING, SETUP, LOCKED, UNLOCKED }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val secureStore = remember { SecureStore(this) }
            val policyStorage = remember { PolicyStorage(secureStore, CryptoManager()) }
            val devicePolicyEngine = remember { DevicePolicyEngine(this) }

            var bundle by remember { mutableStateOf(PolicyBundle()) }
            var authState by remember { mutableStateOf(AuthState.LOADING) }
            var installedApps by remember { mutableStateOf<List<InstalledAppInfo>>(emptyList()) }

            PopstarTheme(themeMode = bundle.themeMode) {

                LaunchedEffect(Unit) {
                    bundle = policyStorage.load()
                    installedApps = loadLaunchableApps(packageManager)
                    FirewallRuntime.rules = bundle.firewallRules
                    FirewallRuntime.blockedPackages = bundle.appRules
                        .filter { it.networkBlocked }
                        .map { it.packageName }
                        .toSet()
                }

                LaunchedEffect(Unit) {
                    val record = secureStore.getPasswordRecord()
                    val passwordRequired = PasswordPolicyEvaluator.isPasswordRequired(
                        bundle.passwordPolicy,
                        System.currentTimeMillis()
                    )
                    authState = when {
                        record == null && bundle.passwordPolicy.mode != PasswordEnforcementMode.DISABLED -> AuthState.SETUP
                        passwordRequired && record != null -> AuthState.LOCKED
                        else -> AuthState.UNLOCKED
                    }
                }

                when (authState) {
                    AuthState.LOADING -> CircularProgressIndicator()
                    AuthState.SETUP -> SetupPasswordScreen { password, mode, days ->
                        val record = PasswordHasher.create(password)
                        secureStore.savePasswordRecord(record)
                        bundle = bundle.copy(
                            passwordPolicy = PasswordPolicy(
                                mode = mode,
                                timedDays = days,
                                enabledAtEpochMs = System.currentTimeMillis()
                            )
                        )
                        policyStorage.save(bundle)
                        authState = AuthState.UNLOCKED
                    }

                    AuthState.LOCKED -> UnlockScreen { entered ->
                        val record = secureStore.getPasswordRecord() ?: return@UnlockScreen false
                        val ok = PasswordHasher.verify(entered, record.hashBase64, record.saltBase64)
                        if (ok) {
                            authState = AuthState.UNLOCKED
                        }
                        ok
                    }

                    AuthState.UNLOCKED -> MainTabs(
                        bundle = bundle,
                        installedApps = installedApps,
                        onBundleChange = {
                            bundle = it
                            FirewallRuntime.rules = it.firewallRules
                            FirewallRuntime.blockedPackages = it.appRules
                                .filter { rule -> rule.networkBlocked }
                                .map { rule -> rule.packageName }
                                .toSet()
                            policyStorage.save(it)
                        },
                        policyStorage = policyStorage,
                        devicePolicyEngine = devicePolicyEngine,
                        onApplyPolicies = {
                            val restrictionFailures =
                                devicePolicyEngine.applyRestrictions(bundle.restrictionPolicy)
                            val suspensionFailures =
                                devicePolicyEngine.applyAppControlRules(bundle.appRules)
                            val failures = restrictionFailures + suspensionFailures
                            if (failures.isEmpty()) "Policies applied" else failures.joinToString("; ")
                        },
                        onDisablePassword = {
                            secureStore.clearPasswordRecord()
                            val updated = bundle.copy(
                                passwordPolicy = bundle.passwordPolicy.copy(mode = PasswordEnforcementMode.DISABLED)
                            )
                            bundle = updated
                            policyStorage.save(updated)
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun MainTabs(
    bundle: PolicyBundle,
    installedApps: List<InstalledAppInfo>,
    onBundleChange: (PolicyBundle) -> Unit,
    policyStorage: PolicyStorage,
    devicePolicyEngine: DevicePolicyEngine,
    onApplyPolicies: () -> String?,
    onDisablePassword: () -> Unit
) {
    val context = LocalContext.current
    var importExportStatus by remember { mutableStateOf<String?>(null) }
    var enforcementStatus by remember { mutableStateOf<String?>(null) }
    var vpnStatus by remember { mutableStateOf<String?>(null) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        val payload = policyStorage.exportEncryptedPolicy(bundle)
        runCatching {
            context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(payload) }
        }.onSuccess {
            importExportStatus = "Exported encrypted policy"
        }.onFailure {
            importExportStatus = "Export failed: ${it.message}"
        }
    }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        }.onSuccess { payload ->
            val parsed = payload?.let { policyStorage.importEncryptedPolicy(it) }
            if (parsed != null) {
                onBundleChange(parsed)
                importExportStatus = "Imported encrypted policy"
            } else {
                importExportStatus = "Import failed: invalid payload"
            }
        }.onFailure {
            importExportStatus = "Import failed: ${it.message}"
        }
    }


    val vpnPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent == null) {
            context.startService(com.popstar.dpc.vpn.PopstarVpnService.startIntent(context))
            vpnStatus = "VPN started"
        } else {
            vpnStatus = "VPN permission was not granted"
        }
    }

    val navController = rememberNavController()
    val items = listOf("device", "firewall", "settings")

    Scaffold(
        bottomBar = {
            NavigationBar {
                val backstack by navController.currentBackStackEntryAsState()
                items.forEach { route ->
                    NavigationBarItem(
                        selected = backstack?.destination?.route == route,
                        onClick = {
                            navController.navigate(route) {
                                popUpTo(navController.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        label = { Text(route.replaceFirstChar { it.uppercase() }) },
                        icon = {}
                    )
                }
            }
        }
    ) { padding ->
        NavHost(navController, startDestination = "device", modifier = Modifier.padding(padding)) {
            composable("device") {
                DeviceControlScreen(
                    restrictionPolicy = bundle.restrictionPolicy,
                    installedApps = installedApps,
                    appRules = bundle.appRules,
                    onAppRulesChanged = { onBundleChange(bundle.copy(appRules = it)) },
                    onRestrictionChanged = { onBundleChange(bundle.copy(restrictionPolicy = it)) },
                    onApplyPolicies = {
                        onApplyPolicies()?.let { enforcementStatus = it }
                    }
                )
            }
            composable("firewall") {
                FirewallScreen(
                    rules = bundle.firewallRules,
                    blockedEvents = FirewallRuntime.events()
                ) { pattern ->
                    val next = FirewallRule(
                        id = System.currentTimeMillis().toString(),
                        pattern = pattern,
                        priority = bundle.firewallRules.size + 1
                    )
                    onBundleChange(bundle.copy(firewallRules = bundle.firewallRules + next))
                }
            }
            composable("settings") {
                SettingsScreen(
                    currentThemeMode = bundle.themeMode,
                    onThemeModeChanged = { onBundleChange(bundle.copy(themeMode = it)) },
                    deviceOwnerStatus = when {
                        devicePolicyEngine.isDeviceOwnerApp() -> "Device owner active (test mode expected for easy removal/transfer)"
                        devicePolicyEngine.isProfileOwnerApp() -> "Profile owner active"
                        devicePolicyEngine.isAdminActive() -> "Device admin active, not device owner"
                        else -> "No admin ownership active"
                    },
                    adbDeviceOwnerCommand = "adb shell dpm set-device-owner --device-owner-only com.popstar.dpc/.admin.PopstarDeviceAdminReceiver",
                    onCopyAdbCommand = {
                        val clipboard = context.getSystemService(ClipboardManager::class.java)
                        clipboard?.setPrimaryClip(
                            ClipData.newPlainText(
                                "dpc_set_device_owner",
                                "adb shell dpm set-device-owner --device-owner-only com.popstar.dpc/.admin.PopstarDeviceAdminReceiver"
                            )
                        )
                        importExportStatus = "ADB command copied"
                    },
                    supportShortMessage = bundle.restrictionPolicy.supportShortMessage,
                    supportLongMessage = bundle.restrictionPolicy.supportLongMessage,
                    onSupportMessagesChanged = { shortMessage, longMessage ->
                        onBundleChange(
                            bundle.copy(
                                restrictionPolicy = bundle.restrictionPolicy.copy(
                                    supportShortMessage = shortMessage,
                                    supportLongMessage = longMessage
                                )
                            )
                        )
                        importExportStatus = "Support messages saved"
                    },
                    onDisablePassword = onDisablePassword,
                    onSetPassword = { password, mode, days ->
                        if (mode == PasswordEnforcementMode.DISABLED) {
                            onDisablePassword()
                            "Password disabled"
                        } else {
                            val record = PasswordHasher.create(password)
                            val updated = bundle.copy(
                                passwordPolicy = bundle.passwordPolicy.copy(
                                    mode = mode,
                                    timedDays = days,
                                    enabledAtEpochMs = System.currentTimeMillis()
                                )
                            )
                            onBundleChange(updated)
                            SecureStore(context).savePasswordRecord(record)
                            "Password policy saved"
                        }
                    },
                    importExportStatus = importExportStatus,
                    enforcementStatus = listOfNotNull(enforcementStatus, vpnStatus).joinToString(" | ").ifBlank { null },
                    onExport = { exportLauncher.launch("popstar-policy.enc.json") },
                    onImport = {
                        importLauncher.launch(arrayOf("application/json", "text/plain"))
                    },
                    onStartVpn = {
                        val prepareIntent = VpnService.prepare(context)
                        if (prepareIntent != null) {
                            vpnPermissionLauncher.launch(prepareIntent)
                        } else {
                            context.startService(com.popstar.dpc.vpn.PopstarVpnService.startIntent(context))
                            vpnStatus = "VPN started"
                        }
                    },
                    onStopVpn = {
                        context.startService(com.popstar.dpc.vpn.PopstarVpnService.stopIntent(context))
                        vpnStatus = "VPN stopped"
                    }
                )
            }
        }
    }
}

private fun loadLaunchableApps(pm: PackageManager): List<InstalledAppInfo> {
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    return pm.queryIntentActivities(intent, 0)
        .map {
            InstalledAppInfo(
                packageName = it.activityInfo.packageName,
                label = it.loadLabel(pm).toString()
            )
        }
        .distinctBy { it.packageName }
        .sortedBy { it.label.lowercase() }
}
