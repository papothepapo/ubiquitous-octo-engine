package com.popstar.dpc

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
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
import com.popstar.dpc.data.policy.DeviceAdminEntry
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class AuthState { LOADING, SETUP, LOCKED, UNLOCKED }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        var keepSplashVisible = true
        installSplashScreen().setKeepOnScreenCondition { keepSplashVisible }
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val secureStore = remember { SecureStore(this) }
            val policyStorage = remember { PolicyStorage(secureStore, CryptoManager()) }
            val devicePolicyEngine = remember { DevicePolicyEngine(this) }

            var bundle by remember { mutableStateOf(PolicyBundle()) }
            var authState by remember { mutableStateOf(AuthState.LOADING) }
            var installedApps by remember { mutableStateOf<List<InstalledAppInfo>>(emptyList()) }
            var deviceAdmins by remember { mutableStateOf<List<DeviceAdminEntry>>(emptyList()) }

            PopstarTheme(themeMode = bundle.themeMode) {
                LaunchedEffect(Unit) {
                    try {
                        val loadedBundle = withContext(Dispatchers.IO) { policyStorage.load().recordOpenEvent() }
                        val loadedApps = withContext(Dispatchers.IO) { loadInstalledApps(packageManager) }
                        bundle = loadedBundle
                        installedApps = loadedApps
                        withContext(Dispatchers.IO) { policyStorage.save(loadedBundle) }
                        deviceAdmins = devicePolicyEngine.getActiveAdmins()
                        FirewallRuntime.rules = loadedBundle.firewallRules
                        FirewallRuntime.blockedPackages = loadedBundle.appRules
                            .filter { it.networkBlocked }
                            .map { it.packageName }
                            .toSet()
                        FirewallRuntime.restore(loadedBundle.vpnLogs)

                        val record = secureStore.getPasswordRecord()
                        val passwordRequired = PasswordPolicyEvaluator.isPasswordRequired(
                            loadedBundle.passwordPolicy,
                            System.currentTimeMillis()
                        )
                        authState = when {
                            record == null && loadedBundle.passwordPolicy.mode != PasswordEnforcementMode.DISABLED -> AuthState.SETUP
                            passwordRequired && record != null -> AuthState.LOCKED
                            else -> AuthState.UNLOCKED
                        }
                    } finally {
                        keepSplashVisible = false
                    }
                }

                when (authState) {
                    AuthState.LOADING -> SplashLoadingScreen()
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
                        deviceAdmins = deviceAdmins,
                        onRefreshDeviceAdmins = { deviceAdmins = devicePolicyEngine.getActiveAdmins() },
                        onBundleChange = {
                            bundle = it
                            FirewallRuntime.rules = it.firewallRules
                            FirewallRuntime.blockedPackages = it.appRules
                                .filter { rule -> rule.networkBlocked }
                                .map { rule -> rule.packageName }
                                .toSet()
                            FirewallRuntime.restore(it.vpnLogs)
                            policyStorage.save(it)
                        },
                        policyStorage = policyStorage,
                        devicePolicyEngine = devicePolicyEngine,
                        onApplyPolicies = {
                            val restrictionFailures =
                                devicePolicyEngine.applyRestrictions(bundle.restrictionPolicy)
                            val suspensionFailures =
                                devicePolicyEngine.applyAppControlRules(bundle.appRules)
                            val vpnFailures = devicePolicyEngine.applyVpnLockdown(bundle.vpnLockdown)
                            val failures = restrictionFailures + suspensionFailures + vpnFailures
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
private fun SplashLoadingScreen() {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(androidx.compose.material3.MaterialTheme.colorScheme.background),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Popstar DPC",
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "Filtering made easy.",
                style = androidx.compose.material3.MaterialTheme.typography.titleMedium
            )
            CircularProgressIndicator(modifier = Modifier.padding(top = 8.dp))
        }
    }
}

@Composable
private fun MainTabs(
    bundle: PolicyBundle,
    installedApps: List<InstalledAppInfo>,
    deviceAdmins: List<DeviceAdminEntry>,
    onRefreshDeviceAdmins: () -> Unit,
    onBundleChange: (PolicyBundle) -> Unit,
    policyStorage: PolicyStorage,
    devicePolicyEngine: DevicePolicyEngine,
    onApplyPolicies: () -> String?,
    onDisablePassword: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    var importExportStatus by remember { mutableStateOf<String?>(null) }
    var enforcementStatus by remember { mutableStateOf<String?>(null) }
    var vpnStatus by remember { mutableStateOf<String?>(null) }

    fun updateBundle(transform: (PolicyBundle) -> PolicyBundle) {
        onBundleChange(transform(bundle).copy(vpnLogs = FirewallRuntime.events()))
    }

    fun showMessage(message: String) {
        scope.launch {
            snackbarHostState.currentSnackbarData?.dismiss()
            snackbarHostState.showSnackbar(
                message = message,
                withDismissAction = true,
                duration = SnackbarDuration.Short
            )
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        val payload = policyStorage.exportEncryptedPolicy(bundle.copy(vpnLogs = FirewallRuntime.events()))
        runCatching {
            context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(payload) }
        }.onSuccess {
            importExportStatus = "Exported encrypted policy"
            showMessage(importExportStatus!!)
        }.onFailure {
            importExportStatus = "Export failed: ${it.message}"
            showMessage(importExportStatus!!)
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
            importExportStatus?.let(::showMessage)
        }.onFailure {
            importExportStatus = "Import failed: ${it.message}"
            showMessage(importExportStatus!!)
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
        vpnStatus?.let(::showMessage)
    }

    LaunchedEffect(bundle.vpnAutoStart) {
        if (bundle.vpnAutoStart) {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent == null) {
                context.startService(com.popstar.dpc.vpn.PopstarVpnService.startIntent(context))
                vpnStatus = "VPN auto-started"
            } else {
                vpnStatus = "VPN auto-start pending permission"
            }
        }
    }

    val navController = rememberNavController()
    val items = listOf("device", "vpn", "settings")

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
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
                    deviceAdmins = deviceAdmins,
                    onAppRulesChanged = {
                        updateBundle { current -> current.copy(appRules = it) }
                    },
                    onRestrictionChanged = {
                        updateBundle { current -> current.copy(restrictionPolicy = it) }
                    },
                    onAppAction = { showMessage(it) },
                    onRestrictionAction = { showMessage(it) },
                    onApplyPolicies = {
                        onApplyPolicies()?.let {
                            enforcementStatus = it
                            showMessage(it)
                        }
                    },
                    onRemoveAdmin = { entry ->
                        context.startActivity(devicePolicyEngine.createAdminRemovalIntent())
                        showMessage("Opened device admin settings. Remove ${entry.label} there.")
                    }
                )
            }
            composable("vpn") {
                FirewallScreen(
                    rules = bundle.firewallRules,
                    blockedEvents = FirewallRuntime.events(),
                    vpnStatus = vpnStatus,
                    vpnLockdown = bundle.vpnLockdown,
                    availableVpnApps = installedApps.filter { it.isVpnCapable },
                    onStartVpn = {
                        val prepareIntent = VpnService.prepare(context)
                        if (prepareIntent != null) {
                            vpnPermissionLauncher.launch(prepareIntent)
                        } else {
                            context.startService(com.popstar.dpc.vpn.PopstarVpnService.startIntent(context))
                            vpnStatus = "VPN started"
                            showMessage(vpnStatus!!)
                        }
                    },
                    onStopVpn = {
                        context.startService(com.popstar.dpc.vpn.PopstarVpnService.stopIntent(context))
                        vpnStatus = "VPN stopped"
                        showMessage(vpnStatus!!)
                    },
                    onAddRule = { pattern ->
                        val next = FirewallRule(
                            id = System.currentTimeMillis().toString(),
                            pattern = pattern,
                            priority = bundle.firewallRules.size + 1
                        )
                        updateBundle { current -> current.copy(firewallRules = current.firewallRules + next) }
                        showMessage("Rule added. It takes effect after Apply changes.")
                    },
                    onClearLogs = {
                        FirewallRuntime.clear()
                        updateBundle { it.copy(vpnLogs = emptyList()) }
                        showMessage("VPN logs cleared")
                    },
                    onVpnLockdownChanged = { enabled, packageName ->
                        updateBundle {
                            it.copy(
                                vpnLockdown = it.vpnLockdown.copy(
                                    enabled = enabled,
                                    selectedVpnPackage = packageName
                                )
                            )
                        }
                        showMessage("VPN lockdown settings saved. Press Apply changes to enforce them.")
                    }
                )
            }
            composable("settings") {
                SettingsScreen(
                    currentThemeMode = bundle.themeMode,
                    onThemeModeChanged = { updateBundle { current -> current.copy(themeMode = it) } },
                    deviceOwnerStatus = when {
                        devicePolicyEngine.isDeviceOwnerApp() -> "Device owner active"
                        devicePolicyEngine.isProfileOwnerApp() -> "Profile owner active"
                        devicePolicyEngine.isAdminActive() -> "Device admin active, not device owner"
                        else -> "No admin ownership active"
                    },
                    adbDeviceOwnerCommand = "adb shell dpm set-device-owner --device-owner-only com.popstar.dpc/.admin.PopstarDeviceAdminReceiver",
                    onCopyAdbCommand = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        clipboard?.setPrimaryClip(
                            ClipData.newPlainText(
                                "dpc_set_device_owner",
                                "adb shell dpm set-device-owner --device-owner-only com.popstar.dpc/.admin.PopstarDeviceAdminReceiver"
                            )
                        )
                        importExportStatus = "ADB command copied"
                        showMessage(importExportStatus!!)
                    },
                    supportShortMessage = bundle.restrictionPolicy.supportShortMessage,
                    supportLongMessage = bundle.restrictionPolicy.supportLongMessage,
                    onSupportMessagesChanged = { shortMessage, longMessage ->
                        updateBundle {
                            it.copy(
                                restrictionPolicy = it.restrictionPolicy.copy(
                                    supportShortMessage = shortMessage,
                                    supportLongMessage = longMessage
                                )
                            )
                        }
                        importExportStatus = "Support messages saved"
                        showMessage("Support messages saved. Press Apply changes to enforce them.")
                    },
                    onDisablePassword = onDisablePassword,
                    onSetPassword = { password, mode, days ->
                        if (mode == PasswordEnforcementMode.DISABLED) {
                            onDisablePassword()
                            "Password disabled"
                        } else {
                            val record = PasswordHasher.create(password)
                            updateBundle {
                                it.copy(
                                    passwordPolicy = it.passwordPolicy.copy(
                                        mode = mode,
                                        timedDays = days,
                                        enabledAtEpochMs = System.currentTimeMillis()
                                    )
                                )
                            }
                            SecureStore(context).savePasswordRecord(record)
                            "Password policy saved"
                        }
                    },
                    importExportStatus = importExportStatus,
                    enforcementStatus = enforcementStatus,
                    vpnAutoStart = bundle.vpnAutoStart,
                    auditLogs = bundle.logs,
                    transferOwnerInstructions = "Export the encrypted policy, provision the new owner device, then import the policy there before removing admin/owner here.",
                    onVpnAutoStartChanged = { enabled -> updateBundle { current -> current.copy(vpnAutoStart = enabled) } },
                    onExport = { exportLauncher.launch("popstar-policy.enc.json") },
                    onImport = { importLauncher.launch(arrayOf("application/json", "text/plain")) },
                    onRemoveAdminOwner = {
                        devicePolicyEngine.removeAdminOrOwner()
                            .also { importExportStatus = it; showMessage(it) }
                    }
                )
            }
        }
    }
}

private fun PolicyBundle.recordOpenEvent(): PolicyBundle = copy(
    logs = logs + com.popstar.dpc.data.model.AuditLogEntry(
        timestamp = System.currentTimeMillis(),
        actor = "system",
        action = "app_opened",
        details = "App opened"
    )
)

private fun loadInstalledApps(pm: PackageManager): List<InstalledAppInfo> {
    val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    val launcherFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PackageManager.MATCH_ALL else 0
    val launchable = pm.queryIntentActivities(launcherIntent, launcherFlags)
        .map {
            val pkg = it.activityInfo.packageName
            InstalledAppInfo(
                packageName = pkg,
                label = it.loadLabel(pm).toString(),
                isSystemApp = (it.activityInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                isVpnCapable = packageProvidesVpnService(pm, pkg)
            )
        }

    val existingPackages = launchable.map { it.packageName }.toMutableSet()
    val installedApplications = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(allApplicationFlags().toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(allApplicationFlags())
        }
    }.getOrDefault(emptyList())

    val extraPackages = installedApplications
        .filter { it.packageName !in existingPackages }
        .map {
            InstalledAppInfo(
                packageName = it.packageName,
                label = pm.getApplicationLabel(it).toString(),
                isSystemApp = (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                isVpnCapable = packageProvidesVpnService(pm, it.packageName)
            )
        }

    return (launchable + extraPackages)
        .distinctBy { it.packageName }
        .sortedBy { it.label.lowercase() }
}

private fun allApplicationFlags(): Int {
    var flags = PackageManager.GET_META_DATA
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        flags = flags or PackageManager.MATCH_DISABLED_COMPONENTS or PackageManager.MATCH_DISABLED_UNTIL_USED_COMPONENTS
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        flags = flags or PackageManager.MATCH_UNINSTALLED_PACKAGES
    } else {
        @Suppress("DEPRECATION")
        run { flags = flags or PackageManager.GET_UNINSTALLED_PACKAGES }
    }
    return flags
}

private fun packageProvidesVpnService(pm: PackageManager, packageName: String): Boolean {
    val info = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_SERVICES.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PackageManager.GET_SERVICES)
        }
    }.getOrNull() ?: return false

    return info.services?.any { it.permission == android.Manifest.permission.BIND_VPN_SERVICE } == true
}
