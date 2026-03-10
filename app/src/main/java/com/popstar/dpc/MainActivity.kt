package com.popstar.dpc

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.popstar.dpc.auth.PasswordPolicyEvaluator
import com.popstar.dpc.data.model.*
import com.popstar.dpc.data.policy.DevicePolicyEngine
import com.popstar.dpc.data.policy.PolicyStorage
import com.popstar.dpc.data.security.CryptoManager
import com.popstar.dpc.data.security.PasswordHasher
import com.popstar.dpc.data.security.SecureStore
import com.popstar.dpc.ui.screens.*
import com.popstar.dpc.ui.theme.PopstarTheme

private enum class AuthState { LOADING, SETUP, LOCKED, UNLOCKED }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            PopstarTheme {
                val secureStore = remember { SecureStore(this) }
                val policyStorage = remember { PolicyStorage(secureStore, CryptoManager()) }
                val devicePolicyEngine = remember { DevicePolicyEngine(this) }

                var bundle by remember { mutableStateOf(PolicyBundle()) }
                var authState by remember { mutableStateOf(AuthState.LOADING) }

                LaunchedEffect(Unit) {
                    bundle = policyStorage.load()
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
                        if (ok) authState = AuthState.UNLOCKED
                        ok
                    }

                    AuthState.UNLOCKED -> MainTabs(
                        bundle = bundle,
                        onBundleChange = {
                            bundle = it
                            policyStorage.save(it)
                        },
                        onApplyPolicies = {
                            devicePolicyEngine.applyRestrictions(bundle.restrictionPolicy)
                            devicePolicyEngine.applySuspensionRules(bundle.appRules)
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
    onBundleChange: (PolicyBundle) -> Unit,
    onApplyPolicies: () -> Unit,
    onDisablePassword: () -> Unit
) {
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
                    enforcementMode = bundle.passwordPolicy.mode,
                    onRestrictionChanged = { onBundleChange(bundle.copy(restrictionPolicy = it)) },
                    onEnforcementModeChanged = {
                        onBundleChange(
                            bundle.copy(
                                passwordPolicy = bundle.passwordPolicy.copy(
                                    mode = it,
                                    enabledAtEpochMs = System.currentTimeMillis()
                                )
                            )
                        )
                    },
                    onApplyPolicies = onApplyPolicies
                )
            }
            composable("firewall") {
                FirewallScreen(bundle.firewallRules) { pattern ->
                    val next = FirewallRule(
                        id = System.currentTimeMillis().toString(),
                        pattern = pattern,
                        priority = bundle.firewallRules.size + 1
                    )
                    onBundleChange(bundle.copy(firewallRules = bundle.firewallRules + next))
                }
            }
            composable("settings") {
                SettingsScreen(onDisablePassword = onDisablePassword)
            }
        }
    }
}
