package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.PasswordEnforcementMode
import com.popstar.dpc.data.model.RestrictionPolicy

@Composable
fun DeviceControlScreen(
    restrictionPolicy: RestrictionPolicy,
    enforcementMode: PasswordEnforcementMode,
    onRestrictionChanged: (RestrictionPolicy) -> Unit,
    onEnforcementModeChanged: (PasswordEnforcementMode) -> Unit,
    onApplyPolicies: () -> Unit
) {
    val expanded = remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Application control", style = MaterialTheme.typography.titleMedium)
                    Button(onClick = { expanded.value = !expanded.value }) {
                        Text(if (expanded.value) "Collapse" else "Expand")
                    }
                    if (expanded.value) {
                        Text("App inventory wiring is pending for full package manager integration.")
                    }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("System restriction toggles", style = MaterialTheme.typography.titleMedium)
                    SwitchRow("Force VPN usage", restrictionPolicy.forceVpn) {
                        onRestrictionChanged(restrictionPolicy.copy(forceVpn = it))
                    }
                    SwitchRow("Block Wi-Fi", restrictionPolicy.wifiBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(wifiBlocked = it))
                    }
                    SwitchRow("Block SMS", restrictionPolicy.smsBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(smsBlocked = it))
                    }
                    SwitchRow("Block mobile data", restrictionPolicy.mobileDataBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(mobileDataBlocked = it))
                    }
                    SwitchRow("Block device reset", restrictionPolicy.deviceResetBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(deviceResetBlocked = it))
                    }
                    SwitchRow("Block network reset", restrictionPolicy.networkResetBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(networkResetBlocked = it))
                    }
                    SwitchRow("Block app reset", restrictionPolicy.appResetBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(appResetBlocked = it))
                    }
                    Button(onClick = onApplyPolicies) { Text("Apply on device") }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Password management", style = MaterialTheme.typography.titleMedium)
                    Text("Enforcement mode")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = enforcementMode == PasswordEnforcementMode.PERSISTENT,
                            onClick = { onEnforcementModeChanged(PasswordEnforcementMode.PERSISTENT) },
                            label = { Text("Persistent") }
                        )
                        FilterChip(
                            selected = enforcementMode == PasswordEnforcementMode.TIMED,
                            onClick = { onEnforcementModeChanged(PasswordEnforcementMode.TIMED) },
                            label = { Text("Timed") }
                        )
                        FilterChip(
                            selected = enforcementMode == PasswordEnforcementMode.DISABLED,
                            onClick = { onEnforcementModeChanged(PasswordEnforcementMode.DISABLED) },
                            label = { Text("Disabled") }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, onToggle: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label)
        Switch(checked = checked, onCheckedChange = onToggle)
    }
}
