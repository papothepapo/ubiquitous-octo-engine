package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.VpnLockdownConfig
import com.popstar.dpc.data.model.VpnLogEntry

@Composable
fun FirewallScreen(
    rules: List<FirewallRule>,
    blockedEvents: List<VpnLogEntry>,
    vpnStatus: String?,
    vpnLockdown: VpnLockdownConfig,
    availableVpnApps: List<InstalledAppInfo>,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
    onAddRule: (String) -> Unit,
    onClearLogs: () -> Unit,
    onVpnLockdownChanged: (Boolean, String?) -> Unit
) {
    val pattern = remember { mutableStateOf("") }
    val logsExpanded = remember { mutableStateOf(true) }
    val selectedVpn = remember(vpnLockdown.selectedVpnPackage) { mutableStateOf(vpnLockdown.selectedVpnPackage.orEmpty()) }
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("VPN", style = MaterialTheme.typography.titleMedium)
                    Text("VPN can only be turned off from inside the app.")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onStartVpn) { Text("Start local VPN") }
                        Button(onClick = onStopVpn) { Text("Turn off VPN") }
                    }
                    vpnStatus?.let { Text("VPN status: $it") }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Lockdown mode", style = MaterialTheme.typography.titleMedium)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Enable always-on VPN lockdown")
                        Switch(
                            checked = vpnLockdown.enabled,
                            onCheckedChange = { onVpnLockdownChanged(it, selectedVpn.value.ifBlank { null }) }
                        )
                    }
                    OutlinedTextField(
                        value = selectedVpn.value,
                        onValueChange = {
                            selectedVpn.value = it
                            onVpnLockdownChanged(vpnLockdown.enabled, it.ifBlank { null })
                        },
                        label = { Text("VPN package for lockdown") },
                        supportingText = { Text("Installed VPNs: ${availableVpnApps.joinToString { it.packageName }.ifBlank { "none detected" }}") },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Domain / URL blocking", style = MaterialTheme.typography.titleMedium)
                    Text("Rules are saved immediately, but traffic and policy enforcement changes only fully apply after Apply changes where applicable.")
                    OutlinedTextField(
                        value = pattern.value,
                        onValueChange = { pattern.value = it },
                        label = { Text("Rule pattern (example: *.social.example)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Button(onClick = {
                        if (pattern.value.isNotBlank()) {
                            onAddRule(pattern.value.trim())
                            pattern.value = ""
                        }
                    }) { Text("Add rule") }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Configured rules", style = MaterialTheme.typography.titleMedium)
                    if (rules.isEmpty()) Text("No rules yet")
                    rules.forEach { rule ->
                        Text("#${rule.priority} ${rule.pattern} ${rule.appPackage ?: "(global)"}")
                    }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Column {
                            Text("VPN logs", style = MaterialTheme.typography.titleMedium)
                            Text("Grouped by site and app where available")
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { logsExpanded.value = !logsExpanded.value }) { Text(if (logsExpanded.value) "Collapse" else "Expand") }
                            Button(onClick = onClearLogs) { Text("Delete logs") }
                        }
                    }
                    if (logsExpanded.value) {
                        if (blockedEvents.isEmpty()) {
                            Text("No blocked traffic logged yet")
                        } else {
                            val grouped = blockedEvents.groupBy { Triple(it.category, it.appPackage ?: "Unknown app", it.site ?: "Unknown site") }
                            grouped.entries.take(30).forEach { (key, values) ->
                                Text("${key.first}: ${key.second} - ${key.third} - ${values.size} events")
                            }
                        }
                    }
                }
            }
        }
    }
}
