package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.AppRule
import com.popstar.dpc.data.model.RestrictionPolicy

/** Launchable app metadata for app-control UI. */
data class InstalledAppInfo(val packageName: String, val label: String)

@Composable
fun DeviceControlScreen(
    restrictionPolicy: RestrictionPolicy,
    installedApps: List<InstalledAppInfo>,
    appRules: List<AppRule>,
    onAppRulesChanged: (List<AppRule>) -> Unit,
    onRestrictionChanged: (RestrictionPolicy) -> Unit,
    onApplyPolicies: () -> Unit
) {
    val expanded = remember { mutableStateOf(false) }
    val search = remember { mutableStateOf("") }
    val selected = remember { mutableStateOf(setOf<String>()) }

    val filtered = installedApps.filter {
        it.label.contains(search.value, ignoreCase = true) || it.packageName.contains(search.value, ignoreCase = true)
    }

    fun updateRule(packageName: String, transform: (AppRule) -> AppRule) {
        val current = appRules.associateBy { it.packageName }.toMutableMap()
        val next = transform(current[packageName] ?: AppRule(packageName = packageName))
        current[packageName] = next
        onAppRulesChanged(current.values.sortedBy { it.packageName })
    }

    fun bulkUpdate(transform: (AppRule) -> AppRule) {
        selected.value.forEach { pkg -> updateRule(pkg, transform) }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Application control", style = MaterialTheme.typography.titleMedium)
                    Button(onClick = { expanded.value = !expanded.value }) {
                        Text(if (expanded.value) "Collapse" else "Expand")
                    }
                    if (expanded.value) {
                        OutlinedTextField(
                            value = search.value,
                            onValueChange = { search.value = it },
                            label = { Text("Search installed apps") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { selected.value = filtered.map { it.packageName }.toSet() }) { Text("Select filtered") }
                            Button(onClick = { selected.value = emptySet() }) { Text("Clear") }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { bulkUpdate { it.copy(blocked = true, networkBlocked = true) } }) { Text("Bulk block") }
                            Button(onClick = { bulkUpdate { it.copy(suspended = true) } }) { Text("Bulk suspend") }
                            Button(onClick = { bulkUpdate { it.copy(blocked = false, suspended = false, networkBlocked = false) } }) { Text("Bulk allow") }
                        }

                        filtered.take(80).forEach { app ->
                            val rule = appRules.firstOrNull { it.packageName == app.packageName }
                            val isSelected = app.packageName in selected.value
                            ElevatedCard {
                                Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                        Column(Modifier.weight(1f)) {
                                            Text(app.label)
                                            Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                                        }
                                        Checkbox(
                                            checked = isSelected,
                                            onCheckedChange = { checked ->
                                                selected.value = if (checked) selected.value + app.packageName else selected.value - app.packageName
                                            }
                                        )
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        FilterChip(
                                            selected = rule?.blocked == true,
                                            onClick = { updateRule(app.packageName) { it.copy(blocked = !(it.blocked), networkBlocked = !(it.blocked)) } },
                                            label = { Text("Block") }
                                        )
                                        FilterChip(
                                            selected = rule?.suspended == true,
                                            onClick = { updateRule(app.packageName) { it.copy(suspended = !(it.suspended)) } },
                                            label = { Text("Suspend") }
                                        )
                                        FilterChip(
                                            selected = rule?.networkBlocked == true,
                                            onClick = { updateRule(app.packageName) { it.copy(networkBlocked = !(it.networkBlocked)) } },
                                            label = { Text("No network") }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("System restriction toggles", style = MaterialTheme.typography.titleMedium)
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
                    SwitchRow("Block developer options", restrictionPolicy.developerOptionsBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(developerOptionsBlocked = it))
                    }
                    SwitchRow("Block app installation", restrictionPolicy.appInstallBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(appInstallBlocked = it))
                    }
                    SwitchRow("Block safe boot", restrictionPolicy.safeBootBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(safeBootBlocked = it))
                    }
                    SwitchRow("Block adding accounts", restrictionPolicy.accountManagementBlocked) {
                        onRestrictionChanged(restrictionPolicy.copy(accountManagementBlocked = it))
                    }
                    Button(onClick = onApplyPolicies) { Text("Apply on device") }
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
