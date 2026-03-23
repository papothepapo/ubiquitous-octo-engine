package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.AppRule
import com.popstar.dpc.data.model.RestrictionPolicy
import com.popstar.dpc.data.policy.DeviceAdminEntry

/** Installed app metadata for app-control UI. */
data class InstalledAppInfo(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean = false,
    val isVpnCapable: Boolean = false
)

@Composable
fun DeviceControlScreen(
    restrictionPolicy: RestrictionPolicy,
    installedApps: List<InstalledAppInfo>,
    appRules: List<AppRule>,
    deviceAdmins: List<DeviceAdminEntry>,
    onAppRulesChanged: (List<AppRule>) -> Unit,
    onRestrictionChanged: (RestrictionPolicy) -> Unit,
    onAppAction: (String) -> Unit,
    onRestrictionAction: (String) -> Unit,
    onApplyPolicies: () -> Unit,
    onRemoveAdmin: (DeviceAdminEntry) -> Unit,
    onOpenAdminSettings: (DeviceAdminEntry) -> Unit
) {
    val appExpanded = remember { mutableStateOf(false) }
    val restrictionExpanded = remember { mutableStateOf(false) }
    val adminExpanded = remember { mutableStateOf(false) }
    val search = remember { mutableStateOf("") }
    val selected = remember { mutableStateOf(setOf<String>()) }
    var customRestrictions by remember(restrictionPolicy.customRestrictions) {
        mutableStateOf(restrictionPolicy.customRestrictions.joinToString("\n"))
    }

    val availableByPackage = installedApps.associateBy { it.packageName }
    val combinedApps = (installedApps + appRules.filter { it.packageName !in availableByPackage }.map {
        InstalledAppInfo(packageName = it.packageName, label = it.packageName)
    }).distinctBy { it.packageName }

    val filtered = combinedApps.filter {
        it.label.contains(search.value, ignoreCase = true) || it.packageName.contains(search.value, ignoreCase = true)
    }

    fun updateRule(packageName: String, transform: (AppRule) -> AppRule) {
        val current = appRules.associateBy { it.packageName }.toMutableMap()
        val next = transform(current[packageName] ?: AppRule(packageName = packageName))
        current[packageName] = next
        onAppRulesChanged(current.values.sortedBy { it.packageName })
    }

    fun bulkUpdate(transform: (AppRule) -> AppRule, message: String) {
        selected.value.forEach { pkg -> updateRule(pkg, transform) }
        onAppAction(message)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ExpandableSectionCard(
                title = "Application control",
                expanded = appExpanded.value,
                subtitle = "Changes only apply after you press Apply changes.",
                onToggle = { appExpanded.value = !appExpanded.value }
            ) {
                OutlinedTextField(
                    value = search.value,
                    onValueChange = { search.value = it },
                    label = { Text("Search installed, blocked, and system apps") },
                    modifier = Modifier.fillMaxWidth()
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { selected.value = filtered.map { it.packageName }.toSet() }) { Text("Select filtered") }
                    Button(onClick = { selected.value = emptySet() }) { Text("Clear") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { bulkUpdate({ it.copy(blocked = true, networkBlocked = true) }, "Apps marked as blocked. Press Apply changes to enforce.") }) { Text("Bulk block") }
                    Button(onClick = { bulkUpdate({ it.copy(suspended = true) }, "Apps marked as suspended. Press Apply changes to enforce.") }) { Text("Bulk suspend") }
                    Button(onClick = { bulkUpdate({ it.copy(blocked = false, suspended = false, networkBlocked = false) }, "Apps marked as allowed. Press Apply changes to enforce.") }) { Text("Bulk allow") }
                }

                Text("${filtered.size} apps shown")
            }
        }
        if (appExpanded.value) {
            items(filtered, key = { it.packageName }) { app ->
                val rule = appRules.firstOrNull { it.packageName == app.packageName }
                val isSelected = app.packageName in selected.value
                ElevatedCard {
                    Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.weight(1f)) {
                                Text(app.label)
                                Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                                if (app.isSystemApp) Text("System app", style = MaterialTheme.typography.bodySmall)
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
                                onClick = {
                                    updateRule(app.packageName) { it.copy(blocked = !it.blocked, networkBlocked = !it.blocked) }
                                    onAppAction("${app.label} updated. Press Apply changes to enforce blocking.")
                                },
                                label = { Text("Block") }
                            )
                            FilterChip(
                                selected = rule?.suspended == true,
                                onClick = {
                                    updateRule(app.packageName) { it.copy(suspended = !it.suspended) }
                                    onAppAction("${app.label} updated. Press Apply changes to enforce suspension.")
                                },
                                label = { Text("Suspend") }
                            )
                            FilterChip(
                                selected = rule?.networkBlocked == true,
                                onClick = {
                                    updateRule(app.packageName) { it.copy(networkBlocked = !it.networkBlocked) }
                                    onAppAction("${app.label} network rule updated. Press Apply changes to enforce it.")
                                },
                                label = { Text("No network") }
                            )
                        }
                    }
                }
            }
        }

        item {
            ExpandableSectionCard(
                title = "Device admins",
                expanded = adminExpanded.value,
                subtitle = "Review active device admin apps and remove this app directly or open system settings for others.",
                onToggle = { adminExpanded.value = !adminExpanded.value }
            ) {
                if (deviceAdmins.isEmpty()) {
                    Text("No active device admin apps found")
                } else {
                    deviceAdmins.forEach { entry ->
                        ElevatedCard {
                            Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(entry.label)
                                Text(entry.packageName, style = MaterialTheme.typography.bodySmall)
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Button(onClick = { onRemoveAdmin(entry) }) {
                                        Text(if (entry.isThisApp) "Remove here" else "Review removal")
                                    }
                                    if (!entry.isThisApp) {
                                        Button(onClick = { onOpenAdminSettings(entry) }) { Text("Open admin settings") }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        item {
            ExpandableSectionCard(
                title = "System restrictions",
                expanded = restrictionExpanded.value,
                subtitle = "Changes only apply after you press Apply changes.",
                onToggle = { restrictionExpanded.value = !restrictionExpanded.value }
            ) {
                SwitchRow("Block Wi‑Fi", restrictionPolicy.wifiBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(wifiBlocked = it))
                    onRestrictionAction("Wi‑Fi restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block SMS", restrictionPolicy.smsBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(smsBlocked = it))
                    onRestrictionAction("SMS restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block mobile data", restrictionPolicy.mobileDataBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(mobileDataBlocked = it))
                    onRestrictionAction("Mobile data restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block device reset", restrictionPolicy.deviceResetBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(deviceResetBlocked = it))
                    onRestrictionAction("Device reset restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block network reset", restrictionPolicy.networkResetBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(networkResetBlocked = it))
                    onRestrictionAction("Network reset restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block app reset", restrictionPolicy.appResetBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(appResetBlocked = it))
                    onRestrictionAction("App reset restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block developer options", restrictionPolicy.developerOptionsBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(developerOptionsBlocked = it))
                    onRestrictionAction("Developer options restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block app installation", restrictionPolicy.appInstallBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(appInstallBlocked = it))
                    onRestrictionAction("App installation restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block safe boot", restrictionPolicy.safeBootBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(safeBootBlocked = it))
                    onRestrictionAction("Safe boot restriction updated. Press Apply changes to enforce.")
                }
                SwitchRow("Block adding accounts", restrictionPolicy.accountManagementBlocked) {
                    onRestrictionChanged(restrictionPolicy.copy(accountManagementBlocked = it))
                    onRestrictionAction("Account restriction updated. Press Apply changes to enforce.")
                }
                OutlinedTextField(
                    value = customRestrictions,
                    onValueChange = {
                        customRestrictions = it
                        onRestrictionChanged(
                            restrictionPolicy.copy(
                                customRestrictions = it.lines().map(String::trim).filter(String::isNotBlank)
                            )
                        )
                    },
                    label = { Text("Custom restriction keys (one per line)") },
                    modifier = Modifier.fillMaxWidth()
                )
                Text("Custom restrictions are applied exactly as entered when you press Apply changes.")
                Button(onClick = onApplyPolicies) { Text("Apply changes") }
            }
        }
    }
}

@Composable
private fun ExpandableSectionCard(
    title: String,
    expanded: Boolean,
    subtitle: String,
    onToggle: () -> Unit,
    content: @Composable () -> Unit
) {
    ElevatedCard {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleMedium)
                    Text(subtitle, style = MaterialTheme.typography.bodySmall)
                }
                Button(onClick = onToggle) {
                    Text(if (expanded) "Collapse" else "Expand")
                }
            }
            if (expanded) content()
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
