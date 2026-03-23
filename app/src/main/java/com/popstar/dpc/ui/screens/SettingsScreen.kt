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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.AppThemeMode
import com.popstar.dpc.data.model.AuditLogEntry
import com.popstar.dpc.data.model.PasswordEnforcementMode
import java.text.DateFormat
import java.util.Date

@Composable
fun SettingsScreen(
    currentThemeMode: AppThemeMode,
    onThemeModeChanged: (AppThemeMode) -> Unit,
    deviceOwnerStatus: String,
    adbDeviceOwnerCommand: String,
    onCopyAdbCommand: () -> Unit,
    supportShortMessage: String,
    supportLongMessage: String,
    onSupportMessagesChanged: (String, String) -> Unit,
    onDisablePassword: () -> Unit,
    onSetPassword: (password: String, mode: PasswordEnforcementMode, days: Int) -> String?,
    importExportStatus: String?,
    enforcementStatus: String?,
    vpnAutoStart: Boolean,
    auditLogs: List<AuditLogEntry>,
    transferOwnerInstructions: String,
    onVpnAutoStartChanged: (Boolean) -> Unit,
    onExport: () -> Unit,
    onImport: () -> Unit,
    onRemoveAdminOwner: () -> Unit
) {
    val password = remember { mutableStateOf("") }
    val confirm = remember { mutableStateOf("") }
    val mode = remember { mutableStateOf(PasswordEnforcementMode.PERSISTENT) }
    val days = remember { mutableStateOf("7") }
    val passwordStatus = remember { mutableStateOf<String?>(null) }
    val shortMessageState = remember(supportShortMessage) { mutableStateOf(supportShortMessage) }
    val longMessageState = remember(supportLongMessage) { mutableStateOf(supportLongMessage) }
    var logsExpanded by remember { mutableStateOf(false) }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Theme")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(selected = currentThemeMode == AppThemeMode.SYSTEM, onClick = { onThemeModeChanged(AppThemeMode.SYSTEM) }, label = { Text("Auto") })
                        FilterChip(selected = currentThemeMode == AppThemeMode.LIGHT, onClick = { onThemeModeChanged(AppThemeMode.LIGHT) }, label = { Text("Light") })
                        FilterChip(selected = currentThemeMode == AppThemeMode.DARK, onClick = { onThemeModeChanged(AppThemeMode.DARK) }, label = { Text("Dark") })
                    }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Owner and admin")
                    Text(deviceOwnerStatus)
                    OutlinedTextField(
                        value = adbDeviceOwnerCommand,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("ADB command") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(transferOwnerInstructions)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onCopyAdbCommand) { Text("Copy command") }
                        Button(onClick = onRemoveAdminOwner) { Text("Remove admin / owner") }
                    }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Blocked-by-policy support messages")
                    OutlinedTextField(
                        value = shortMessageState.value,
                        onValueChange = { shortMessageState.value = it },
                        label = { Text("Short message") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = longMessageState.value,
                        onValueChange = { longMessageState.value = it },
                        label = { Text("Long message") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Button(onClick = { onSupportMessagesChanged(shortMessageState.value, longMessageState.value) }) {
                        Text("Save support messages")
                    }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Password")
                    OutlinedTextField(
                        value = password.value,
                        onValueChange = { password.value = it },
                        visualTransformation = PasswordVisualTransformation(),
                        label = { Text("New password") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = confirm.value,
                        onValueChange = { confirm.value = it },
                        visualTransformation = PasswordVisualTransformation(),
                        label = { Text("Confirm password") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(selected = mode.value == PasswordEnforcementMode.PERSISTENT, onClick = { mode.value = PasswordEnforcementMode.PERSISTENT }, label = { Text("Persistent") })
                        FilterChip(selected = mode.value == PasswordEnforcementMode.TIMED, onClick = { mode.value = PasswordEnforcementMode.TIMED }, label = { Text("Timed") })
                        FilterChip(selected = mode.value == PasswordEnforcementMode.DISABLED, onClick = { mode.value = PasswordEnforcementMode.DISABLED }, label = { Text("Disabled") })
                    }
                    if (mode.value == PasswordEnforcementMode.TIMED) {
                        OutlinedTextField(
                            value = days.value,
                            onValueChange = { days.value = it },
                            label = { Text("Days") }
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            if (mode.value != PasswordEnforcementMode.DISABLED && password.value.length < 8) {
                                passwordStatus.value = "Password must be at least 8 chars"
                                return@Button
                            }
                            if (mode.value != PasswordEnforcementMode.DISABLED && password.value != confirm.value) {
                                passwordStatus.value = "Passwords do not match"
                                return@Button
                            }
                            passwordStatus.value = onSetPassword(password.value, mode.value, days.value.toIntOrNull() ?: 0)
                        }) { Text("Save password policy") }
                        Button(onClick = {
                            password.value = ""
                            confirm.value = ""
                            passwordStatus.value = "Password disabled"
                            onDisablePassword()
                        }) { Text("Disable password") }
                    }
                    passwordStatus.value?.let { Text(it) }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("App startup")
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Auto start VPN on app startup")
                        Switch(checked = vpnAutoStart, onCheckedChange = onVpnAutoStartChanged)
                    }
                    enforcementStatus?.let { Text("Policy apply status: $it") }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Policy backup and restore")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onExport) { Text("Export encrypted policy") }
                        Button(onClick = onImport) { Text("Import encrypted policy") }
                    }
                    importExportStatus?.let { Text(it) }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Column(Modifier.weight(1f)) {
                            Text("Open log")
                            Text("This log is append-only in the UI and cannot be deleted.")
                        }
                        Button(onClick = { logsExpanded = !logsExpanded }) {
                            Text(if (logsExpanded) "Collapse" else "Expand")
                        }
                    }
                    if (logsExpanded) {
                        auditLogs.takeLast(25).asReversed().forEach { log ->
                            Text("${DateFormat.getDateTimeInstance().format(Date(log.timestamp))}: ${log.action} — ${log.details}")
                        }
                    }
                }
            }
        }
    }
}
