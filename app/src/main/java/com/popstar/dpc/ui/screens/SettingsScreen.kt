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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.PasswordEnforcementMode

@Composable
fun SettingsScreen(
    onDisablePassword: () -> Unit,
    onSetPassword: (password: String, mode: PasswordEnforcementMode, days: Int) -> String?,
    importExportStatus: String?,
    enforcementStatus: String?,
    onExport: () -> Unit,
    onImport: () -> Unit,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit
) {
    val password = remember { mutableStateOf("") }
    val confirm = remember { mutableStateOf("") }
    val mode = remember { mutableStateOf(PasswordEnforcementMode.PERSISTENT) }
    val days = remember { mutableStateOf("7") }
    val passwordStatus = remember { mutableStateOf<String?>(null) }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Theme")
                    Text("Light / Dark / Auto")
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
                        Button(onClick = onDisablePassword) { Text("Disable password") }
                    }
                    passwordStatus.value?.let { Text(it) }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("VPN / Firewall")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onStartVpn) { Text("Start local VPN") }
                        Button(onClick = onStopVpn) { Text("Stop local VPN") }
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
    }
}
