package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun DeviceControlScreen() {
    var expanded by remember { mutableStateOf(false) }
    var forceVpn by remember { mutableStateOf(false) }
    val sampleApps = listOf("com.chat.app", "com.video.app", "com.browser.app")

    LazyColumn(modifier = Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Application control", style = MaterialTheme.typography.titleMedium)
                    Button(onClick = { expanded = !expanded }) { Text(if (expanded) "Collapse" else "Expand") }
                    if (expanded) {
                        OutlinedTextField("", {}, label = { Text("Search apps") }, modifier = Modifier.fillMaxWidth())
                        sampleApps.forEach {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(it)
                                Row {
                                    TextButton(onClick = {}) { Text("Block") }
                                    TextButton(onClick = {}) { Text("Suspend") }
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
                    SwitchRow("Force VPN usage", forceVpn) { forceVpn = it }
                    SwitchRow("Block Wi-Fi", false) {}
                    SwitchRow("Block SMS", false) {}
                    SwitchRow("Block mobile data", false) {}
                    SwitchRow("Block device reset", true) {}
                    SwitchRow("Block network reset", true) {}
                    SwitchRow("Block app reset", false) {}
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Password management", style = MaterialTheme.typography.titleMedium)
                    Button(onClick = {}) { Text("Change password") }
                    Button(onClick = {}) { Text("Configure enforcement mode") }
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
