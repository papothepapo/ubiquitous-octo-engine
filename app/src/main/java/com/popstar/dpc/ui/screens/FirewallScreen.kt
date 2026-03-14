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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.FirewallRule

@Composable
fun FirewallScreen(
    rules: List<FirewallRule>,
    blockedEvents: List<String>,
    vpnStatus: String?,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
    onAddRule: (String) -> Unit
) {
    val pattern = remember { mutableStateOf("") }
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("VPN", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onStartVpn) { Text("Start local VPN") }
                        Button(onClick = onStopVpn) { Text("Stop local VPN") }
                    }
                    vpnStatus?.let { Text("VPN status: $it") }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Domain / URL blocking", style = MaterialTheme.typography.titleMedium)
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
                    Text("Blocked attempts", style = MaterialTheme.typography.titleMedium)
                    if (blockedEvents.isEmpty()) {
                        Text("No blocked traffic logged yet")
                    } else {
                        blockedEvents.take(20).forEach { Text(it) }
                    }
                }
            }
        }
    }
}
