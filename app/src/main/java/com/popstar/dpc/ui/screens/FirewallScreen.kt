package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun FirewallScreen() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Domain / URL blocking", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField("*.social.example", {}, label = { Text("Rule pattern") })
                    Button(onClick = {}) { Text("Add rule") }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("App network controls")
                    Text("Per-app and global prioritized rules are supported.")
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Live blocked attempts")
                    Text("12:00 blocked com.video.app -> ads.example")
                }
            }
        }
    }
}
