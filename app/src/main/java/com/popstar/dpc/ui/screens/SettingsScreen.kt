package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun SettingsScreen(onDisablePassword: () -> Unit) {
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
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Password")
                    Button(onClick = onDisablePassword) { Text("Disable password") }
                }
            }
        }
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("Policy backup and restore")
                    Text("Encrypted import/export wiring remains in-progress.")
                }
            }
        }
    }
}
