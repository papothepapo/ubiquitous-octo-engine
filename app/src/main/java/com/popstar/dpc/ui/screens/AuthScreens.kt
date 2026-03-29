package com.popstar.dpc.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.popstar.dpc.data.model.PasswordEnforcementMode

@Composable
fun SetupPasswordScreen(onCreate: (password: String, mode: PasswordEnforcementMode, days: Int) -> Unit) {
    val password = remember { mutableStateOf("") }
    val confirm = remember { mutableStateOf("") }
    val mode = remember { mutableStateOf(PasswordEnforcementMode.PERSISTENT) }
    val days = remember { mutableStateOf("7") }
    val error = remember { mutableStateOf<String?>(null) }

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        ElevatedCard {
            Column(
                Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Create administrator password", style = MaterialTheme.typography.headlineSmall)
                OutlinedTextField(password.value, { password.value = it }, visualTransformation = PasswordVisualTransformation(), label = { Text("Password") })
                OutlinedTextField(confirm.value, { confirm.value = it }, visualTransformation = PasswordVisualTransformation(), label = { Text("Confirm") })
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(selected = mode.value == PasswordEnforcementMode.PERSISTENT, onClick = { mode.value = PasswordEnforcementMode.PERSISTENT }, label = { Text("Persistent") })
                    FilterChip(selected = mode.value == PasswordEnforcementMode.TIMED, onClick = { mode.value = PasswordEnforcementMode.TIMED }, label = { Text("Timed") })
                    FilterChip(selected = mode.value == PasswordEnforcementMode.DISABLED, onClick = { mode.value = PasswordEnforcementMode.DISABLED }, label = { Text("Disabled") })
                }
                if (mode.value == PasswordEnforcementMode.TIMED) {
                    OutlinedTextField(days.value, { days.value = it }, label = { Text("Days") })
                }
                error.value?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(onClick = {
                    if (password.value.length < 8) {
                        error.value = "Password must be at least 8 chars"
                        return@Button
                    }
                    if (password.value != confirm.value) {
                        error.value = "Passwords do not match"
                        return@Button
                    }
                    onCreate(password.value, mode.value, days.value.toIntOrNull() ?: 0)
                }) { Text("Save") }
            }
        }
    }
}

@Composable
fun UnlockScreen(onUnlock: (String) -> Boolean) {
    val password = remember { mutableStateOf("") }
    val error = remember { mutableStateOf<String?>(null) }
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        ElevatedCard {
            Column(
                Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Enter administrator password", style = MaterialTheme.typography.headlineSmall)
                OutlinedTextField(password.value, { password.value = it }, visualTransformation = PasswordVisualTransformation(), label = { Text("Password") })
                error.value?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(onClick = {
                    val ok = onUnlock(password.value)
                    if (!ok) error.value = "Invalid password"
                }) { Text("Unlock") }
            }
        }
    }
}
