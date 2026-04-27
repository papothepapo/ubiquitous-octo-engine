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
import com.popstar.dpc.data.firewall.FirewallRuleEngine
import com.popstar.dpc.data.model.FirewallRule
import com.popstar.dpc.data.model.FirewallRuleType
import com.popstar.dpc.data.model.VpnLockdownConfig
import com.popstar.dpc.data.model.VpnLogEntry
import java.text.DateFormat
import java.util.Date

@Composable
fun FirewallScreen(
    rules: List<FirewallRule>,
    blockedEvents: List<VpnLogEntry>,
    vpnStatus: String?,
    vpnLockdown: VpnLockdownConfig,
    installedApps: List<InstalledAppInfo>,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit,
    onSaveRule: (FirewallRule) -> Unit,
    onDeleteRule: (String) -> Unit,
    onClearLogs: () -> Unit,
    onVpnLockdownChanged: (Boolean, String?) -> Unit
) {
    val ruleEngine = remember { FirewallRuleEngine() }
    val availableVpnApps = remember(installedApps) { installedApps.filter { it.isVpnCapable } }
    var logFilter by remember { mutableStateOf("All") }
    var pattern by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf(FirewallRuleType.DOMAIN) }
    var blockRule by remember { mutableStateOf(true) }
    var appScope by remember { mutableStateOf("") }
    var enabledRule by remember { mutableStateOf(true) }
    var editingRuleId by remember { mutableStateOf<String?>(null) }
    var ruleError by remember { mutableStateOf<String?>(null) }
    val editingRule = editingRuleId?.let { id -> rules.firstOrNull { it.id == id } }

    fun resetEditor() {
        editingRuleId = null
        pattern = ""
        selectedType = FirewallRuleType.DOMAIN
        blockRule = true
        appScope = ""
        enabledRule = true
        ruleError = null
    }

    fun loadRule(rule: FirewallRule) {
        editingRuleId = rule.id
        pattern = rule.pattern
        selectedType = rule.type
        blockRule = rule.block
        appScope = rule.appPackage.orEmpty()
        enabledRule = rule.enabled
        ruleError = null
    }

    fun saveRule() {
        val trimmedPattern = pattern.trim()
        if (!ruleEngine.isValidPattern(selectedType, trimmedPattern)) {
            ruleError = if (selectedType == FirewallRuleType.IP) {
                "Enter a valid IPv4 address or CIDR, excluding 0.0.0.0/0"
            } else {
                "Enter a valid domain, wildcard, or URL"
            }
            return
        }

        val nextRule = FirewallRule(
            id = editingRule?.id ?: System.currentTimeMillis().toString(),
            pattern = trimmedPattern,
            appPackage = appScope.trim().ifBlank { null },
            block = blockRule,
            priority = editingRule?.priority ?: ((rules.maxOfOrNull { it.priority } ?: 0) + 1),
            type = selectedType,
            enabled = enabledRule
        )
        onSaveRule(nextRule)
        resetEditor()
    }

    val visibleEvents = remember(blockedEvents, logFilter) {
        blockedEvents.filter { event ->
            when (logFilter) {
                "Blocked" -> event.action == "BLOCK"
                "Allowed" -> event.action == "ALLOW"
                "Apps" -> event.appPackage != null
                "Domains" -> event.site != null
                "IP" -> event.destIp != null
                else -> true
            }
        }
    }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("VPN firewall", style = MaterialTheme.typography.titleLarge)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatText("Rules", rules.count { it.enabled }.toString(), Modifier.weight(1f))
                        StatText("Blocked", blockedEvents.count { it.action == "BLOCK" }.toString(), Modifier.weight(1f))
                        StatText("Allowed", blockedEvents.count { it.action == "ALLOW" }.toString(), Modifier.weight(1f))
                    }
                    vpnStatus?.let { Text("Status: $it") }
                    Text("Targeted IP routing only auto-routes global IP block rules. App-scoped IP rules apply when matching traffic is already captured by the VPN.")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onStartVpn) { Text("Start / refresh") }
                        Button(onClick = onStopVpn) { Text("Stop") }
                        Button(onClick = onClearLogs) { Text("Clear logs") }
                    }
                }
            }
        }

        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Lockdown", style = MaterialTheme.typography.titleMedium)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Always-on VPN lockdown")
                        Switch(
                            checked = vpnLockdown.enabled,
                            onCheckedChange = { onVpnLockdownChanged(it, vpnLockdown.selectedVpnPackage) }
                        )
                    }
                    OutlinedTextField(
                        value = vpnLockdown.selectedVpnPackage.orEmpty(),
                        onValueChange = { onVpnLockdownChanged(vpnLockdown.enabled, it.ifBlank { null }) },
                        label = { Text("VPN package") },
                        supportingText = { Text("Detected VPN apps: ${availableVpnApps.joinToString { it.packageName }.ifBlank { "none" }}") },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(if (editingRule == null) "Add blocking rule" else "Edit rule", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(selected = selectedType == FirewallRuleType.DOMAIN, onClick = { selectedType = FirewallRuleType.DOMAIN }, label = { Text("Domain") })
                        FilterChip(selected = selectedType == FirewallRuleType.IP, onClick = { selectedType = FirewallRuleType.IP }, label = { Text("IP / CIDR") })
                    }
                    OutlinedTextField(
                        value = pattern,
                        onValueChange = { pattern = it; ruleError = null },
                        label = { Text(if (selectedType == FirewallRuleType.IP) "IPv4 or CIDR" else "Domain, wildcard, or URL") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = appScope,
                        onValueChange = { appScope = it },
                        label = { Text("App package (optional)") },
                        supportingText = { Text("Example: ${installedApps.firstOrNull()?.packageName ?: "com.example.app"}") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(selected = blockRule, onClick = { blockRule = true }, label = { Text("Block") })
                        FilterChip(selected = !blockRule, onClick = { blockRule = false }, label = { Text("Allow") })
                        FilterChip(selected = enabledRule, onClick = { enabledRule = !enabledRule }, label = { Text(if (enabledRule) "Enabled" else "Disabled") })
                    }
                    ruleError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = ::saveRule) { Text(if (editingRule == null) "Add rule" else "Save rule") }
                        if (editingRule != null) {
                            Button(onClick = ::resetEditor) { Text("Cancel") }
                        }
                    }
                }
            }
        }

        item {
            Text("Rules", style = MaterialTheme.typography.titleMedium)
        }
        if (rules.isEmpty()) {
            item { Text("No rules yet") }
        } else {
            items(rules.sortedBy { it.priority }, key = { it.id }) { rule ->
                ElevatedCard {
                    Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Column(Modifier.weight(1f)) {
                                Text(rule.pattern, style = MaterialTheme.typography.titleMedium)
                                Text("${rule.type.name.lowercase()} - ${if (rule.block) "block" else "allow"} - ${rule.appPackage ?: "all apps"}")
                                Text(if (rule.enabled) "Enabled" else "Disabled", style = MaterialTheme.typography.bodySmall)
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = { loadRule(rule) }) { Text("Edit") }
                                Button(onClick = { onDeleteRule(rule.id) }) { Text("Delete") }
                            }
                        }
                    }
                }
            }
        }

        item {
            ElevatedCard {
                Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Traffic log", style = MaterialTheme.typography.titleMedium)
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        listOf(
                            listOf("All", "Blocked", "Allowed"),
                            listOf("Apps", "Domains", "IP")
                        ).forEach { row ->
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                row.forEach { filter ->
                                    FilterChip(selected = logFilter == filter, onClick = { logFilter = filter }, label = { Text(filter) })
                                }
                            }
                        }
                    }
                    LogSummary("By app", blockedEvents.mapNotNull { it.appPackage })
                    LogSummary("By domain", blockedEvents.mapNotNull { it.site })
                    LogSummary("By IP", blockedEvents.mapNotNull { it.destIp })
                }
            }
        }

        if (visibleEvents.isEmpty()) {
            item { Text("No matching traffic yet") }
        } else {
            items(visibleEvents.take(50), key = { "${it.timestamp}-${it.category}-${it.destIp}-${it.site}" }) { event ->
                ElevatedCard {
                    Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("${event.action} ${event.category}", style = MaterialTheme.typography.titleMedium)
                        Text(eventDestination(event))
                        Text("App: ${event.appPackage ?: "Unknown"}")
                        event.rulePattern?.let { Text("Rule: $it") }
                        Text(DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(Date(event.timestamp)), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun StatText(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier = modifier) {
        Text(value, style = MaterialTheme.typography.titleLarge)
        Text(label, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun LogSummary(label: String, values: List<String>) {
    val summary = values.groupingBy { it }.eachCount()
        .entries
        .sortedByDescending { it.value }
        .take(3)
        .joinToString { "${it.key} (${it.value})" }
    Text("$label: ${summary.ifBlank { "none" }}")
}

private fun eventDestination(event: VpnLogEntry): String {
    val target = event.site ?: event.destIp ?: "Unknown destination"
    val port = event.destPort?.let { ":$it" }.orEmpty()
    val protocol = event.protocol?.let { "$it " }.orEmpty()
    return "$protocol$target$port - ${event.details}"
}
