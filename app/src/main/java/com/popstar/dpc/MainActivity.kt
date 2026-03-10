package com.popstar.dpc

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.popstar.dpc.ui.screens.DeviceControlScreen
import com.popstar.dpc.ui.screens.FirewallScreen
import com.popstar.dpc.ui.screens.SettingsScreen
import com.popstar.dpc.ui.theme.PopstarTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            PopstarTheme {
                val navController = rememberNavController()
                val items = listOf("device", "firewall", "settings")
                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            val backstack by navController.currentBackStackEntryAsState()
                            items.forEach { route ->
                                NavigationBarItem(
                                    selected = backstack?.destination?.route == route,
                                    onClick = { navController.navigate(route) },
                                    label = { Text(route.replaceFirstChar { it.uppercase() }) },
                                    icon = {}
                                )
                            }
                        }
                    }
                ) { padding ->
                    NavHost(navController, startDestination = "device", modifier = Modifier.padding(padding)) {
                        composable("device") { DeviceControlScreen() }
                        composable("firewall") { FirewallScreen() }
                        composable("settings") { SettingsScreen() }
                    }
                }
            }
        }
    }
}
