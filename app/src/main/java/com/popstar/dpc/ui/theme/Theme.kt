package com.popstar.dpc.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.popstar.dpc.data.model.AppThemeMode

private val LightScheme = lightColorScheme(
    primary = Color(0xFF115E67),
    onPrimary = Color.White,
    secondary = Color(0xFF4B5F8C),
    tertiary = Color(0xFF8A5A17),
    background = Color(0xFFF7F9FB),
    surface = Color.White,
    surfaceVariant = Color(0xFFE3E8EF)
)
private val DarkScheme = darkColorScheme(
    primary = Color(0xFF65D6E2),
    secondary = Color(0xFFB9C7F4),
    tertiary = Color(0xFFFFC46B),
    background = Color(0xFF101418),
    surface = Color(0xFF171C22),
    surfaceVariant = Color(0xFF303842)
)

@Composable
fun PopstarTheme(
    themeMode: AppThemeMode,
    content: @Composable () -> Unit
) {
    val useDark = when (themeMode) {
        AppThemeMode.SYSTEM -> isSystemInDarkTheme()
        AppThemeMode.LIGHT -> false
        AppThemeMode.DARK -> true
    }

    MaterialTheme(
        colorScheme = if (useDark) DarkScheme else LightScheme,
        content = content
    )
}
