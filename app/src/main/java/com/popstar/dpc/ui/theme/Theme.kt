package com.popstar.dpc.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.popstar.dpc.data.model.AppThemeMode

private val Purple = Color(0xFFB388FF)
private val LightScheme = lightColorScheme(
    primary = Purple,
    secondary = Color(0xFFD1C4E9),
    background = Color.White
)
private val DarkScheme = darkColorScheme(
    primary = Purple,
    secondary = Color(0xFF7E57C2)
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
