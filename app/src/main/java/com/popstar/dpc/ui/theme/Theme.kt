package com.popstar.dpc.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

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
fun PopstarTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkScheme else LightScheme,
        content = content
    )
}
