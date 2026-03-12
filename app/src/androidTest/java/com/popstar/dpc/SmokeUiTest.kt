package com.popstar.dpc

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.assertExists
import org.junit.Rule
import org.junit.Test

class SmokeUiTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    @Test
    fun bottomNavItemsExist() {
        composeRule.onNodeWithText("Device").assertExists()
        composeRule.onNodeWithText("Firewall").assertExists()
        composeRule.onNodeWithText("Settings").assertExists()
    }
}
