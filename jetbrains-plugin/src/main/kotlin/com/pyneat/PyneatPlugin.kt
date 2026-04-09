package com.pyneat

import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.StartupActivity
import com.pyneat.services.PyneatLspService
import com.pyneat.services.PyneatConfigService

/**
 * Main entry point for the PyNEAT plugin.
 *
 * This class is called when the IDE starts up and initializes
 * the PyNEAT services.
 */
class PyneatPlugin : StartupActivity {

    override fun runActivity(project: Project) {
        // Initialize PyNEAT services
        PyneatConfigService.getInstance(project)
        PyneatLspService.getInstance(project)

        // Register PyNEAT as a language server for Python
        registerLanguageServer(project)
    }

    private fun registerLanguageServer(project: Project) {
        // Register PyNEAT LSP with the IDE's LSP framework
        // This enables real-time diagnostics as the user types
    }
}

/**
 * Constants used throughout the plugin.
 */
object PyneatConstants {
    const val PLUGIN_ID = "com.pyneat"
    const val PLUGIN_NAME = "PyNEAT"
    const val PLUGIN_VERSION = "2.2.0"

    // Service names
    const val LSP_SERVICE = "PyneatLspService"
    const val CONFIG_SERVICE = "PyneatConfigService"

    // Configuration keys
    const val ENABLE_SECURITY = "pyneat.enable.security"
    const val ENABLE_AI_BUGS = "pyneat.enable.ai_bugs"
    const val ENABLE_AUTO_FIX = "pyneat.enable.auto_fix"
    const val EXPORT_FORMAT = "pyneat.export.format"

    // Default values
    const val DEFAULT_FORMAT = "json"
}
