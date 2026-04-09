package com.pyneat.services

import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.project.Project
import com.intellij.util.xmlb.XmlSerializerUtil

/**
 * Service for managing PyNEAT configuration.
 *
 * Stores user preferences for PyNEAT plugin behavior.
 */
@State(
    name = "PyneatConfigState",
    storages = [Storage("pyneat-config.xml")]
)
class PyneatConfigService(private val project: Project) {

    // Configuration state
    var enableSecurity: Boolean = true
    var enableAiBugs: Boolean = true
    var enableAutoFix: Boolean = true
    var enableConservative: Boolean = false
    var enableDestructive: Boolean = false
    var exportFormat: String = "json"
    var maxLineLength: Int = 120
    var showOnSave: Boolean = false

    companion object {
        fun getInstance(project: Project): PyneatConfigService {
            return project.getService(PyneatConfigService::class.java)
        }
    }

    fun getConfigAsArgs(): List<String> {
        val args = mutableListOf<String>()

        if (enableSecurity) args.add("--enable-security")
        if (enableAiBugs) args.add("--enable-ai-bugs")
        if (enableConservative) args.add("--conservative")
        if (enableDestructive) args.add("--destructive")

        return args
    }
}

/**
 * Service for running PyNEAT as a subprocess.
 *
 * This service spawns a Python process to run PyNEAT commands.
 */
class PyneatProcessService {

    private var process: Process? = null

    companion object {
        private var instance: PyneatProcessService? = null

        fun getInstance(): PyneatProcessService {
            if (instance == null) {
                instance = PyneatProcessService()
            }
            return instance!!
        }
    }

    fun analyze(filePath: String): PyneatResult {
        return runPyneatCommand(listOf("check", filePath))
    }

    fun clean(filePath: String): PyneatResult {
        return runPyneatCommand(listOf("clean", filePath))
    }

    fun exportManifest(filePath: String): String? {
        val result = runPyneatCommand(listOf("manifest", filePath, "--format", "json"))
        return if (result.success) result.output else null
    }

    private fun runPyneatCommand(args: List<String>): PyneatResult {
        try {
            val python = findPythonExecutable()
            val pyneatArgs = listOf("-m", "pyneat.cli") + args

            val processBuilder = ProcessBuilder(python, *pyneatArgs.toTypedArray())
            processBuilder.redirectErrorStream(true)

            val process = processBuilder.start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()

            return PyneatResult(
                success = exitCode == 0,
                output = output,
                error = if (exitCode != 0) output else null,
                issuesFixed = parseIssuesFixed(output)
            )
        } catch (e: Exception) {
            return PyneatResult(
                success = false,
                output = null,
                error = e.message,
                issuesFixed = 0
            )
        }
    }

    private fun findPythonExecutable(): String {
        // Try to find Python in common locations
        val paths = listOf(
            "python",
            "python3",
            "C:\\Python312\\python.exe",
            "C:\\Python311\\python.exe",
            "/usr/bin/python3"
        )

        for (path in paths) {
            try {
                val process = ProcessBuilder(path, "--version").start()
                if (process.waitFor() == 0) {
                    return path
                }
            } catch (e: Exception) {
                // Try next path
            }
        }

        return "python" // Default fallback
    }

    private fun parseIssuesFixed(output: String): Int {
        // Parse the output to find "N issues fixed"
        val regex = Regex("(\\d+) issues?")
        val match = regex.find(output)
        return match?.groupValues?.getOrNull(1)?.toIntOrNull() ?: 0
    }
}

/**
 * Result from a PyNEAT command execution.
 */
data class PyneatResult(
    val success: Boolean,
    val output: String?,
    val error: String?,
    val issuesFixed: Int
)

/**
 * Service for displaying PyNEAT results in the IDE.
 */
class PyneatResultService(private val project: Project) {

    companion object {
        fun getInstance(project: Project): PyneatResultService {
            return project.getService(PyneatResultService::class.java)
        }
    }

    fun displayResults(result: PyneatResult) {
        if (result.success) {
            // Display success message with results
            com.intellij.openapi.ui.Messages.showInfoMessage(
                result.output ?: "Analysis complete",
                "PyNEAT Results"
            )
        } else {
            // Display error
            com.intellij.openapi.ui.Messages.showErrorDialog(
                result.error ?: "Unknown error",
                "PyNEAT Error"
            )
        }
    }
}

/**
 * Service for PyNEAT LSP integration.
 */
class PyneatLspService(private val project: Project) {

    companion object {
        fun getInstance(project: Project): PyneatLspService {
            return project.getService(PyneatLspService::class.java)
        }
    }

    // LSP integration would go here
    // This connects PyNEAT to the IDE's LSP framework
}
