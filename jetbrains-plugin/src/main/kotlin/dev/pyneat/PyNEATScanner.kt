/*
 * Copyright (C) 2026 PyNEAT Authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package dev.pyneat

import com.intellij.openapi.project.Project
import com.intellij.openapi.application.ApplicationManager
import com.intellij.psi.search.FileTypeIndex
import com.intellij.psi.search.GlobalSearchScope
import com.intellij.openapi.roots.ProjectRootManager
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.fileEditor.FileEditorManager
import com.fasterxml.jackson.databind.JsonNode
import java.io.File
import java.util.concurrent.Executors

data class SecurityFinding(
    val ruleId: String,
    val severity: String,
    val line: Int,
    val column: Int,
    val file: String,
    val problem: String,
    val fixHint: String,
    val cweId: String?,
    val autoFixAvailable: Boolean = false
)

class PyNEATScanner(private val project: Project) {

    fun scanFile(filePath: String): List<SecurityFinding> {
        val results = mutableListOf<SecurityFinding>()

        try {
            val pyneatRs = findPyneatRs()
            if (pyneatRs != null) {
                val process = Runtime.getRuntime().exec(arrayOf(pyneatRs, "check", "--format", "sarif", filePath))
                val output = process.inputStream.bufferedReader().readText()
                return parseSarifOrJson(output, filePath)
            }

            val pythonPath = getPythonPath()
            val cmd = arrayOf(pythonPath, "-m", "pyneat.cli", "check", filePath, "--format", "sarif")
            val process = Runtime.getRuntime().exec(cmd)
            val output = process.inputStream.bufferedReader().readText()
            return parseSarifOrJson(output, filePath)
        } catch (e: Exception) {
            // Ignore
        }

        return results
    }

    fun scanWorkspace(project: Project): List<SecurityFinding> {
        val basePath = project.basePath ?: return emptyList()
        val results = mutableListOf<SecurityFinding>()

        val searcher = FileTypeIndex.getFiles(
            { true },
            GlobalSearchScope.projectScope(project)
        )

        val extensions = setOf("py", "js", "ts", "tsx", "go", "java", "rs", "cs", "php", "rb")

        for (virtualFile in searcher) {
            if (virtualFile.extension !in extensions) continue
            val path = virtualFile.path
            val fileFindings = scanFile(path)
            results.addAll(fileFindings)
        }

        return results
    }

    fun applyFix(finding: SecurityFinding): Boolean {
        if (!finding.autoFixAvailable) return false

        try {
            val pyneatRs = findPyneatRs() ?: return false
            val cmd = arrayOf(pyneatRs, "check", "--fix", finding.file)
            val process = Runtime.getRuntime().exec(cmd)
            process.waitFor()
            return process.exitValue() == 0
        } catch (e: Exception) {
            return false
        }
    }

    private fun parseSarifOrJson(output: String, filePath: String): List<SecurityFinding> {
        if (output.isBlank()) return emptyList()

        try {
            val mapper = com.fasterxml.jackson.databind.ObjectMapper()
            val tree = mapper.readTree(output)

            if (tree.has("version") && tree.has("runs")) {
                return parseSarif(tree, filePath)
            }

            if (tree.has("findings")) {
                return parseJsonResults(tree, filePath)
            }
        } catch (e: Exception) {
            // Fall through
        }
        return emptyList()
    }

    private fun parseSarif(tree: JsonNode, filePath: String): List<SecurityFinding> {
        val results = mutableListOf<SecurityFinding>()

        val runs = tree.get("runs") ?: return emptyList()
        for (run in runs) {
            val runResults = run.get("results") ?: continue
            for (result in runResults) {
                val ruleId = result.get("ruleId")?.asText() ?: continue
                val level = result.get("level")?.asText() ?: "warning"

                val locations = result.get("locations") ?: continue
                if (!locations.isArray || locations.size() == 0) continue

                val loc = locations[0]
                val physLoc = loc.get("physicalLocation") ?: continue
                val region = physLoc.get("region") ?: continue

                val file = physLoc.get("artifactLocation")?.get("uri")?.asText() ?: filePath
                val line = region.get("startLine")?.asInt() ?: 1
                val message = result.get("message")?.get("text")?.asText() ?: "Security issue"
                val props = result.get("properties")

                val cweId = props?.get("cwe_id")?.asText()
                val autoFix = props?.get("can_auto_fix")?.asBoolean() ?: false

                results.add(
                    SecurityFinding(
                        ruleId = ruleId.substringAfterLast("/").substringAfterLast("\\"),
                        severity = sarifLevelToSeverity(level),
                        line = line,
                        column = region.get("startColumn")?.asInt() ?: 1,
                        file = file,
                        problem = message,
                        fixHint = props?.get("fix_hint")?.asText() ?: "No auto-fix available",
                        cweId = cweId,
                        autoFixAvailable = autoFix
                    )
                )
            }
        }
        return results
    }

    private fun parseJsonResults(tree: JsonNode, filePath: String): List<SecurityFinding> {
        val results = mutableListOf<SecurityFinding>()
        val findings = tree.get("findings") ?: return emptyList()

        for (finding in findings) {
            results.add(
                SecurityFinding(
                    ruleId = finding.get("rule_id")?.asText() ?: "UNKNOWN",
                    severity = finding.get("severity")?.asText() ?: "info",
                    line = finding.get("line")?.asInt() ?: finding.get("start_line")?.asInt() ?: 1,
                    column = finding.get("column")?.asInt() ?: 1,
                    file = filePath,
                    problem = finding.get("problem")?.asText() ?: finding.get("message")?.asText() ?: "",
                    fixHint = finding.get("fix_hint")?.asText() ?: "",
                    cweId = finding.get("cwe_id")?.asText(),
                    autoFixAvailable = finding.get("can_auto_fix")?.asBoolean() ?: false
                )
            )
        }
        return results
    }

    private fun sarifLevelToSeverity(level: String): String {
        return when (level) {
            "error" -> "high"
            "warning" -> "medium"
            "note" -> "low"
            else -> "info"
        }
    }

    private fun findPyneatRs(): String? {
        val paths = listOf(
            "./target/release/pyneat",
            "./target/release/pyneat.exe",
            "./pyneat-rs/target/release/pyneat",
            "./pyneat-rs/target/release/pyneat.exe"
        )
        for (path in paths) {
            val file = File(path)
            if (file.exists() && file.canExecute()) {
                return path
            }
        }
        return null
    }

    private fun getPythonPath(): String {
        val sdkPath = ProjectRootManager.getInstance(project)
            .projectSdk
            ?.homeDirectory
            ?.path
        return if (sdkPath != null) "$sdkPath/bin/python" else "python"
    }
}
