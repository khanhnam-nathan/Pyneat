package com.pyneat.actions

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.command.CommandProcessor
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.ui.Messages
import com.pyneat.services.PyneatProcessService
import com.pyneat.services.PyneatResultService
import java.io.File

/**
 * Action to analyze a Python file with PyNEAT.
 *
 * This action is triggered when the user selects "PyNEAT: Check"
 * from the context menu or keyboard shortcut.
 */
class PyneatAnalyzeAction : AnAction() {

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val virtualFile = event.getData(CommonDataKeys.VIRTUAL_FILE) ?: return

        if (!virtualFile.isPythonFile()) {
            Messages.showInfoMessage(
                "PyNEAT only works with Python files (.py)",
                "PyNEAT"
            )
            return
        }

        // Save the file first
        FileDocumentManager.getInstance().saveDocument(
            event.getData(CommonDataKeys.DOCUMENT)
        )

        // Run PyNEAT analysis
        ProgressManager.getInstance().run(object : Task.Backgroundable(
            project,
            "PyNEAT Analysis",
            true
        ) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                indicator.text = "Running PyNEAT security scan..."

                val processService = PyneatProcessService.getInstance()
                val result = processService.analyze(virtualFile.path)

                // Display results
                ApplicationManager.getApplication().invokeLater {
                    val resultService = PyneatResultService.getInstance(project)
                    resultService.displayResults(result)
                }
            }
        })
    }

    private fun com.intellij.openapi.vfs.VirtualFile.isPythonFile(): Boolean {
        return extension == "py" || name.endsWith(".py")
    }
}

/**
 * Action to clean a Python file with PyNEAT.
 */
class PyneatCleanAction : AnAction() {

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val virtualFile = event.getData(CommonDataKeys.VIRTUAL_FILE) ?: return

        if (!virtualFile.isPythonFile()) {
            Messages.showInfoMessage(
                "PyNEAT only works with Python files (.py)",
                "PyNEAT"
            )
            return
        }

        // Confirm before modifying
        val result = Messages.showYesNoDialog(
            project,
            "This will modify the file. Continue?",
            "PyNEAT Clean",
            "Clean", "Cancel",
            Messages.getQuestionIcon()
        )

        if (result != Messages.YES) return

        // Save and clean
        FileDocumentManager.getInstance().saveDocument(
            event.getData(CommonDataKeys.DOCUMENT)
        )

        ProgressManager.getInstance().run(object : Task.Backgroundable(
            project,
            "PyNEAT Clean",
            true
        ) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                indicator.text = "Running PyNEAT auto-fix..."

                val processService = PyneatProcessService.getInstance()
                val result = processService.clean(virtualFile.path)

                ApplicationManager.getApplication().invokeLater {
                    if (result.success) {
                        // Reload the file
                        virtualFile.refresh(false, true)
                        Messages.showInfoMessage(
                            "PyNEAT cleaned ${result.issuesFixed} issues",
                            "PyNEAT"
                        )
                    } else {
                        Messages.showErrorDialog(
                            "PyNEAT failed: ${result.error}",
                            "PyNEAT Error"
                        )
                    }
                }
            }
        })
    }

    private fun com.intellij.openapi.vfs.VirtualFile.isPythonFile(): Boolean {
        return extension == "py" || name.endsWith(".py")
    }
}

/**
 * Action to export PyNEAT manifest for AI editors.
 */
class PyneatExportManifestAction : AnAction() {

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val virtualFile = event.getData(CommonDataKeys.VIRTUAL_FILE) ?: return

        if (!virtualFile.isPythonFile()) {
            Messages.showInfoMessage(
                "PyNEAT only works with Python files (.py)",
                "PyNEAT"
            )
            return
        }

        ProgressManager.getInstance().run(object : Task.Backgroundable(
            project,
            "PyNEAT Manifest Export",
            true
        ) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                indicator.text = "Exporting PYNAGENT manifest..."

                val processService = PyneatProcessService.getInstance()
                val manifestPath = processService.exportManifest(virtualFile.path)

                ApplicationManager.getApplication().invokeLater {
                    if (manifestPath != null) {
                        Messages.showInfoMessage(
                            "Manifest exported to:\n$manifestPath",
                            "PyNEAT"
                        )
                    } else {
                        Messages.showWarningDialog(
                            "No manifest generated (no issues found)",
                            "PyNEAT"
                        )
                    }
                }
            }
        })
    }

    private fun com.intellij.openapi.vfs.VirtualFile.isPythonFile(): Boolean {
        return extension == "py" || name.endsWith(".py")
    }
}
