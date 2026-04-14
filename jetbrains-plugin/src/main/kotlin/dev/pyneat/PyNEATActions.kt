package dev.pyneat

import com.intellij.openapi.actionSystem.*
import com.intellij.openapi.project.*
import com.intellij.openapi.wm.*

class PyNEATPlugin : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        ToolWindowManager.getInstance(project)
            .getToolWindow("PyNEAT Security")
            ?.show()
    }
}

class ScanAction(private val action: () -> Unit) : AnAction("Scan File", "Run PyNEAT scan on current file", null) {
    override fun actionPerformed(e: AnActionEvent) = action()
}

class ScanWorkspaceAction(private val action: () -> Unit) : AnAction("Scan Workspace", "Run PyNEAT scan on entire workspace", null) {
    override fun actionPerformed(e: AnActionEvent) = action()
}

class ClearAction(private val action: () -> Unit) : AnAction("Clear", "Clear PyNEAT findings", null) {
    override fun actionPerformed(e: AnActionEvent) = action()
}

class FilterAction(private val action: () -> Unit) : AnAction("Filter", "Filter findings by severity", null) {
    override fun actionPerformed(e: AnActionEvent) = action()
}
