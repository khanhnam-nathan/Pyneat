package com.pyneat

import com.intellij.openapi.components.ProjectComponent
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.openapi.wm.ToolWindowManager
import com.intellij.ui.content.ContentFactory

/**
 * Project-level component for PyNEAT.
 *
 * This component is initialized when a project is opened and stays active
 * for the entire project session.
 */
class PyneatProjectComponent(private val project: Project) : ProjectComponent {

    override fun initComponent() {
        // Initialize project-specific PyNEAT state
    }

    override fun disposeComponent() {
        // Cleanup project resources
    }

    override fun projectOpened() {
        // Called when the project is opened
        // Register PyNEAT tool window
        registerToolWindow()
    }

    override fun projectClosed() {
        // Called when the project is closed
    }

    override fun getComponentName(): String = "PyneatProjectComponent"

    private fun registerToolWindow() {
        val toolWindowManager = ToolWindowManager.getInstance(project)
        val toolWindow = toolWindowManager.getToolWindow("PyNEAT")

        if (toolWindow == null) {
            // Register a new tool window
            // This would show PyNEAT results
        }
    }
}

/**
 * Tool window factory for PyNEAT results.
 */
class PyneatToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val contentFactory = ContentFactory.SERVICE.getInstance()
        // Create content for the PyNEAT tool window
    }

    override fun shouldBeAvailable(project: Project): Boolean = true
}
