package dev.pyneat

import com.intellij.openapi.wm.*
import com.intellij.ui.*

class PyNEATToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val contentManager = toolWindow.contentManager
        val component = PyNEATToolWindowContent(project)
        val content = contentManager.factory.createContent(component, "PyNEAT", false)
        contentManager.addContent(content)
    }
}

class PyNEATToolWindowContent(project: Project) : JPanel(BorderLayout()) {
    init {
        val label = JLabel("PyNEAT Security Scanner v2.4.0 - Use actions in Tools menu to scan")
        label.horizontalAlignment = SwingConstants.CENTER
        add(label, BorderLayout.CENTER)
    }
}
