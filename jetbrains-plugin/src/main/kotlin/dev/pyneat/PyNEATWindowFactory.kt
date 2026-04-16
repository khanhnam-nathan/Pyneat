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
