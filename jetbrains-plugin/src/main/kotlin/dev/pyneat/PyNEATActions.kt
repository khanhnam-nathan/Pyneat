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
