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

import com.intellij.openapi.components.*
import com.intellij.openapi.project.*
import com.intellij.ui.*
import com.intellij.ui.treeStructure.*
import com.intellij.util.ui.*
import java.awt.*
import javax.swing.*
import javax.swing.tree.*

class FilterDialog(project: Project) : DialogWrapper(project, true) {
    var criticalEnabled = true
    var highEnabled = true
    var mediumEnabled = true
    var lowEnabled = true

    private val criticalCB = JCheckBox("Critical", true)
    private val highCB = JCheckBox("High", true)
    private val mediumCB = JCheckBox("Medium", true)
    private val lowCB = JCheckBox("Low", true)

    init {
        title = "Filter by Severity"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(GridLayout(4, 1, 5, 5))
        panel.add(criticalCB)
        panel.add(highCB)
        panel.add(mediumCB)
        panel.add(lowCB)
        return panel
    }

    override fun doOKAction() {
        criticalEnabled = criticalCB.isSelected
        highEnabled = highCB.isSelected
        mediumEnabled = mediumCB.isSelected
        lowEnabled = lowCB.isSelected
        super.doOKAction()
    }
}
