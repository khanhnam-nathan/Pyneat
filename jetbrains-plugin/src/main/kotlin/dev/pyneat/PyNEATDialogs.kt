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
