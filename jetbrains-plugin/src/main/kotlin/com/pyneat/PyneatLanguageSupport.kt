package com.pyneat

import com.intellij.lang.Language
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiFileFactory
import com.intellij.psi.FileViewProvider

/**
 * Language support for Python files in PyNEAT.
 *
 * This class provides language-specific integration for PyNEAT
 * with the IntelliJ Python plugin.
 */
class PyneatLanguageSupport : Language("Python") {

    companion object {
        val INSTANCE = PyneatLanguageSupport()
    }
}

/**
 * Intentions for PyNEAT quick fixes.
 *
 * These are the lightbulb suggestions that appear in the IDE
 * when PyNEAT detects an issue.
 */
package com.pyneat.intentions

import com.intellij.codeInspection.IntentionAction
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiFile
import com.pyneat.services.PyneatProcessService

/**
 * Quick fix intention for PyNEAT issues.
 *
 * This intention appears as a lightbulb suggestion when
 * PyNEAT detects an issue that can be auto-fixed.
 */
class PyneatQuickFixIntention : IntentionAction {

    override fun getText(): String = "PyNEAT: Fix with PyNEAT"

    override fun getFamilyName(): String = "PyNEAT"

    override fun isAvailable(
        project: Project,
        editor: Editor?,
        file: PsiFile?
    ): Boolean {
        return file?.language?.id == "Python"
    }

    override fun invoke(
        project: Project,
        editor: Editor?,
        file: PsiFile?
    ) {
        if (file == null) return

        val virtualFile = file.virtualFile ?: return
        val processService = PyneatProcessService.getInstance()
        val result = processService.clean(virtualFile.path)

        if (result.success) {
            // Refresh the file in the editor
            virtualFile.refresh(false, true)
        }
    }
}
