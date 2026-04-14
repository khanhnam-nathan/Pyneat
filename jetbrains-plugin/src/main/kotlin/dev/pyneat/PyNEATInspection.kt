package dev.pyneat

import com.intellij.codeInspection.*

class PyNEATInspection : GlobalInspectionTool() {
    override fun getDisplayName() = "PyNEAT Security Scan"
    override fun getGroupDisplayName() = "PyNEAT"
    override fun getShortName() = "PyNEATSecurity"

    override fun runInspection(
        file: com.intellij.psi.PsiFile,
        manager: InspectionManager,
        problemsHolder: ProblemsHolder,
        onTheFly: Boolean
    ) {
        val project = file.project
        val scanner = PyNEATScanner(project)
        val findings = scanner.scanFile(file.virtualFile.path)

        for (finding in findings) {
            val message = "[${finding.ruleId}] ${finding.problem} (${finding.severity.uppercase()})"
            val descriptor = manager.createProblemDescriptor(
                file,
                message,
                PyNEATLocalQuickFix(finding),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
                onTheFly
            )
            problemsHolder.registerProblem(descriptor)
        }
    }
}

class PyNEATLocalQuickFix(private val finding: SecurityFinding) : LocalQuickFix {
    override fun getName() = "Apply PyNEAT Fix (${finding.ruleId})"
    override fun getFamilyName() = "PyNEAT"

    override fun applyFix(project: Project, descriptor: ProblemDescriptor) {
        val scanner = PyNEATScanner(project)
        scanner.applyFix(finding)
    }
}
