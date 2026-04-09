package com.pyneat

import com.intellij.openapi.components.ApplicationComponent
import com.pyneat.services.PyneatProcessService

/**
 * Application-level component for PyNEAT.
 *
 * This component is initialized when the IDE starts and stays active
 * for the entire IDE session.
 */
class PyneatApplicationComponent : ApplicationComponent {

    override fun initComponent() {
        // Initialize the PyNEAT process service
        PyneatProcessService.getInstance()
    }

    override fun disposeComponent() {
        // Cleanup resources
    }

    override fun getComponentName(): String = "PyneatApplicationComponent"
}
