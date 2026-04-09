# PyNEAT JetBrains Plugin Configuration
#
# This directory contains configuration files for the PyNEAT JetBrains plugin.
# The actual plugin is built using Gradle and IntelliJ Platform SDK.
#
# For more information, see:
# https://plugins.jetbrains.com/docs/intellij/welcome.html

# build.gradle.kts - Gradle build script for JetBrains plugin
# settings.gradle.kts - Gradle settings
# src/ - Plugin source code

# Required IDE: IntelliJ IDEA 2023.1+
# Required JDK: 17+

## Quick Setup

1. Open this project in IntelliJ IDEA
2. Install the Plugin DevKit plugin
3. Run `./gradlew runIde` to start IDE with the plugin
4. Run `./gradlew buildPlugin` to build the plugin

## Gradle Tasks

```bash
# Build the plugin
./gradlew buildPlugin

# Run IDE with plugin
./gradlew runIde

# Run tests
./gradlew test

# Publish to JetBrains Marketplace
./gradlew publishPlugin
```

## Features

- Real-time security scanning
- Code quality suggestions
- One-click auto-fix
- Integration with PyCharm, IntelliJ IDEA, WebStorm, etc.
- Support for Python 3.10+

## Configuration

Configure PyNEAT in JetBrains settings:
- File > Settings > Tools > PyNEAT
- Enable/disable rules
- Set package (safe/conservative/destructive)
- Configure keyboard shortcuts
