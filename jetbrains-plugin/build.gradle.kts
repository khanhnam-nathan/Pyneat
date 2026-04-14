// Top-level build file where you can add configuration options common to all sub-projects/modules.
buildscript {
    ext.kotlin_version = '1.9.20'
    ext.plugin_xml_version = '2.1.0'

    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
        classpath "org.jetbrains.intellij.plugins:plugin-xml:$plugin_xml_version"
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

apply plugin: 'org.jetbrains.intellij'
apply plugin: 'org.jetbrains.kotlin.jvm'

group = "dev.pyneat"
version = "2.4.0"

// Configure IntelliJ Plugin
intellij {
    pluginName = 'PyNEAT'
    type = 'IC'
    version = '2024.1'
    plugins = [
        'com.intellij.modules.platform',
        'com.intellij.modules.lang',
        'com.intellij.modules.vcs',
        'com.intellij.modules.python',
        'com.intellij.plugins.platform'
    ]
}

tasks.withType(JavaCompile) {
    sourceCompatibility = '17'
    targetCompatibility = '17'
}

tasks.withType(KotlinCompile) {
    kotlinOptions.jvmTarget = '17'
}

patchPluginXml {
    changeNotes = """
        <h3>PyNEAT Security Scanner v2.4.0</h3>
        <ul>
            <li>Added multi-language support (JS, TS, Go, Java, Rust, C#, PHP, Ruby)</li>
            <li>Added SARIF export for CI/CD integration</li>
            <li>Added AI security scanning for prompt injection detection</li>
            <li>Added real-time diagnostics with debouncing</li>
            <li>Added auto-fix support for security issues</li>
        </ul>
    """
    sinceBuild = '241'
    untilBuild = '243.*'
}
