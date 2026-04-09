import org.jetbrains.intellij.platform.gradle.IntelliJPlatformType
import org.jetbrains.intellij.platform.gradle.tasks.BuildSearchableOptionsTask

plugins {
    id("java")
    id("org.jetbrains.kotlin") version "1.9.22"
    id("org.jetbrains.intellij.platform") version "2.0.1"
    id("org.jetbrains.intellij.plugins.secondary-system" version "2.0.1")
}

group = "com.pyneat"
version = "2.2.0"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17)
}

intellijPlatform {
    intellij {
        version.set("2024.1")
        type.set(IntelliJPlatformType.IdeaCommunity)
    }

    pluginVerification {
        ides {
            recommended()
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib")
    
    // Python plugin integration
    implementation("com.jetbrains.python:sdk:241.0.0")
    
    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.0")
}

tasks {
    wrapper {
        gradleVersion = "8.5"
    }

    test {
        useJUnitPlatform()
    }

    patchPluginXml {
        version.set("2.2.0")
        sinceBuild.set("241")
        untilBuild.set("243.*")
    }

    signPlugin {
        certificateChain.set(file("credentials/chain.crt"))
        privateKey.set(file("credentials/private.key"))
        password.set(System.getenv("PLUGIN_SIGNING_PASSWORD"))
    }

    publishPlugin {
        token.set(System.getenv("JETBRAINS_TOKEN"))
        channels.set(listOf("beta"))
    }

    buildSearchableOptions {
        enabled.set(false)
    }
}
