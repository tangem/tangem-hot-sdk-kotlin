package com.tangem.plugin.configuration.configurations.extension

import com.android.build.gradle.AppExtension
import com.tangem.plugin.configuration.model.AppConfig
import org.gradle.api.Project

internal fun AppExtension.configure(project: Project) {
    configureCompileSdk()
    configureDefaultConfig(project)
    configureCompilerOptions()
}

private fun AppExtension.configureDefaultConfig(project: Project) {
    defaultConfig {
        applicationId = AppConfig.packageName
        minSdk = AppConfig.minSdkVersion
        targetSdk = AppConfig.targetSdkVersion

        versionCode = if (project.hasProperty("versionCode")) {
            (project.property("versionCode") as String).toInt()
        } else {
            AppConfig.versionCode
        }

        versionName = if (project.hasProperty("versionName")) {
            project.property("versionName") as String
        } else {
            AppConfig.versionName
        }

        buildFeatures.buildConfig = true

        testInstrumentationRunner = "com.tangem.common.HiltTestRunner"
    }
}