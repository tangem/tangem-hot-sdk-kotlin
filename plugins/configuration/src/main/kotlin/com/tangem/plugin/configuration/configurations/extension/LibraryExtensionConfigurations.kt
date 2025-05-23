package com.tangem.plugin.configuration.configurations.extension

import com.android.build.gradle.LibraryExtension
import com.tangem.plugin.configuration.model.AppConfig
import org.gradle.api.Project

internal fun LibraryExtension.configure(project: Project) {
    configureCompileSdk()
    configureDefaultConfig()
    configureCompilerOptions()
}

private fun LibraryExtension.configureDefaultConfig() {
    defaultConfig {
        minSdk = AppConfig.minSdkVersion
        vectorDrawables {
            useSupportLibrary = true
        }
        buildFeatures.buildConfig = true
    }
}