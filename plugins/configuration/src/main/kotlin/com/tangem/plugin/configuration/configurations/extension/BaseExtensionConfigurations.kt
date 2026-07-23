package com.tangem.plugin.configuration.configurations.extension

import com.android.build.gradle.BaseExtension
import com.tangem.plugin.configuration.model.AppConfig
import org.gradle.api.JavaVersion

internal fun BaseExtension.configureCompileSdk() {
    compileSdkVersion(AppConfig.compileSdkVersion)
}

internal fun BaseExtension.configureCompilerOptions() {
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}