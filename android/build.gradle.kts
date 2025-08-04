
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    id("configuration")
}

apply {
    from("../upload-github.gradle")
}

val pageSize16KbFlags = "-Wl','-z','max-page-size=16384"

android {
    namespace = "com.tangem.hot.sdk.android"

    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments()
                cppFlags(pageSize16KbFlags)
            }
        }
        ndk {
            abiFilters.add("armeabi-v7a")
            abiFilters.add("arm64-v8a")
        }

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    externalNativeBuild {
        cmake {
            path = File("src/main/cpp/CMakeLists.txt")
        }
    }
}

dependencies {
    implementation(projects.core)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.card.core)
    implementation(libs.card.android)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}