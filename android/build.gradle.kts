import kotlin.apply

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    id("configuration")
}

apply {
    from("../upload-github.gradle")
}

android {
    namespace = "com.tangem.hot.sdk.android"
}

dependencies {
    implementation(projects.core)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.card.core)
    implementation(libs.card.android)
    implementation(libs.wallet.core)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}