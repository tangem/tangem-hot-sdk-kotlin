plugins {
    alias(deps.plugins.kotlin.jvm)
    alias(deps.plugins.kotlin.serialization)
    id("configuration")
}

apply {
    from("../upload-github.gradle")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(libs.card.core)
    implementation(libs.kotlin.serialization)
    implementation(libs.kotlin.coroutines)
}