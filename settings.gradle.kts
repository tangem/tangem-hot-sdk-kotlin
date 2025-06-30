pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }

    includeBuild("plugins/configuration")
}

val properties = java.util.Properties()
val propertiesFile = File(rootDir.absolutePath, "local.properties")
if (propertiesFile.exists()) {
    properties.load(propertiesFile.inputStream())
    println("Authenticating user: " + properties.getProperty("gpr.user"))
} else {
    println(
        "local.properties not found, please create it next to build.gradle and set gpr.user and gpr.key (Create a GitHub package read only + non expiration token at https://github.com/settings/tokens)\n" +
                "Or set GITHUB_ACTOR and GITHUB_TOKEN environment variables"
    )
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        mavenLocal {
            content {
                includeGroupAndSubgroups("com.tangem.tangem-sdk-kotlin")
            }
        }
        maven {
            // setting any repository from tangem project allows maven search all packages in the project
            url = uri("https://maven.pkg.github.com/tangem/tangem-sdk-android")
            credentials {
                username = properties.getProperty("gpr.user") ?: System.getenv("GITHUB_ACTOR")
                password = properties.getProperty("gpr.key") ?: System.getenv("GITHUB_TOKEN")
            }
            content { includeGroupAndSubgroups("com.tangem.tangem-sdk-kotlin") }
        }
        maven {
            // setting any repository from tangem project allows maven search all packages in the project
            url = uri("https://maven.pkg.github.com/tangem/wallet-core")
            credentials {
                username = properties.getProperty("gpr.user") ?: System.getenv("GITHUB_ACTOR")
                password = properties.getProperty("gpr.key") ?: System.getenv("GITHUB_TOKEN")
            }
            content {
                includeModule("com.tangem", "wallet-core-proto")
                includeModule("com.tangem", "wallet-core")
            }
        }
    }

    versionCatalogs {
        create("deps") {
            from(files("gradle/libs.versions.toml"))
        }
    }
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "tangem-hot-sdk-kotlin"
include(":android")
include(":core")