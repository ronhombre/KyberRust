pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    val nrgp: String = providers.gradleProperty("nrgp").get()

    plugins {
        id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
        id("asia.hombre.neorust") version nrgp
    }
}
rootProject.name = "KyberRust"
include("keccakrust")
