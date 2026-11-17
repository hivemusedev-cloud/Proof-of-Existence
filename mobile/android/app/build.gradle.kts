plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.poe.suite"
    compileSdk = 34

    defaultConfig {
        applicationId = "app.poe.suite"
        minSdk = 28
        targetSdk = 34
        versionCode = 2
        versionName = "0.2.0"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // UniFFI's Kotlin bindings call the Rust core through JNA.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
