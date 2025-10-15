plugins {
    id("com.android.application") version "8.7.0"
}

android {
    namespace = "com.byd.xposedhooks"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.byd.xposedhooks"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        getByName("debug") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    packaging {
        resources.excludes += setOf("META-INF/androidx.*", "META-INF/ASL2.0", "META-INF/LICENSE**")
    }
}

dependencies {
    compileOnly(files("libs/xposed-stub.jar"))
}
