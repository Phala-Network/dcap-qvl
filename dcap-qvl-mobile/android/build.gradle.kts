plugins {
    id("com.android.library") version "8.7.0"
    id("org.jetbrains.kotlin.android") version "2.0.20"
    `maven-publish`
}

group = "com.phala"
version = "0.5.0"

android {
    namespace = "com.phala.dcapqvl"
    compileSdk = 34

    defaultConfig {
        minSdk = 21
        ndkVersion = "26.1.10909125"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Where `scripts/build_android.sh` deposits the cross-compiled .so files.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")
    sourceSets["test"].java.srcDirs("src/test/kotlin")
    // For the local JVM test task, JNA must be able to locate the host-arch
    // .so. The build script (`scripts/build_android.sh`) copies the host build
    // into `.host-jna/` (outside `build/`, so `gradle clean` can't wipe it
    // before tests run) and we forward that path via `jna.library.path` and
    // `java.library.path` so JNA finds it without classpath extraction.
    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all {
            it.systemProperty(
                "jna.library.path",
                file(".host-jna").absolutePath
            )
            it.systemProperty(
                "java.library.path",
                file(".host-jna").absolutePath
            )
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    // UniFFI Kotlin bindings use JNA for the FFI bridge.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("net.java.dev.jna:jna:5.14.0")
    // The `org.json` package is stubbed in android.jar — local unit tests
    // need a real implementation on the classpath.
    testImplementation("org.json:json:20240303")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.phala"
            artifactId = "dcap-qvl-android"
            version = project.version.toString()

            afterEvaluate {
                from(components["release"])
            }

            pom {
                name.set("dcap-qvl for Android")
                description.set("Native DCAP quote verification for Android (Kotlin)")
                url.set("https://github.com/Phala-Network/dcap-qvl")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
            }
        }
    }
}
