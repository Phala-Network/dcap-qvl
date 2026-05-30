import com.vanniktech.maven.publish.AndroidSingleVariantLibrary

plugins {
    id("com.android.library") version "8.7.0"
    id("org.jetbrains.kotlin.android") version "2.0.20"
    // Speaks the Sonatype Central Portal bundle-upload protocol. A plain
    // `maven-publish` PUT to the Portal returns 404 — new namespaces no longer
    // get a Nexus/OSSRH staging repo, so artifacts must be uploaded as a
    // zipped bundle, which this plugin handles.
    //
    // Pinned to 0.35.0: it's the last release supporting our AGP 8.7.0
    // (0.36.0 requires AGP >= 8.13.0). The `publishToMavenCentral(...)` DSL
    // below is unchanged — `SonatypeHost` was already dropped before 0.35.0.
    id("com.vanniktech.maven.publish") version "0.35.0"
}

group = "com.phala"
version = "0.5.1"

android {
    namespace = "com.phala.dcapqvl"
    compileSdk = 34

    defaultConfig {
        minSdk = 21
        ndkVersion = "26.1.10909125"
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    sourceSets["androidTest"].java.srcDirs("src/androidTest/kotlin")
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

    // Instrumented (on-device) test that exercises the real JNA-extract-from-
    // AAR `.so` loading path. `org.json` and `java.time` are provided by the
    // device runtime, so no extra deps are needed there.
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}

mavenPublishing {
    // Publish the single Android `release` variant with sources + javadoc jars.
    configure(AndroidSingleVariantLibrary(variant = "release", sourcesJar = true, publishJavadocJar = true))

    // Upload to the Sonatype Central Portal and auto-publish once the
    // deployment passes validation — a tag push goes live with no manual
    // promotion. The `com.phala` namespace's first releases (0.5.0/0.5.1)
    // were promoted by hand; now that it's established this is hands-off.
    // (Flip back to `false` to stage for manual review if ever needed.)
    publishToMavenCentral(automaticRelease = true)

    // PGP-sign all artifacts. Credentials come from the
    // `ORG_GRADLE_PROJECT_signingInMemoryKey*` env vars (see the workflow).
    // The key is unprotected, so no key password is supplied.
    signAllPublications()

    coordinates("com.phala", "dcap-qvl-android", version.toString())

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
        developers {
            developer {
                id.set("phala-network")
                name.set("Phala Network")
                url.set("https://phala.com")
            }
        }
        scm {
            url.set("https://github.com/Phala-Network/dcap-qvl")
            connection.set("scm:git:https://github.com/Phala-Network/dcap-qvl.git")
            developerConnection.set("scm:git:ssh://git@github.com/Phala-Network/dcap-qvl.git")
        }
    }
}
