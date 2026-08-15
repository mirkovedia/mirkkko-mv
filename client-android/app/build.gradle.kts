import java.security.KeyStore
import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// SHA-256 del certificado de debug de esta maquina (~/.android/debug.keystore).
// Se calcula en build time para que el pin de la variante debug sea real y la senal
// apkSignature.mismatch no de un falso positivo en el e2e local. Nunca se hardcodea:
// cada desarrollador tiene su propio debug.keystore.
fun debugSigningCertSha256(): String {
    val keystore = File(System.getProperty("user.home"), ".android/debug.keystore")
    if (!keystore.exists()) return "DEBUG_KEYSTORE_NOT_FOUND"
    return runCatching {
        val store = KeyStore.getInstance("JKS")
        keystore.inputStream().use { store.load(it, "android".toCharArray()) }
        val cert = store.getCertificate("androiddebugkey") ?: return "DEBUG_KEY_ALIAS_NOT_FOUND"
        MessageDigest.getInstance("SHA-256")
            .digest(cert.encoded)
            .joinToString("") { "%02x".format(it) }
    }.getOrElse { "DEBUG_CERT_READ_FAILED" }
}
android {
    namespace = "com.anticheat.client"
    compileSdk = 34
    // Local env has build-tools 35.0.0 (not 34.0.0); pin to what is installed to build offline.
    buildToolsVersion = "35.0.0"
    defaultConfig {
        applicationId = "com.anticheat.client"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("String", "BACKEND_BASE_URL", "\"http://10.0.2.2:3000/\"")
        buildConfigField("String", "APK_SIGNING_CERT_SHA256", "\"REPLACE_WITH_RELEASE_CERT_SHA256\"")
    }
    buildTypes {
        debug {
            // El APK debug se firma con el keystore de debug de la maquina, asi que el pin
            // debe ser ese certificado. Solo para desarrollo local.
            buildConfigField(
                "String",
                "APK_SIGNING_CERT_SHA256",
                "\"${debugSigningCertSha256()}\"",
            )
        }
    }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.0")
    implementation("com.jakewharton.retrofit:retrofit2-kotlinx-serialization-converter:1.0.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
