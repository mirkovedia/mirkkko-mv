# Android Anti-Cheat Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a native Android (Kotlin) opt-in self-check app that enrolls a hardware-backed key, runs a signed verification session against the existing NestJS anti-cheat backend, and shows a server-verifiable verdict.

**Architecture:** Server-authoritative. The device collects signals and signs each snapshot with an Android Keystore EC P-256 key; the backend verifies signature + rotating nonce + attestation and computes the verdict. Platform access is isolated behind interfaces so all core logic (crypto encoding, payload building, networking, signal decisions, orchestration) is unit-testable on the plain JVM.

**Tech Stack:** Kotlin, Jetpack Compose, Retrofit + OkHttp, kotlinx.serialization, Android Keystore, JUnit + MockWebServer.

## Global Constraints

- Language/UI: Kotlin native + Jetpack Compose. Package root: `com.anticheat.client`.
- Crypto: ECDSA P-256 (`secp256r1`), `SHA256withECDSA` (DER signatures), public key exported as X.509 SPKI DER then Base64 (no line breaks, `Base64.NO_WRAP`).
- The bytes that are signed for a snapshot MUST be byte-for-byte identical to the bytes that are Base64-encoded into `payloadB64`.
- Signals must match the backend `SignalSet` exactly: `root{detected}`, `hooking{frida,xposed}`, `packages[]`, `emulator{detected}`, `overlay{activeDuringSession}`, `accessibility{suspiciousServiceActive}`, `apkSignature{mismatch}`.
- Package enumeration: use a manifest `<queries>` list of known cheat packages. Do NOT use `QUERY_ALL_PACKAGES`.
- Play Integrity is deferred: snapshots send `integrityToken = null` and omit `integrityTokenHash`.
- `minSdk = 26`, recent `targetSdk`/`compileSdk`.
- Backend base URL comes from `BuildConfig.BACKEND_BASE_URL`; the app's own signing-cert pin comes from `BuildConfig.APK_SIGNING_CERT_SHA256`.
- New code lives under `client-android/`; the NestJS backend is not modified.

### Backend contract (fixed — copy verbatim)

- `POST /devices/enroll` body `{ publicKey, platform:"ANDROID", keyAlgo?, attestation?:{type,certificateChain?} }` → `{ deviceId, createdAt }`. Idempotent by public-key fingerprint. (Note: backend only special-cases `type:"PLAY_INTEGRITY"`; our `ANDROID_KEY_ATTESTATION` chain is stored as evidence but typed `NONE` — acceptable.)
- `POST /sessions/start` body `{ deviceId, clientTimestamp(ISO8601), signatureB64=sign(deviceId+clientTimestamp) }` → `{ sessionId, nonce, expectedIntervalSec, jitterSec, blacklistVersion }`.
- `POST /sessions/:id/snapshot` body `{ payloadB64, signatureB64=sign(payloadBytes), integrityToken:null }`. `payloadB64`=Base64 of UTF-8 JSON `{ deviceId, sessionId, seq, nonce, clientTimestamp, integrityTokenHash?, signals }` → `{ accepted, nextNonce, seq }`. Rejections: `401 SIGNATURE_INVALID`, `409 NONCE_REUSE`, `401 BINDING_MISMATCH`, `401 CLOCK_SKEW`, `410 SESSION_NOT_ACTIVE`.
- `POST /sessions/:id/end` body `{ clientTimestamp, signatureB64=sign(sessionId+clientTimestamp) }` → `{ sessionId, status, verdict, flags }`.
- `GET /sessions/:id/verdict` → `{ sessionId, status, verdict }`.

---

## File Structure

```
client-android/
  settings.gradle.kts
  build.gradle.kts
  gradle.properties
  app/
    build.gradle.kts
    src/main/AndroidManifest.xml
    src/main/java/com/anticheat/client/
      crypto/SigningKey.kt              # interface: publicKeySpkiB64(), sign(bytes), attestationChainB64()
      crypto/JvmSigningKey.kt           # pure-JVM impl (tests + interop proof)
      crypto/KeystoreSigningKey.kt      # Android Keystore impl (StrongBox/TEE + Key Attestation)
      crypto/CryptoUtil.kt              # sha256Hex, base64NoWrap helpers
      net/dto/Dtos.kt                   # request/response @Serializable data classes
      net/AntiCheatApi.kt               # Retrofit interface
      net/ApiClient.kt                  # Retrofit/OkHttp factory
      session/SnapshotPayload.kt        # @Serializable payload model
      session/PayloadBuilder.kt         # builds signed snapshot body
      session/DeviceStore.kt            # interface: getDeviceId()/setDeviceId()
      session/DataStoreDeviceStore.kt   # DataStore impl
      session/VerificationOrchestrator.kt
      session/VerificationState.kt      # sealed UI state
      signals/model/SignalSet.kt        # @Serializable SignalSet + sub-models
      signals/SignalCollector.kt        # interface Collector { fun contribute(SignalSetBuilder) }
      signals/probes/Probes.kt          # interfaces: FileProbe, BuildProbe, PackageProbe, SettingsProbe, ObscuredTouchProbe, SelfCertProbe
      signals/RootLogic.kt HookingLogic.kt EmulatorLogic.kt ApkSignatureLogic.kt PackagesLogic.kt OverlayLogic.kt AccessibilityLogic.kt
      signals/AndroidProbes.kt          # Android impls of the probe interfaces
      signals/SignalAggregator.kt
      ui/MainActivity.kt MainScreen.kt ResultScreen.kt
    src/test/java/com/anticheat/client/...   # JVM unit tests (JUnit + MockWebServer)
  README.md
```

---

## Task 1: Gradle Android project scaffold

**Files:**
- Create: `client-android/settings.gradle.kts`, `client-android/build.gradle.kts`, `client-android/gradle.properties`, `client-android/app/build.gradle.kts`, `client-android/app/src/main/AndroidManifest.xml`, `client-android/app/src/main/java/com/anticheat/client/ui/MainActivity.kt`

**Interfaces:**
- Produces: a buildable Android app module `:app`, `BuildConfig.BACKEND_BASE_URL` and `BuildConfig.APK_SIGNING_CERT_SHA256` string fields, dependencies for Compose, Retrofit, OkHttp, kotlinx.serialization, JUnit, MockWebServer.

- [ ] **Step 1: Create Gradle wrapper + settings**

`client-android/settings.gradle.kts`:
```kotlin
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "anticheat-client"
include(":app")
```

`client-android/build.gradle.kts`:
```kotlin
plugins {
    id("com.android.application") version "8.5.0" apply false
    id("org.jetbrains.kotlin.android") version "2.0.0" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.0" apply false
}
```

`client-android/gradle.properties`:
```
org.gradle.jvmargs=-Xmx2048m
android.useAndroidX=true
kotlin.code.style=official
```

- [ ] **Step 2: Create the app module build file**

`client-android/app/build.gradle.kts`:
```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}
android {
    namespace = "com.anticheat.client"
    compileSdk = 34
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
    buildFeatures { compose = true; buildConfig = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }
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
```

- [ ] **Step 3: Minimal manifest + empty MainActivity**

`AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="AntiCheat Check" android:usesCleartextTraffic="true">
        <activity android:name=".ui.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
    <queries>
        <!-- Known cheat packages; keep in sync with the server blacklist per release. -->
        <package android:name="com.example.knowncheat"/>
    </queries>
</manifest>
```

`MainActivity.kt`:
```kotlin
package com.anticheat.client.ui
import android.os.Bundle
import androidx.activity.ComponentActivity
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState) }
}
```

- [ ] **Step 4: Verify it assembles**

Run: `cd client-android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL. (Requires Android SDK; document in README if unavailable locally.)

- [ ] **Step 5: Commit**

```bash
git add client-android
git commit -m "chore: scaffold client-android Gradle project"
```

---

## Task 2: SignalSet model + JSON serialization

**Files:**
- Create: `app/src/main/java/com/anticheat/client/signals/model/SignalSet.kt`
- Test: `app/src/test/java/com/anticheat/client/signals/SignalSetSerializationTest.kt`

**Interfaces:**
- Produces: `@Serializable SignalSet` with nullable sub-objects `RootSignal(detected)`, `HookingSignal(frida,xposed)`, `EmulatorSignal(detected)`, `OverlaySignal(activeDuringSession)`, `AccessibilitySignal(suspiciousServiceActive)`, `ApkSignatureSignal(mismatch)`, and `packages: List<String>?`. A shared `Json { encodeDefaults = false; explicitNulls = false }` instance named `AntiCheatJson`.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.model.*
import org.junit.Assert.assertEquals
import org.junit.Test
class SignalSetSerializationTest {
    @Test fun omitsNullFieldsAndSerializesPresentOnes() {
        val s = SignalSet(root = RootSignal(detected = true), packages = listOf("com.x"))
        val json = AntiCheatJson.encodeToString(SignalSet.serializer(), s)
        assertEquals("""{"root":{"detected":true},"packages":["com.x"]}""", json)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "*SignalSetSerializationTest*"`
Expected: FAIL (unresolved references).

- [ ] **Step 3: Write minimal implementation**

`SignalSet.kt`:
```kotlin
package com.anticheat.client.signals.model
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

val AntiCheatJson = Json { encodeDefaults = false; explicitNulls = false }

@Serializable data class RootSignal(val detected: Boolean)
@Serializable data class HookingSignal(val frida: Boolean? = null, val xposed: Boolean? = null)
@Serializable data class EmulatorSignal(val detected: Boolean)
@Serializable data class OverlaySignal(val activeDuringSession: Boolean)
@Serializable data class AccessibilitySignal(val suspiciousServiceActive: Boolean)
@Serializable data class ApkSignatureSignal(val mismatch: Boolean)

@Serializable data class SignalSet(
    val root: RootSignal? = null,
    val hooking: HookingSignal? = null,
    val packages: List<String>? = null,
    val emulator: EmulatorSignal? = null,
    val overlay: OverlaySignal? = null,
    val accessibility: AccessibilitySignal? = null,
    val apkSignature: ApkSignatureSignal? = null,
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "*SignalSetSerializationTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add client-android/app/src
git commit -m "feat: SignalSet model with backend-matching JSON serialization"
```

---

## Task 3: SigningKey interface + JvmSigningKey (crypto core + interop proof)

**Files:**
- Create: `app/src/main/java/com/anticheat/client/crypto/SigningKey.kt`, `.../crypto/JvmSigningKey.kt`, `.../crypto/CryptoUtil.kt`
- Test: `app/src/test/java/com/anticheat/client/crypto/JvmSigningKeyTest.kt`

**Interfaces:**
- Produces:
  - `interface SigningKey { fun publicKeySpkiB64(): String; fun sign(payload: ByteArray): String; fun attestationChainB64(): List<String> }`
  - `class JvmSigningKey(keyPair: KeyPair? = null) : SigningKey` — generates a P-256 keypair if none given; `sign` returns Base64 (NO_WRAP) of a DER `SHA256withECDSA` signature; `attestationChainB64()` returns `emptyList()`.
  - `object CryptoUtil { fun base64(bytes: ByteArray): String; fun sha256Hex(s: String): String }`.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.anticheat.client.crypto
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
class JvmSigningKeyTest {
    // Proves the exported SPKI + DER signature verify with a standard verifier,
    // i.e. exactly what the Node backend does (crypto.verify sha256, spki, der).
    @Test fun signatureVerifiesWithStandardEcdsaOverExportedSpki() {
        val key = JvmSigningKey()
        val payload = """{"hello":"world"}""".toByteArray(Charsets.UTF_8)
        val sigB64 = key.sign(payload)
        val spki = Base64.getDecoder().decode(key.publicKeySpkiB64())
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        val v = Signature.getInstance("SHA256withECDSA")
        v.initVerify(pub); v.update(payload)
        assertTrue(v.verify(Base64.getDecoder().decode(sigB64)))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "*JvmSigningKeyTest*"`
Expected: FAIL (unresolved references).

- [ ] **Step 3: Write minimal implementation**

`SigningKey.kt`:
```kotlin
package com.anticheat.client.crypto
interface SigningKey {
    fun publicKeySpkiB64(): String
    fun sign(payload: ByteArray): String
    fun attestationChainB64(): List<String>
}
```

`CryptoUtil.kt`:
```kotlin
package com.anticheat.client.crypto
import java.security.MessageDigest
import java.util.Base64
object CryptoUtil {
    fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes) // standard, padded, no wrap
    fun sha256Hex(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
```

`JvmSigningKey.kt`:
```kotlin
package com.anticheat.client.crypto
import java.security.*
import java.security.spec.ECGenParameterSpec
class JvmSigningKey(keyPair: KeyPair? = null) : SigningKey {
    private val kp: KeyPair = keyPair ?: KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    override fun publicKeySpkiB64(): String = CryptoUtil.base64(kp.public.encoded) // X.509 SPKI DER
    override fun sign(payload: ByteArray): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(kp.private); s.update(payload)
        return CryptoUtil.base64(s.sign()) // DER
    }
    override fun attestationChainB64(): List<String> = emptyList()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "*JvmSigningKeyTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add client-android/app/src
git commit -m "feat: SigningKey interface + JVM impl with SPKI/DER interop proof"
```

---

## Task 4: SnapshotPayload model + PayloadBuilder

**Files:**
- Create: `app/src/main/java/com/anticheat/client/session/SnapshotPayload.kt`, `.../session/PayloadBuilder.kt`
- Test: `app/src/test/java/com/anticheat/client/session/PayloadBuilderTest.kt`

**Interfaces:**
- Consumes: `SigningKey`, `SignalSet`, `AntiCheatJson`, `CryptoUtil`.
- Produces:
  - `@Serializable data class SnapshotPayload(deviceId, sessionId, seq:Int, nonce, clientTimestamp, integrityTokenHash:String?=null, signals:SignalSet)`.
  - `data class SnapshotBody(payloadB64:String, signatureB64:String, integrityToken:String?)`.
  - `object PayloadBuilder { fun build(key:SigningKey, p:SnapshotPayload, integrityToken:String?): SnapshotBody }` where the signed bytes equal the Base64-decoded `payloadB64`.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.anticheat.client.session
import com.anticheat.client.crypto.JvmSigningKey
import com.anticheat.client.signals.model.RootSignal
import com.anticheat.client.signals.model.SignalSet
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
class PayloadBuilderTest {
    @Test fun signedBytesEqualDecodedPayloadAndVerify() {
        val key = JvmSigningKey()
        val payload = SnapshotPayload(
            deviceId = "d1", sessionId = "s1", seq = 0, nonce = "n0",
            clientTimestamp = "2026-07-28T00:00:00.000Z",
            signals = SignalSet(root = RootSignal(detected = false))
        )
        val body = PayloadBuilder.build(key, payload, integrityToken = null)
        val decoded = Base64.getDecoder().decode(body.payloadB64)
        // signature must verify over the exact decoded bytes
        val pub = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(key.publicKeySpkiB64())))
        val v = Signature.getInstance("SHA256withECDSA"); v.initVerify(pub); v.update(decoded)
        assertTrue(v.verify(Base64.getDecoder().decode(body.signatureB64)))
        assertNull(body.integrityToken)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "*PayloadBuilderTest*"`
Expected: FAIL (unresolved references).

- [ ] **Step 3: Write minimal implementation**

`SnapshotPayload.kt`:
```kotlin
package com.anticheat.client.session
import com.anticheat.client.signals.model.SignalSet
import kotlinx.serialization.Serializable
@Serializable data class SnapshotPayload(
    val deviceId: String, val sessionId: String, val seq: Int,
    val nonce: String, val clientTimestamp: String,
    val integrityTokenHash: String? = null, val signals: SignalSet,
)
data class SnapshotBody(val payloadB64: String, val signatureB64: String, val integrityToken: String?)
```

`PayloadBuilder.kt`:
```kotlin
package com.anticheat.client.session
import com.anticheat.client.crypto.CryptoUtil
import com.anticheat.client.crypto.SigningKey
import com.anticheat.client.signals.model.AntiCheatJson
object PayloadBuilder {
    fun build(key: SigningKey, payload: SnapshotPayload, integrityToken: String?): SnapshotBody {
        val enriched = if (integrityToken != null)
            payload.copy(integrityTokenHash = CryptoUtil.sha256Hex(integrityToken)) else payload
        val bytes = AntiCheatJson.encodeToString(SnapshotPayload.serializer(), enriched)
            .toByteArray(Charsets.UTF_8)
        return SnapshotBody(CryptoUtil.base64(bytes), key.sign(bytes), integrityToken)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "*PayloadBuilderTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add client-android/app/src
git commit -m "feat: snapshot payload builder with sign==encode byte guarantee"
```

---

## Task 5: DTOs + Retrofit API + ApiClient (with MockWebServer tests)

**Files:**
- Create: `app/src/main/java/com/anticheat/client/net/dto/Dtos.kt`, `.../net/AntiCheatApi.kt`, `.../net/ApiClient.kt`
- Test: `app/src/test/java/com/anticheat/client/net/AntiCheatApiTest.kt`

**Interfaces:**
- Produces:
  - DTOs: `EnrollRequest(publicKey, platform, keyAlgo, attestation:AttestationDto?)`, `AttestationDto(type, certificateChain:List<String>?)`, `EnrollResponse(deviceId, createdAt)`, `StartRequest(deviceId, clientTimestamp, signatureB64)`, `StartResponse(sessionId, nonce, expectedIntervalSec:Int, jitterSec:Int, blacklistVersion:Int)`, `SnapshotRequest(payloadB64, signatureB64, integrityToken:String?)`, `SnapshotResponse(accepted:Boolean, nextNonce:String, seq:Int)`, `EndRequest(clientTimestamp, signatureB64)`, `EndResponse(sessionId, status, verdict, flags:List<FlagDto>)`, `FlagDto(type, severity)`, `VerdictResponse(sessionId, status, verdict:String?)`.
  - `interface AntiCheatApi` with suspend functions for the five endpoints.
  - `object ApiClient { fun create(baseUrl:String): AntiCheatApi }`.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.anticheat.client.net
import com.anticheat.client.net.dto.*
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Test
class AntiCheatApiTest {
    @Test fun startParsesResponseAndPostsBody() = runTest {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(
            """{"sessionId":"s1","nonce":"n0","expectedIntervalSec":10,"jitterSec":2,"blacklistVersion":3}"""
        ).addHeader("Content-Type", "application/json"))
        server.start()
        val api = ApiClient.create(server.url("/").toString())
        val res = api.startSession(StartRequest("d1", "2026-07-28T00:00:00.000Z", "sig"))
        assertEquals("s1", res.sessionId)
        assertEquals(10, res.expectedIntervalSec)
        val recorded = server.takeRequest()
        assertEquals("/sessions/start", recorded.path)
        server.shutdown()
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "*AntiCheatApiTest*"`
Expected: FAIL (unresolved references).

- [ ] **Step 3: Write minimal implementation**

`Dtos.kt`:
```kotlin
package com.anticheat.client.net.dto
import kotlinx.serialization.Serializable
@Serializable data class AttestationDto(val type: String, val certificateChain: List<String>? = null)
@Serializable data class EnrollRequest(val publicKey: String, val platform: String = "ANDROID",
    val keyAlgo: String = "EC_P256", val attestation: AttestationDto? = null)
@Serializable data class EnrollResponse(val deviceId: String, val createdAt: String)
@Serializable data class StartRequest(val deviceId: String, val clientTimestamp: String, val signatureB64: String)
@Serializable data class StartResponse(val sessionId: String, val nonce: String,
    val expectedIntervalSec: Int, val jitterSec: Int, val blacklistVersion: Int)
@Serializable data class SnapshotRequest(val payloadB64: String, val signatureB64: String, val integrityToken: String? = null)
@Serializable data class SnapshotResponse(val accepted: Boolean, val nextNonce: String, val seq: Int)
@Serializable data class EndRequest(val clientTimestamp: String, val signatureB64: String)
@Serializable data class FlagDto(val type: String, val severity: String)
@Serializable data class EndResponse(val sessionId: String, val status: String, val verdict: String? = null, val flags: List<FlagDto> = emptyList())
@Serializable data class VerdictResponse(val sessionId: String, val status: String, val verdict: String? = null)
```

`AntiCheatApi.kt`:
```kotlin
package com.anticheat.client.net
import com.anticheat.client.net.dto.*
import retrofit2.http.*
interface AntiCheatApi {
    @POST("devices/enroll") suspend fun enroll(@Body body: EnrollRequest): EnrollResponse
    @POST("sessions/start") suspend fun startSession(@Body body: StartRequest): StartResponse
    @POST("sessions/{id}/snapshot") suspend fun snapshot(@Path("id") id: String, @Body body: SnapshotRequest): SnapshotResponse
    @POST("sessions/{id}/end") suspend fun endSession(@Path("id") id: String, @Body body: EndRequest): EndResponse
    @GET("sessions/{id}/verdict") suspend fun verdict(@Path("id") id: String): VerdictResponse
}
```

`ApiClient.kt`:
```kotlin
package com.anticheat.client.net
import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import retrofit2.Retrofit
object ApiClient {
    fun create(baseUrl: String): AntiCheatApi {
        val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
        return Retrofit.Builder().baseUrl(baseUrl)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build().create(AntiCheatApi::class.java)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "*AntiCheatApiTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add client-android/app/src
git commit -m "feat: backend DTOs + Retrofit API client"
```

---

## Task 6: Signal probes + security-signal logic (root, hooking, emulator, apkSignature)

**Files:**
- Create: `app/src/main/java/com/anticheat/client/signals/probes/Probes.kt`, `.../signals/RootLogic.kt`, `.../signals/HookingLogic.kt`, `.../signals/EmulatorLogic.kt`, `.../signals/ApkSignatureLogic.kt`
- Test: `app/src/test/java/com/anticheat/client/signals/SecuritySignalsTest.kt`

**Interfaces:**
- Produces:
  - `interface FileProbe { fun exists(path: String): Boolean }`, `interface BuildProbe { val tags:String; val fingerprint:String; val model:String; val brand:String; val hardware:String }`, `interface SelfCertProbe { fun signingCertSha256(): String }`, `interface ProcMapsProbe { fun selfMaps(): String }`.
  - Pure functions: `fun detectRoot(f:FileProbe,b:BuildProbe):Boolean`, `fun detectHooking(maps:ProcMapsProbe, xposedPresent:Boolean):Pair<Boolean,Boolean>` (frida,xposed), `fun detectEmulator(b:BuildProbe):Boolean`, `fun detectApkMismatch(self:SelfCertProbe, pinned:String):Boolean`.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.*
import org.junit.Assert.*
import org.junit.Test
class SecuritySignalsTest {
    private fun build(tags:String="release-keys", fp:String="", model:String="", brand:String="", hw:String="") =
        object : BuildProbe { override val tags=tags; override val fingerprint=fp; override val model=model; override val brand=brand; override val hardware=hw }
    @Test fun rootDetectedWhenSuBinaryPresent() {
        val f = FileProbe { it == "/system/bin/su" }
        assertTrue(detectRoot(f, build()))
    }
    @Test fun rootDetectedWhenTestKeys() {
        assertTrue(detectRoot(FileProbe { false }, build(tags = "test-keys")))
    }
    @Test fun rootCleanOtherwise() {
        assertFalse(detectRoot(FileProbe { false }, build()))
    }
    @Test fun emulatorDetectedByHardware() {
        assertTrue(detectEmulator(build(hw = "goldfish")))
        assertFalse(detectEmulator(build(hw = "qcom", fp = "samsung/greatlte")))
    }
    @Test fun hookingDetectsFridaInMaps() {
        val maps = ProcMapsProbe { "7f... /data/local/tmp/frida-agent-64.so\n" }
        val (frida, xposed) = detectHooking(maps, xposedPresent = false)
        assertTrue(frida); assertFalse(xposed)
    }
    @Test fun apkMismatchWhenCertDiffers() {
        assertTrue(detectApkMismatch(SelfCertProbe { "AA" }, pinned = "BB"))
        assertFalse(detectApkMismatch(SelfCertProbe { "AA" }, pinned = "AA"))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "*SecuritySignalsTest*"`
Expected: FAIL (unresolved references).

- [ ] **Step 3: Write minimal implementation**

`Probes.kt`:
```kotlin
package com.anticheat.client.signals.probes
fun interface FileProbe { fun exists(path: String): Boolean }
interface BuildProbe { val tags:String; val fingerprint:String; val model:String; val brand:String; val hardware:String }
fun interface SelfCertProbe { fun signingCertSha256(): String }
fun interface ProcMapsProbe { fun selfMaps(): String }
```

`RootLogic.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.BuildProbe
import com.anticheat.client.signals.probes.FileProbe
private val SU_PATHS = listOf("/system/bin/su","/system/xbin/su","/sbin/su","/system/app/Superuser.apk","/data/adb/magisk")
fun detectRoot(f: FileProbe, b: BuildProbe): Boolean =
    b.tags.contains("test-keys") || SU_PATHS.any { f.exists(it) }
```

`EmulatorLogic.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.BuildProbe
private val EMU_HW = listOf("goldfish","ranchu","vbox86")
fun detectEmulator(b: BuildProbe): Boolean =
    EMU_HW.any { b.hardware.contains(it, true) } ||
    b.fingerprint.contains("generic", true) || b.model.contains("emulator", true)
```

`HookingLogic.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.ProcMapsProbe
fun detectHooking(maps: ProcMapsProbe, xposedPresent: Boolean): Pair<Boolean, Boolean> {
    val m = maps.selfMaps()
    val frida = m.contains("frida", true) || m.contains("gum-js-loop", true)
    return frida to xposedPresent
}
```

`ApkSignatureLogic.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.SelfCertProbe
fun detectApkMismatch(self: SelfCertProbe, pinned: String): Boolean =
    !self.signingCertSha256().equals(pinned, ignoreCase = true)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "*SecuritySignalsTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add client-android/app/src
git commit -m "feat: security signal logic (root, hooking, emulator, apk signature)"
```

---

## Task 7: System-signal logic (packages, overlay, accessibility) + SignalAggregator

**Files:**
- Create: `app/src/main/java/com/anticheat/client/signals/PackagesLogic.kt`, `.../signals/OverlayLogic.kt`, `.../signals/AccessibilityLogic.kt`, `.../signals/SignalAggregator.kt`, and add `PackageProbe`, `SettingsProbe`, `ObscuredTouchProbe` to `probes/Probes.kt`
- Test: `app/src/test/java/com/anticheat/client/signals/SystemSignalsTest.kt`, `.../signals/SignalAggregatorTest.kt`

**Interfaces:**
- Consumes: probes + all `detect*` functions + `SignalSet` model.
- Produces:
  - `interface PackageProbe { fun installedFrom(candidates:List<String>): List<String> }`, `fun interface SettingsProbe { fun enabledAccessibilityServices(): String }`, `fun interface ObscuredTouchProbe { fun sawObscuredTouch(): Boolean }`.
  - `fun detectSuspiciousAccessibility(s:SettingsProbe, systemPrefixes:List<String>):Boolean`, `fun detectOverlay(o:ObscuredTouchProbe):Boolean`, `fun collectPackages(p:PackageProbe, candidates:List<String>):List<String>`.
  - `class SignalAggregator(...probes..., pinnedCert:String, knownCheatPackages:List<String>) { fun collect(): SignalSet }`.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.*
import org.junit.Assert.*
import org.junit.Test
class SystemSignalsTest {
    @Test fun accessibilityFlaggedForNonSystemService() {
        val s = SettingsProbe { "com.evil/.Svc:com.android.talkback/.Svc" }
        assertTrue(detectSuspiciousAccessibility(s, listOf("com.android.", "com.google.android.")))
    }
    @Test fun accessibilityCleanWhenOnlySystem() {
        val s = SettingsProbe { "com.google.android.marvin/.Svc" }
        assertFalse(detectSuspiciousAccessibility(s, listOf("com.android.", "com.google.android.")))
    }
    @Test fun overlayFromObscuredTouch() {
        assertTrue(detectOverlay { true }); assertFalse(detectOverlay { false })
    }
    @Test fun packagesReportsOnlyInstalledCandidates() {
        val p = object : PackageProbe { override fun installedFrom(c: List<String>) = listOf("com.cheat") }
        assertEquals(listOf("com.cheat"), collectPackages(p, listOf("com.cheat", "com.other")))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "*SystemSignalsTest*"`
Expected: FAIL (unresolved references).

- [ ] **Step 3: Write minimal implementation**

Add to `probes/Probes.kt`:
```kotlin
interface PackageProbe { fun installedFrom(candidates: List<String>): List<String> }
fun interface SettingsProbe { fun enabledAccessibilityServices(): String }
fun interface ObscuredTouchProbe { fun sawObscuredTouch(): Boolean }
```

`PackagesLogic.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.PackageProbe
fun collectPackages(p: PackageProbe, candidates: List<String>): List<String> = p.installedFrom(candidates)
```

`OverlayLogic.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.ObscuredTouchProbe
fun detectOverlay(o: ObscuredTouchProbe): Boolean = o.sawObscuredTouch()
```

`AccessibilityLogic.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.SettingsProbe
fun detectSuspiciousAccessibility(s: SettingsProbe, systemPrefixes: List<String>): Boolean =
    s.enabledAccessibilityServices()
        .split(':').filter { it.isNotBlank() }
        .map { it.substringBefore('/') }
        .any { pkg -> systemPrefixes.none { pkg.startsWith(it) } }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "*SystemSignalsTest*"`
Expected: PASS.

- [ ] **Step 5: Write the SignalAggregator failing test**

```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.probes.*
import org.junit.Assert.*
import org.junit.Test
class SignalAggregatorTest {
    @Test fun buildsCompleteSignalSet() {
        val agg = SignalAggregator(
            fileProbe = FileProbe { it == "/system/bin/su" },
            buildProbe = object : BuildProbe { override val tags="release-keys"; override val fingerprint=""; override val model=""; override val brand=""; override val hardware="goldfish" },
            procMapsProbe = ProcMapsProbe { "" },
            xposedPresent = false,
            selfCertProbe = SelfCertProbe { "AA" },
            settingsProbe = SettingsProbe { "" },
            obscuredTouchProbe = ObscuredTouchProbe { false },
            packageProbe = object : PackageProbe { override fun installedFrom(c: List<String>) = emptyList<String>() },
            pinnedCert = "AA",
            knownCheatPackages = listOf("com.cheat"),
        )
        val s = agg.collect()
        assertEquals(true, s.root?.detected)
        assertEquals(true, s.emulator?.detected)
        assertEquals(false, s.apkSignature?.mismatch)
        assertEquals(emptyList<String>(), s.packages)
    }
}
```

- [ ] **Step 6: Implement SignalAggregator and run both suites**

`SignalAggregator.kt`:
```kotlin
package com.anticheat.client.signals
import com.anticheat.client.signals.model.*
import com.anticheat.client.signals.probes.*
class SignalAggregator(
    private val fileProbe: FileProbe, private val buildProbe: BuildProbe,
    private val procMapsProbe: ProcMapsProbe, private val xposedPresent: Boolean,
    private val selfCertProbe: SelfCertProbe, private val settingsProbe: SettingsProbe,
    private val obscuredTouchProbe: ObscuredTouchProbe, private val packageProbe: PackageProbe,
    private val pinnedCert: String, private val knownCheatPackages: List<String>,
) {
    private val systemPrefixes = listOf("com.android.", "com.google.android.")
    fun collect(): SignalSet {
        val (frida, xposed) = detectHooking(procMapsProbe, xposedPresent)
        return SignalSet(
            root = RootSignal(detectRoot(fileProbe, buildProbe)),
            hooking = HookingSignal(frida = frida, xposed = xposed),
            packages = collectPackages(packageProbe, knownCheatPackages),
            emulator = EmulatorSignal(detectEmulator(buildProbe)),
            overlay = OverlaySignal(detectOverlay(obscuredTouchProbe)),
            accessibility = AccessibilitySignal(detectSuspiciousAccessibility(settingsProbe, systemPrefixes)),
            apkSignature = ApkSignatureSignal(detectApkMismatch(selfCertProbe, pinnedCert)),
        )
    }
}
```

Run: `./gradlew :app:testDebugUnitTest --tests "*SystemSignalsTest*" --tests "*SignalAggregatorTest*"`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add client-android/app/src
git commit -m "feat: system signal logic + SignalAggregator"
```

---

## Task 8: VerificationOrchestrator + DeviceStore + state model

**Files:**
- Create: `app/src/main/java/com/anticheat/client/session/DeviceStore.kt`, `.../session/VerificationState.kt`, `.../session/VerificationOrchestrator.kt`
- Test: `app/src/test/java/com/anticheat/client/session/VerificationOrchestratorTest.kt`

**Interfaces:**
- Consumes: `AntiCheatApi`, `SigningKey`, `SignalAggregator` (as a `() -> SignalSet` provider to stay JVM-testable), `PayloadBuilder`, `DeviceStore`.
- Produces:
  - `interface DeviceStore { suspend fun getDeviceId(): String?; suspend fun setDeviceId(id: String) }`.
  - `sealed interface VerificationState { Idle; Running(step:String, progress:Float); Done(verdict:String?, status:String, flags:List<FlagDto>, sessionId:String); Error(code:String, message:String) }`.
  - `class VerificationOrchestrator(api, key, store, signalsProvider:()->SignalSet, clock:()->Long = System::currentTimeMillis, snapshotCount:Int = 6) { fun state: StateFlow<VerificationState>; suspend fun run() }`. Enrolls if needed, starts, loops `snapshotCount` snapshots advancing the nonce, ends, exposes final verdict. `run()` does NOT sleep between snapshots (interval delay is the caller/UI concern) so tests are fast.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.anticheat.client.session
import com.anticheat.client.net.AntiCheatApi
import com.anticheat.client.net.dto.*
import com.anticheat.client.crypto.JvmSigningKey
import com.anticheat.client.signals.model.SignalSet
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
class VerificationOrchestratorTest {
    private class FakeApi : AntiCheatApi {
        var snapshotNonces = mutableListOf<String>()
        override suspend fun enroll(body: EnrollRequest) = EnrollResponse("dev-1", "t")
        override suspend fun startSession(body: StartRequest) = StartResponse("sess-1", "n0", 10, 2, 1)
        override suspend fun snapshot(id: String, body: SnapshotRequest): SnapshotResponse {
            // record the nonce the client signed by decoding payload is out of scope here; assert count
            snapshotNonces.add(body.signatureB64.take(0) + "x")
            return SnapshotResponse(true, "n${snapshotNonces.size}", body.let { 0 })
        }
        override suspend fun endSession(id: String, body: EndRequest) = EndResponse("sess-1", "COMPLETE", "CLEAN", emptyList())
        override suspend fun verdict(id: String) = VerdictResponse("sess-1", "COMPLETE", "CLEAN")
    }
    private class MemStore : DeviceStore {
        private var id: String? = null
        override suspend fun getDeviceId() = id
        override suspend fun setDeviceId(id: String) { this.id = id }
    }
    @Test fun runsFullCycleAndReportsVerdict() = runTest {
        val api = FakeApi()
        val orch = VerificationOrchestrator(api, JvmSigningKey(), MemStore(),
            signalsProvider = { SignalSet() }, clock = { 0L }, snapshotCount = 3)
        orch.run()
        val state = orch.state.value
        assertTrue(state is VerificationState.Done)
        state as VerificationState.Done
        assertEquals("CLEAN", state.verdict)
        assertEquals(3, api.snapshotNonces.size)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "*VerificationOrchestratorTest*"`
Expected: FAIL (unresolved references).

- [ ] **Step 3: Write minimal implementation**

`DeviceStore.kt`:
```kotlin
package com.anticheat.client.session
interface DeviceStore {
    suspend fun getDeviceId(): String?
    suspend fun setDeviceId(id: String)
}
```

`VerificationState.kt`:
```kotlin
package com.anticheat.client.session
import com.anticheat.client.net.dto.FlagDto
sealed interface VerificationState {
    data object Idle : VerificationState
    data class Running(val step: String, val progress: Float) : VerificationState
    data class Done(val verdict: String?, val status: String, val flags: List<FlagDto>, val sessionId: String) : VerificationState
    data class Error(val code: String, val message: String) : VerificationState
}
```

`VerificationOrchestrator.kt`:
```kotlin
package com.anticheat.client.session
import com.anticheat.client.crypto.SigningKey
import com.anticheat.client.net.AntiCheatApi
import com.anticheat.client.net.dto.*
import com.anticheat.client.signals.model.SignalSet
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.time.Instant

class VerificationOrchestrator(
    private val api: AntiCheatApi,
    private val key: SigningKey,
    private val store: DeviceStore,
    private val signalsProvider: () -> SignalSet,
    private val clock: () -> Long = System::currentTimeMillis,
    private val snapshotCount: Int = 6,
) {
    private val _state = MutableStateFlow<VerificationState>(VerificationState.Idle)
    val state: StateFlow<VerificationState> = _state
    private fun iso() = Instant.ofEpochMilli(clock()).toString()

    suspend fun run() {
        try {
            _state.value = VerificationState.Running("Enrolando dispositivo", 0.1f)
            val deviceId = store.getDeviceId() ?: run {
                val chain = key.attestationChainB64()
                val att = if (chain.isNotEmpty()) AttestationDto("ANDROID_KEY_ATTESTATION", chain) else null
                val id = api.enroll(EnrollRequest(publicKey = key.publicKeySpkiB64(), attestation = att)).deviceId
                store.setDeviceId(id); id
            }
            _state.value = VerificationState.Running("Iniciando sesión", 0.2f)
            val ts0 = iso()
            val start = api.startSession(StartRequest(deviceId, ts0, key.sign("$deviceId$ts0".toByteArray())))
            var nonce = start.nonce
            for (seq in 0 until snapshotCount) {
                _state.value = VerificationState.Running("Snapshot ${seq + 1}/$snapshotCount", 0.2f + 0.6f * (seq + 1) / snapshotCount)
                val payload = SnapshotPayload(deviceId, start.sessionId, seq, nonce, iso(), signals = signalsProvider())
                val body = PayloadBuilder.build(key, payload, integrityToken = null)
                val res = api.snapshot(start.sessionId, SnapshotRequest(body.payloadB64, body.signatureB64, null))
                nonce = res.nextNonce
            }
            _state.value = VerificationState.Running("Cerrando sesión", 0.9f)
            val tsEnd = iso()
            val end = api.endSession(start.sessionId, EndRequest(tsEnd, key.sign("${start.sessionId}$tsEnd".toByteArray())))
            _state.value = VerificationState.Done(end.verdict, end.status, end.flags, end.sessionId)
        } catch (e: retrofit2.HttpException) {
            _state.value = VerificationState.Error("HTTP_${e.code()}", e.message())
        } catch (e: Exception) {
            _state.value = VerificationState.Error("CLIENT_ERROR", e.message ?: "error")
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "*VerificationOrchestratorTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add client-android/app/src
git commit -m "feat: verification orchestrator state machine + device store"
```

---

## Task 9: Android platform implementations (Keystore + probes + DataStore)

**Files:**
- Create: `app/src/main/java/com/anticheat/client/crypto/KeystoreSigningKey.kt`, `.../signals/AndroidProbes.kt`, `.../session/DataStoreDeviceStore.kt`
- Test: none automated (requires a device/emulator). Verified via Task 11 manual e2e.

**Interfaces:**
- Consumes: `SigningKey`, all probe interfaces, `DeviceStore`.
- Produces: `KeystoreSigningKey(context, challenge:ByteArray)` implementing `SigningKey` via Android Keystore; Android probe implementations; `DataStoreDeviceStore(context)`.

- [ ] **Step 1: Implement KeystoreSigningKey**

`KeystoreSigningKey.kt`:
```kotlin
package com.anticheat.client.crypto
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.Certificate

class KeystoreSigningKey(private val challenge: ByteArray) : SigningKey {
    private val alias = "anticheat_device_key"
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    init { if (!ks.containsAlias(alias)) generate() }

    private fun generate() {
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
        try { spec.setIsStrongBoxBacked(true); gen.initialize(spec.build()); gen.generateKeyPair() }
        catch (e: Exception) { spec.setIsStrongBoxBacked(false); gen.initialize(spec.build()); gen.generateKeyPair() }
    }

    override fun publicKeySpkiB64(): String =
        CryptoUtil.base64(ks.getCertificate(alias).publicKey.encoded)

    override fun sign(payload: ByteArray): String {
        val entry = ks.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(entry.privateKey); s.update(payload)
        return CryptoUtil.base64(s.sign())
    }

    override fun attestationChainB64(): List<String> =
        (ks.getCertificateChain(alias) ?: arrayOf<Certificate>()).map { CryptoUtil.base64(it.encoded) }
}
```

- [ ] **Step 2: Implement AndroidProbes**

`AndroidProbes.kt`:
```kotlin
package com.anticheat.client.signals
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.anticheat.client.signals.probes.*
import java.io.File

fun androidFileProbe() = FileProbe { File(it).exists() }
fun androidBuildProbe() = object : BuildProbe {
    override val tags = Build.TAGS ?: ""
    override val fingerprint = Build.FINGERPRINT ?: ""
    override val model = Build.MODEL ?: ""
    override val brand = Build.BRAND ?: ""
    override val hardware = Build.HARDWARE ?: ""
}
fun androidProcMapsProbe() = ProcMapsProbe { runCatching { File("/proc/self/maps").readText() }.getOrDefault("") }
fun androidSettingsProbe(ctx: Context) = SettingsProbe {
    Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
}
fun androidPackageProbe(ctx: Context) = object : PackageProbe {
    override fun installedFrom(candidates: List<String>): List<String> = candidates.filter { pkg ->
        runCatching { ctx.packageManager.getPackageInfo(pkg, 0); true }.getOrDefault(false)
    }
}
fun androidSelfCertProbe(ctx: Context) = SelfCertProbe {
    val sigs = ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        .signingInfo.apkContentsSigners
    val md = java.security.MessageDigest.getInstance("SHA-256")
    sigs.firstOrNull()?.let { md.digest(it.toByteArray()).joinToString("") { b -> "%02x".format(b) } } ?: ""
}
```

- [ ] **Step 3: Implement DataStoreDeviceStore**

`DataStoreDeviceStore.kt`:
```kotlin
package com.anticheat.client.session
import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first

private val Context.dataStore by preferencesDataStore(name = "anticheat")
private val DEVICE_ID = stringPreferencesKey("device_id")

class DataStoreDeviceStore(private val ctx: Context) : DeviceStore {
    override suspend fun getDeviceId(): String? = ctx.dataStore.data.first()[DEVICE_ID]
    override suspend fun setDeviceId(id: String) { ctx.dataStore.edit { it[DEVICE_ID] = id } }
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cd client-android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add client-android/app/src
git commit -m "feat: Android Keystore signing key, probes, and DataStore device store"
```

---

## Task 10: Compose UI + wiring

**Files:**
- Modify: `app/src/main/java/com/anticheat/client/ui/MainActivity.kt`
- Create: `app/src/main/java/com/anticheat/client/ui/MainScreen.kt`, `.../ui/ResultScreen.kt`
- Test: none automated (UI smoke verified manually).

**Interfaces:**
- Consumes: `VerificationOrchestrator`, `VerificationState`, all Android platform impls, `ApiClient`, `BuildConfig`.

- [ ] **Step 1: Wire dependencies + render state in MainActivity**

`MainActivity.kt`:
```kotlin
package com.anticheat.client.ui
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.lifecycleScope
import com.anticheat.client.BuildConfig
import com.anticheat.client.crypto.KeystoreSigningKey
import com.anticheat.client.net.ApiClient
import com.anticheat.client.session.*
import com.anticheat.client.signals.*
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val api = ApiClient.create(BuildConfig.BACKEND_BASE_URL)
        val key = KeystoreSigningKey(challenge = "anticheat".toByteArray())
        val aggregator = SignalAggregator(
            fileProbe = androidFileProbe(), buildProbe = androidBuildProbe(),
            procMapsProbe = androidProcMapsProbe(), xposedPresent = false,
            selfCertProbe = androidSelfCertProbe(this), settingsProbe = androidSettingsProbe(this),
            obscuredTouchProbe = { false }, packageProbe = androidPackageProbe(this),
            pinnedCert = BuildConfig.APK_SIGNING_CERT_SHA256,
            knownCheatPackages = listOf("com.example.knowncheat"),
        )
        val orch = VerificationOrchestrator(api, key, DataStoreDeviceStore(this), aggregator::collect)
        setContent {
            val state by orch.state.collectAsState()
            MainScreen(state = state, onVerify = { lifecycleScope.launch { orch.run() } })
        }
    }
}
```

- [ ] **Step 2: Implement MainScreen + ResultScreen**

`MainScreen.kt`:
```kotlin
package com.anticheat.client.ui
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.anticheat.client.session.VerificationState

@Composable
fun MainScreen(state: VerificationState, onVerify: () -> Unit) {
    Surface {
        Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Verificación Anti-Cheat", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(24.dp))
            when (state) {
                is VerificationState.Idle -> Button(onClick = onVerify) { Text("Verificar") }
                is VerificationState.Running -> { LinearProgressIndicator(progress = { state.progress }); Text(state.step) }
                is VerificationState.Done -> ResultScreen(state)
                is VerificationState.Error -> Text("Error ${state.code}: ${state.message}")
            }
        }
    }
}
```

`ResultScreen.kt`:
```kotlin
package com.anticheat.client.ui
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.anticheat.client.BuildConfig
import com.anticheat.client.session.VerificationState

@Composable
fun ResultScreen(state: VerificationState.Done) {
    Column {
        Text("Veredicto: ${state.verdict ?: state.status}", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        state.flags.forEach { Text("• ${it.type} (${it.severity})") }
        Spacer(Modifier.height(16.dp))
        val verifyUrl = "${BuildConfig.BACKEND_BASE_URL}sessions/${state.sessionId}/verdict"
        Text("Verificar en el servidor:")
        Text(verifyUrl, style = MaterialTheme.typography.bodySmall)
        // QR rendering of verifyUrl is a follow-up; the URL alone is already server-verifiable.
    }
}
```

- [ ] **Step 3: Verify it builds**

Run: `cd client-android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add client-android/app/src
git commit -m "feat: Compose UI wiring the verification flow"
```

---

## Task 11: Interval pacing, README, and live-backend interop verification

**Files:**
- Modify: `app/src/main/java/com/anticheat/client/ui/MainActivity.kt` (add interval delay between snapshots via the UI coroutine)
- Create: `client-android/README.md`

**Interfaces:**
- Consumes: `StartResponse.expectedIntervalSec`/`jitterSec` (currently the orchestrator loops without delay; real pacing happens here for the on-device run).

- [ ] **Step 1: Add real interval pacing on-device**

The orchestrator stays delay-free for fast tests. For the on-device run, pace snapshots by injecting a suspend delay. Add an optional `betweenSnapshots: suspend (Int) -> Unit = {}` parameter to `VerificationOrchestrator.run()` and call it after each snapshot; in `MainActivity` pass `{ delay(start.expectedIntervalSec * 1000L) }` equivalent. Minimal change: add the parameter with a no-op default and invoke it inside the loop.

Edit `VerificationOrchestrator.run()` signature to `suspend fun run(betweenSnapshots: suspend (Int) -> Unit = {})` and add `betweenSnapshots(seq)` as the last line inside the `for` loop. Re-run `*VerificationOrchestratorTest*` to confirm the default no-op keeps it green.

Run: `./gradlew :app:testDebugUnitTest --tests "*VerificationOrchestratorTest*"`
Expected: PASS.

- [ ] **Step 2: Write the README**

`client-android/README.md` must document:
- Prereqs: Android SDK, JDK 17, an emulator or device (minSdk 26).
- Point the app at the backend: emulator uses `http://10.0.2.2:3000/`; a physical device needs the machine's LAN IP in `BACKEND_BASE_URL`.
- How to run the backend locally (`npm run start:dev`, Postgres on 5435 per project env).
- Manual interop e2e: start backend → launch app → tap Verificar → expect a verdict; then open `GET /sessions/:id/verdict` in a browser and confirm it matches. This is the real cross-stack proof that Android Keystore ECDSA/DER signatures are accepted by the Node backend.
- Note: `usesCleartextTraffic` is for local dev only; production needs HTTPS + cert pinning.
- Note: keep `<queries>` and `knownCheatPackages` in sync with the server blacklist per release.

- [ ] **Step 3: Verify build + full unit suite green**

Run: `cd client-android && ./gradlew :app:testDebugUnitTest`
Expected: all unit tests PASS.

- [ ] **Step 4: Commit**

```bash
git add client-android
git commit -m "docs: client-android README + on-device interval pacing"
```

---

## Self-Review Notes

- **Spec coverage:** §1 use model → Tasks 8/10; §3 crypto/keys → Tasks 3/9; §5 signals → model Task 2, logic Tasks 6/7, Android probes Task 9; §7 orchestration → Task 8; §8 result/verification → Task 10; §9 networking → Task 5; §10 repo/build → Task 1; §11 testing → embedded per task + live e2e Task 11. Play Integrity deferred (integrityToken null) honored in Tasks 4/8.
- **Interop proof:** the automated gate is Task 3 (standard ECDSA verify over exported SPKI + DER = exactly Node's `crypto.verify`); the live cross-stack proof is Task 11 manual e2e.
- **Type consistency:** `SigningKey.sign(ByteArray):String`, `publicKeySpkiB64():String`, `attestationChainB64():List<String>` used identically across Tasks 3/4/8/9. DTO names in Task 5 match usages in Task 8. `SignalSet` shape from Task 2 matches `SignalAggregator` output in Task 7 and backend contract.
- **Known simplification:** QR rendering is deferred (Task 10 shows the verifiable URL text); the URL is already server-verifiable, so this does not block the MVP definition of done.
```

