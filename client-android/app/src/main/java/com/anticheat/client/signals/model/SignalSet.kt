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
