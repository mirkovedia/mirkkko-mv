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
