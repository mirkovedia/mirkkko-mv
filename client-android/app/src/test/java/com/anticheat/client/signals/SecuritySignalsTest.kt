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
