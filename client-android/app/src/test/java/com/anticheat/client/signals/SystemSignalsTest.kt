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
