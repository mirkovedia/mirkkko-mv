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
