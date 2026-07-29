package com.anticheat.client.signals
import com.anticheat.client.signals.probes.SettingsProbe
fun detectSuspiciousAccessibility(s: SettingsProbe, systemPrefixes: List<String>): Boolean =
    s.enabledAccessibilityServices()
        .split(':').filter { it.isNotBlank() }
        .map { it.substringBefore('/') }
        .any { pkg -> systemPrefixes.none { pkg.startsWith(it) } }
