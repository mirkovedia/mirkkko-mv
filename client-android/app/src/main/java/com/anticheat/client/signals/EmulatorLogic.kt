package com.anticheat.client.signals
import com.anticheat.client.signals.probes.BuildProbe
private val EMU_HW = listOf("goldfish","ranchu","vbox86")
fun detectEmulator(b: BuildProbe): Boolean =
    EMU_HW.any { b.hardware.contains(it, true) } ||
    b.fingerprint.contains("generic", true) || b.model.contains("emulator", true)
