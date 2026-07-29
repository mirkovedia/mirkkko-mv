package com.anticheat.client.signals
import com.anticheat.client.signals.probes.ProcMapsProbe
fun detectHooking(maps: ProcMapsProbe, xposedPresent: Boolean): Pair<Boolean, Boolean> {
    val m = maps.selfMaps()
    val frida = m.contains("frida", true) || m.contains("gum-js-loop", true)
    return frida to xposedPresent
}
