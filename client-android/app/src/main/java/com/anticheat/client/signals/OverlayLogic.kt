package com.anticheat.client.signals
import com.anticheat.client.signals.probes.ObscuredTouchProbe
fun detectOverlay(o: ObscuredTouchProbe): Boolean = o.sawObscuredTouch()
