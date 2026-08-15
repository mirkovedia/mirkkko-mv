package com.anticheat.client.signals
import com.anticheat.client.signals.probes.SelfCertProbe
fun detectApkMismatch(self: SelfCertProbe, pinned: String): Boolean =
    !self.signingCertSha256().equals(pinned, ignoreCase = true)
