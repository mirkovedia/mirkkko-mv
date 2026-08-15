package com.anticheat.client.signals
import com.anticheat.client.signals.probes.PackageProbe
fun collectPackages(p: PackageProbe, candidates: List<String>): List<String> = p.installedFrom(candidates)
