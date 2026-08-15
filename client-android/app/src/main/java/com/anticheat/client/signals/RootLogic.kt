package com.anticheat.client.signals
import com.anticheat.client.signals.probes.BuildProbe
import com.anticheat.client.signals.probes.FileProbe
private val SU_PATHS = listOf("/system/bin/su","/system/xbin/su","/sbin/su","/system/app/Superuser.apk","/data/adb/magisk")
fun detectRoot(f: FileProbe, b: BuildProbe): Boolean =
    b.tags.contains("test-keys") || SU_PATHS.any { f.exists(it) }
