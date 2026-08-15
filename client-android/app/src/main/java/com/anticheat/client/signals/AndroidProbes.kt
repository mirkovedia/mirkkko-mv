package com.anticheat.client.signals
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.anticheat.client.signals.probes.*
import java.io.File

fun androidFileProbe() = FileProbe { File(it).exists() }
fun androidBuildProbe() = object : BuildProbe {
    override val tags = Build.TAGS ?: ""
    override val fingerprint = Build.FINGERPRINT ?: ""
    override val model = Build.MODEL ?: ""
    override val brand = Build.BRAND ?: ""
    override val hardware = Build.HARDWARE ?: ""
}
fun androidProcMapsProbe() = ProcMapsProbe { runCatching { File("/proc/self/maps").readText() }.getOrDefault("") }
fun androidSettingsProbe(ctx: Context) = SettingsProbe {
    Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
}
fun androidPackageProbe(ctx: Context) = object : PackageProbe {
    override fun installedFrom(candidates: List<String>): List<String> = candidates.filter { pkg ->
        runCatching { ctx.packageManager.getPackageInfo(pkg, 0); true }.getOrDefault(false)
    }
}
fun androidSelfCertProbe(ctx: Context) = SelfCertProbe {
    val sigs = ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        .signingInfo.apkContentsSigners
    val md = java.security.MessageDigest.getInstance("SHA-256")
    sigs.firstOrNull()?.let { md.digest(it.toByteArray()).joinToString("") { b -> "%02x".format(b) } } ?: ""
}
