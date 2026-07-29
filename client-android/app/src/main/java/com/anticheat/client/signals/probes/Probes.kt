package com.anticheat.client.signals.probes
fun interface FileProbe { fun exists(path: String): Boolean }
interface BuildProbe { val tags:String; val fingerprint:String; val model:String; val brand:String; val hardware:String }
fun interface SelfCertProbe { fun signingCertSha256(): String }
fun interface ProcMapsProbe { fun selfMaps(): String }
interface PackageProbe { fun installedFrom(candidates: List<String>): List<String> }
fun interface SettingsProbe { fun enabledAccessibilityServices(): String }
fun interface ObscuredTouchProbe { fun sawObscuredTouch(): Boolean }
