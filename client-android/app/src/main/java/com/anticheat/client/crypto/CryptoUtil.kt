package com.anticheat.client.crypto
import java.security.MessageDigest
import java.util.Base64
object CryptoUtil {
    fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes) // standard, padded, no wrap
    fun sha256Hex(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
