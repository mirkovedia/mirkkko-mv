package com.anticheat.client.crypto
interface SigningKey {
    fun publicKeySpkiB64(): String
    fun sign(payload: ByteArray): String
    fun attestationChainB64(): List<String>
}
