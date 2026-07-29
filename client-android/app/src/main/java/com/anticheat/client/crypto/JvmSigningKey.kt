package com.anticheat.client.crypto
import java.security.*
import java.security.spec.ECGenParameterSpec
class JvmSigningKey(keyPair: KeyPair? = null) : SigningKey {
    private val kp: KeyPair = keyPair ?: KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    override fun publicKeySpkiB64(): String = CryptoUtil.base64(kp.public.encoded) // X.509 SPKI DER
    override fun sign(payload: ByteArray): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(kp.private); s.update(payload)
        return CryptoUtil.base64(s.sign()) // DER
    }
    override fun attestationChainB64(): List<String> = emptyList()
}
