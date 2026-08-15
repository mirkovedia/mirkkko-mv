package com.anticheat.client.crypto
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.Certificate

class KeystoreSigningKey(private val challenge: ByteArray) : SigningKey {
    private val alias = "anticheat_device_key"
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    init { if (!ks.containsAlias(alias)) generate() }

    private fun generate() {
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
        try { spec.setIsStrongBoxBacked(true); gen.initialize(spec.build()); gen.generateKeyPair() }
        catch (e: Exception) { spec.setIsStrongBoxBacked(false); gen.initialize(spec.build()); gen.generateKeyPair() }
    }

    override fun publicKeySpkiB64(): String =
        CryptoUtil.base64(ks.getCertificate(alias).publicKey.encoded)

    override fun sign(payload: ByteArray): String {
        val entry = ks.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(entry.privateKey); s.update(payload)
        return CryptoUtil.base64(s.sign())
    }

    override fun attestationChainB64(): List<String> =
        (ks.getCertificateChain(alias) ?: arrayOf<Certificate>()).map { CryptoUtil.base64(it.encoded) }
}
