package com.anticheat.client.crypto
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
class JvmSigningKeyTest {
    // Proves the exported SPKI + DER signature verify with a standard verifier,
    // i.e. exactly what the Node backend does (crypto.verify sha256, spki, der).
    @Test fun signatureVerifiesWithStandardEcdsaOverExportedSpki() {
        val key = JvmSigningKey()
        val payload = """{"hello":"world"}""".toByteArray(Charsets.UTF_8)
        val sigB64 = key.sign(payload)
        val spki = Base64.getDecoder().decode(key.publicKeySpkiB64())
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        val v = Signature.getInstance("SHA256withECDSA")
        v.initVerify(pub); v.update(payload)
        assertTrue(v.verify(Base64.getDecoder().decode(sigB64)))
    }
}
