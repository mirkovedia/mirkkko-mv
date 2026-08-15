package com.anticheat.client.session
import com.anticheat.client.crypto.JvmSigningKey
import com.anticheat.client.signals.model.RootSignal
import com.anticheat.client.signals.model.SignalSet
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
class PayloadBuilderTest {
    @Test fun signedBytesEqualDecodedPayloadAndVerify() {
        val key = JvmSigningKey()
        val payload = SnapshotPayload(
            deviceId = "d1", sessionId = "s1", seq = 0, nonce = "n0",
            clientTimestamp = "2026-07-28T00:00:00.000Z",
            signals = SignalSet(root = RootSignal(detected = false))
        )
        val body = PayloadBuilder.build(key, payload, integrityToken = null)
        val decoded = Base64.getDecoder().decode(body.payloadB64)
        // signature must verify over the exact decoded bytes
        val pub = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(key.publicKeySpkiB64())))
        val v = Signature.getInstance("SHA256withECDSA"); v.initVerify(pub); v.update(decoded)
        assertTrue(v.verify(Base64.getDecoder().decode(body.signatureB64)))
        assertNull(body.integrityToken)
    }
}
