package com.anticheat.client.session
import com.anticheat.client.crypto.CryptoUtil
import com.anticheat.client.crypto.SigningKey
import com.anticheat.client.signals.model.AntiCheatJson
object PayloadBuilder {
    fun build(key: SigningKey, payload: SnapshotPayload, integrityToken: String?): SnapshotBody {
        val enriched = if (integrityToken != null)
            payload.copy(integrityTokenHash = CryptoUtil.sha256Hex(integrityToken)) else payload
        val bytes = AntiCheatJson.encodeToString(SnapshotPayload.serializer(), enriched)
            .toByteArray(Charsets.UTF_8)
        return SnapshotBody(CryptoUtil.base64(bytes), key.sign(bytes), integrityToken)
    }
}
