package com.anticheat.client.session
import com.anticheat.client.signals.model.SignalSet
import kotlinx.serialization.Serializable
@Serializable data class SnapshotPayload(
    val deviceId: String, val sessionId: String, val seq: Int,
    val nonce: String, val clientTimestamp: String,
    val integrityTokenHash: String? = null, val signals: SignalSet,
)
data class SnapshotBody(val payloadB64: String, val signatureB64: String, val integrityToken: String?)
