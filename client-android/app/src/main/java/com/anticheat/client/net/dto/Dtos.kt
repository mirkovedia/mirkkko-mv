package com.anticheat.client.net.dto
import kotlinx.serialization.Serializable
@Serializable data class AttestationDto(val type: String, val certificateChain: List<String>? = null)
@Serializable data class EnrollRequest(val publicKey: String, val platform: String = "ANDROID",
    val keyAlgo: String = "ES256", val attestation: AttestationDto? = null)
@Serializable data class EnrollResponse(val deviceId: String, val createdAt: String)
@Serializable data class StartRequest(val deviceId: String, val clientTimestamp: String, val signatureB64: String)
@Serializable data class StartResponse(val sessionId: String, val nonce: String,
    val expectedIntervalSec: Int, val jitterSec: Int, val blacklistVersion: Int)
@Serializable data class SnapshotRequest(val payloadB64: String, val signatureB64: String, val integrityToken: String? = null)
@Serializable data class SnapshotResponse(val accepted: Boolean, val nextNonce: String, val seq: Int)
@Serializable data class EndRequest(val clientTimestamp: String, val signatureB64: String)
@Serializable data class FlagDto(val type: String, val severity: String)
@Serializable data class EndResponse(val sessionId: String, val status: String, val verdict: String? = null, val flags: List<FlagDto> = emptyList())
@Serializable data class VerdictResponse(val sessionId: String, val status: String, val verdict: String? = null)
