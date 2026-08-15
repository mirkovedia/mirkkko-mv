package com.anticheat.client.session
import com.anticheat.client.crypto.SigningKey
import com.anticheat.client.net.AntiCheatApi
import com.anticheat.client.net.dto.*
import com.anticheat.client.signals.model.SignalSet
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.time.Instant

class VerificationOrchestrator(
    private val api: AntiCheatApi,
    private val key: SigningKey,
    private val store: DeviceStore,
    private val signalsProvider: () -> SignalSet,
    private val clock: () -> Long = System::currentTimeMillis,
    private val snapshotCount: Int = 6,
) {
    private val _state = MutableStateFlow<VerificationState>(VerificationState.Idle)
    val state: StateFlow<VerificationState> = _state
    private fun iso() = Instant.ofEpochMilli(clock()).toString()

    suspend fun run(betweenSnapshots: suspend (Int) -> Unit = {}) {
        try {
            _state.value = VerificationState.Running("Enrolando dispositivo", 0.1f)
            val deviceId = store.getDeviceId() ?: kotlin.run {
                val chain = key.attestationChainB64()
                val att = if (chain.isNotEmpty()) AttestationDto("ANDROID_KEY_ATTESTATION", chain) else null
                val id = api.enroll(EnrollRequest(publicKey = key.publicKeySpkiB64(), attestation = att)).deviceId
                store.setDeviceId(id); id
            }
            _state.value = VerificationState.Running("Iniciando sesión", 0.2f)
            val ts0 = iso()
            val start = api.startSession(StartRequest(deviceId, ts0, key.sign("$deviceId$ts0".toByteArray())))
            var nonce = start.nonce
            for (seq in 0 until snapshotCount) {
                _state.value = VerificationState.Running("Snapshot ${seq + 1}/$snapshotCount", 0.2f + 0.6f * (seq + 1) / snapshotCount)
                val payload = SnapshotPayload(deviceId, start.sessionId, seq, nonce, iso(), signals = signalsProvider())
                val body = PayloadBuilder.build(key, payload, integrityToken = null)
                val res = api.snapshot(start.sessionId, SnapshotRequest(body.payloadB64, body.signatureB64, null))
                nonce = res.nextNonce
                betweenSnapshots(seq)
            }
            _state.value = VerificationState.Running("Cerrando sesión", 0.9f)
            val tsEnd = iso()
            val end = api.endSession(start.sessionId, EndRequest(tsEnd, key.sign("${start.sessionId}$tsEnd".toByteArray())))
            _state.value = VerificationState.Done(end.verdict, end.status, end.flags, end.sessionId)
        } catch (e: retrofit2.HttpException) {
            _state.value = VerificationState.Error("HTTP_${e.code()}", e.message())
        } catch (e: Exception) {
            _state.value = VerificationState.Error("CLIENT_ERROR", e.message ?: "error")
        }
    }
}
