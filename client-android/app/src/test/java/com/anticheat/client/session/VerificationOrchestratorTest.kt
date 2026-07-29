package com.anticheat.client.session
import com.anticheat.client.net.AntiCheatApi
import com.anticheat.client.net.dto.*
import com.anticheat.client.crypto.JvmSigningKey
import com.anticheat.client.signals.model.SignalSet
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
class VerificationOrchestratorTest {
    private class FakeApi : AntiCheatApi {
        var snapshotNonces = mutableListOf<String>()
        override suspend fun enroll(body: EnrollRequest) = EnrollResponse("dev-1", "t")
        override suspend fun startSession(body: StartRequest) = StartResponse("sess-1", "n0", 10, 2, 1)
        override suspend fun snapshot(id: String, body: SnapshotRequest): SnapshotResponse {
            // record the nonce the client signed by decoding payload is out of scope here; assert count
            snapshotNonces.add(body.signatureB64.take(0) + "x")
            return SnapshotResponse(true, "n${snapshotNonces.size}", body.let { 0 })
        }
        override suspend fun endSession(id: String, body: EndRequest) = EndResponse("sess-1", "COMPLETE", "CLEAN", emptyList())
        override suspend fun verdict(id: String) = VerdictResponse("sess-1", "COMPLETE", "CLEAN")
    }
    private class MemStore : DeviceStore {
        private var id: String? = null
        override suspend fun getDeviceId() = id
        override suspend fun setDeviceId(id: String) { this.id = id }
    }
    @Test fun runsFullCycleAndReportsVerdict() = runTest {
        val api = FakeApi()
        val orch = VerificationOrchestrator(api, JvmSigningKey(), MemStore(),
            signalsProvider = { SignalSet() }, clock = { 0L }, snapshotCount = 3)
        orch.run()
        val state = orch.state.value
        assertTrue(state is VerificationState.Done)
        state as VerificationState.Done
        assertEquals("CLEAN", state.verdict)
        assertEquals(3, api.snapshotNonces.size)
    }
}
