package com.anticheat.client.net
import com.anticheat.client.net.dto.*
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Test
class AntiCheatApiTest {
    @Test fun startParsesResponseAndPostsBody() = runTest {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(
            """{"sessionId":"s1","nonce":"n0","expectedIntervalSec":10,"jitterSec":2,"blacklistVersion":3}"""
        ).addHeader("Content-Type", "application/json"))
        server.start()
        val api = ApiClient.create(server.url("/").toString())
        val res = api.startSession(StartRequest("d1", "2026-07-28T00:00:00.000Z", "sig"))
        assertEquals("s1", res.sessionId)
        assertEquals(10, res.expectedIntervalSec)
        val recorded = server.takeRequest()
        assertEquals("/sessions/start", recorded.path)
        server.shutdown()
    }
}
