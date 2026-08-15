package com.anticheat.client.net
import com.anticheat.client.net.dto.*
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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

    // Regresion: kotlinx.serialization omite los valores por defecto salvo que se pida
    // encodeDefaults. El backend valida platform con @IsIn(['ANDROID','IOS']) y sin default,
    // asi que omitirlo devuelve 400 en el enrolamiento real.
    @Test fun enrollBodyIncludesFieldsThatOnlyHaveDefaultValues() = runTest {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(
            """{"deviceId":"d1","createdAt":"2026-07-28T00:00:00.000Z"}"""
        ).addHeader("Content-Type", "application/json"))
        server.start()
        val api = ApiClient.create(server.url("/").toString())
        api.enroll(EnrollRequest(publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" + "x".repeat(52)))
        val body = server.takeRequest().body.readUtf8()
        assertTrue("falta platform en $body", body.contains("\"platform\":\"ANDROID\""))
        assertTrue("falta keyAlgo en $body", body.contains("\"keyAlgo\":\"ES256\""))
        server.shutdown()
    }

    // Los campos nulos siguen omitiendose: el backend los trata como ausentes y asi el
    // cuerpo se mantiene minimo.
    @Test fun snapshotBodyOmitsNullIntegrityToken() = runTest {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody(
            """{"accepted":true,"nextNonce":"n1","seq":0}"""
        ).addHeader("Content-Type", "application/json"))
        server.start()
        val api = ApiClient.create(server.url("/").toString())
        api.snapshot("s1", SnapshotRequest("cGF5", "c2ln", null))
        val body = server.takeRequest().body.readUtf8()
        assertFalse("integrityToken no deberia viajar: $body", body.contains("integrityToken"))
        server.shutdown()
    }
}
