package com.anticheat.client.signals
import com.anticheat.client.signals.model.*
import org.junit.Assert.assertEquals
import org.junit.Test
class SignalSetSerializationTest {
    @Test fun omitsNullFieldsAndSerializesPresentOnes() {
        val s = SignalSet(root = RootSignal(detected = true), packages = listOf("com.x"))
        val json = AntiCheatJson.encodeToString(SignalSet.serializer(), s)
        assertEquals("""{"root":{"detected":true},"packages":["com.x"]}""", json)
    }
}
