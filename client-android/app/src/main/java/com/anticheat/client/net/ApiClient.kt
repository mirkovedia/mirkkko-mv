package com.anticheat.client.net
import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import retrofit2.Retrofit
object ApiClient {
    fun create(baseUrl: String): AntiCheatApi {
        // encodeDefaults = true es obligatorio: sin el, kotlinx.serialization omite los
        // campos que solo tienen valor por defecto (platform, keyAlgo) y el backend responde
        // 400 porque platform es requerido. explicitNulls = false mantiene fuera los nulos.
        val json = Json { ignoreUnknownKeys = true; explicitNulls = false; encodeDefaults = true }
        return Retrofit.Builder().baseUrl(baseUrl)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build().create(AntiCheatApi::class.java)
    }
}
