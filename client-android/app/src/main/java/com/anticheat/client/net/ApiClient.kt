package com.anticheat.client.net
import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import retrofit2.Retrofit
object ApiClient {
    fun create(baseUrl: String): AntiCheatApi {
        val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
        return Retrofit.Builder().baseUrl(baseUrl)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build().create(AntiCheatApi::class.java)
    }
}
