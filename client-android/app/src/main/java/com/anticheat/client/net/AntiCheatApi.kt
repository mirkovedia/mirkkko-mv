package com.anticheat.client.net
import com.anticheat.client.net.dto.*
import retrofit2.http.*
interface AntiCheatApi {
    @POST("devices/enroll") suspend fun enroll(@Body body: EnrollRequest): EnrollResponse
    @POST("sessions/start") suspend fun startSession(@Body body: StartRequest): StartResponse
    @POST("sessions/{id}/snapshot") suspend fun snapshot(@Path("id") id: String, @Body body: SnapshotRequest): SnapshotResponse
    @POST("sessions/{id}/end") suspend fun endSession(@Path("id") id: String, @Body body: EndRequest): EndResponse
    @GET("sessions/{id}/verdict") suspend fun verdict(@Path("id") id: String): VerdictResponse
}
