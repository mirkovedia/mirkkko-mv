package com.anticheat.client.session
interface DeviceStore {
    suspend fun getDeviceId(): String?
    suspend fun setDeviceId(id: String)
}
