package com.anticheat.client.session
import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first

private val Context.dataStore by preferencesDataStore(name = "anticheat")
private val DEVICE_ID = stringPreferencesKey("device_id")

class DataStoreDeviceStore(private val ctx: Context) : DeviceStore {
    override suspend fun getDeviceId(): String? = ctx.dataStore.data.first()[DEVICE_ID]
    override suspend fun setDeviceId(id: String) { ctx.dataStore.edit { it[DEVICE_ID] = id } }
}
