package com.anticheat.client.ui
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.lifecycleScope
import com.anticheat.client.BuildConfig
import com.anticheat.client.crypto.KeystoreSigningKey
import com.anticheat.client.net.ApiClient
import com.anticheat.client.session.*
import com.anticheat.client.signals.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private const val SNAPSHOT_INTERVAL_MS = 10_000L

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val api = ApiClient.create(BuildConfig.BACKEND_BASE_URL)
        val key = KeystoreSigningKey(challenge = "anticheat".toByteArray())
        val aggregator = SignalAggregator(
            fileProbe = androidFileProbe(), buildProbe = androidBuildProbe(),
            procMapsProbe = androidProcMapsProbe(), xposedPresent = false,
            selfCertProbe = androidSelfCertProbe(this), settingsProbe = androidSettingsProbe(this),
            obscuredTouchProbe = { false }, packageProbe = androidPackageProbe(this),
            pinnedCert = BuildConfig.APK_SIGNING_CERT_SHA256,
            knownCheatPackages = listOf("com.example.knowncheat"),
        )
        val orch = VerificationOrchestrator(api, key, DataStoreDeviceStore(this), aggregator::collect)
        setContent {
            val state by orch.state.collectAsState()
            MainScreen(state = state, onVerify = {
                // Pacing real en dispositivo: espera el intervalo esperado entre snapshots
                // para emular una sesion de juego. Los tests usan el no-op por defecto.
                lifecycleScope.launch { orch.run(betweenSnapshots = { delay(SNAPSHOT_INTERVAL_MS) }) }
            })
        }
    }
}
