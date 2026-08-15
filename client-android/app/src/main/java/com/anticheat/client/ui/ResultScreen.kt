package com.anticheat.client.ui
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.anticheat.client.BuildConfig
import com.anticheat.client.session.VerificationState

@Composable
fun ResultScreen(state: VerificationState.Done) {
    Column {
        Text("Veredicto: ${state.verdict ?: state.status}", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        state.flags.forEach { Text("• ${it.type} (${it.severity})") }
        Spacer(Modifier.height(16.dp))
        val verifyUrl = "${BuildConfig.BACKEND_BASE_URL}sessions/${state.sessionId}/verdict"
        Text("Verificar en el servidor:")
        Text(verifyUrl, style = MaterialTheme.typography.bodySmall)
        // QR rendering of verifyUrl is a follow-up; the URL alone is already server-verifiable.
    }
}
