package com.anticheat.client.ui
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.anticheat.client.session.VerificationState

@Composable
fun MainScreen(state: VerificationState, onVerify: () -> Unit) {
    Surface {
        Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Verificación Anti-Cheat", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(24.dp))
            when (state) {
                is VerificationState.Idle -> Button(onClick = onVerify) { Text("Verificar") }
                is VerificationState.Running -> { LinearProgressIndicator(progress = { state.progress }); Text(state.step) }
                is VerificationState.Done -> ResultScreen(state)
                is VerificationState.Error -> Text("Error ${state.code}: ${state.message}")
            }
        }
    }
}
