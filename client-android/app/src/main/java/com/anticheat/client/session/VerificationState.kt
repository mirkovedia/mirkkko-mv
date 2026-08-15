package com.anticheat.client.session
import com.anticheat.client.net.dto.FlagDto
sealed interface VerificationState {
    data object Idle : VerificationState
    data class Running(val step: String, val progress: Float) : VerificationState
    data class Done(val verdict: String?, val status: String, val flags: List<FlagDto>, val sessionId: String) : VerificationState
    data class Error(val code: String, val message: String) : VerificationState
}
