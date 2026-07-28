import { Injectable } from '@nestjs/common';
import type {
  AttestationInput,
  AttestationVerifier,
  IntegrityResult,
} from './attestation-verifier.interface';
import type { IntegrityVerdict } from '../verdict/types';

// Forma parcial del payload decodificado de Play Integrity que nos interesa.
interface DecodedToken {
  requestDetails?: { nonce?: string };
  deviceIntegrity?: { deviceRecognitionVerdict?: string[] };
}

@Injectable()
export class GooglePlayIntegrityVerifier implements AttestationVerifier {
  // Mapeo puro (testeable con fixtures) del token decodificado a nuestro veredicto.
  mapDecodedToken(decoded: unknown, expectedNonce: string): IntegrityResult {
    const token = decoded as DecodedToken;
    const now = new Date();

    // El nonce del token debe coincidir con el nonce de servidor (anti-replay).
    if (token.requestDetails?.nonce !== expectedNonce) {
      return { verdict: 'FAILED', raw: decoded, evaluatedAt: now };
    }
    const labels = token.deviceIntegrity?.deviceRecognitionVerdict ?? [];
    let verdict: IntegrityVerdict = 'FAILED';
    if (labels.includes('MEETS_STRONG_INTEGRITY')) verdict = 'MEETS_STRONG';
    else if (labels.includes('MEETS_DEVICE_INTEGRITY')) verdict = 'MEETS_DEVICE';
    else if (labels.includes('MEETS_BASIC_INTEGRITY')) verdict = 'MEETS_BASIC';
    // labels vacío → FAILED (device no alcanzó integridad).
    return { verdict, raw: decoded, evaluatedAt: now };
  }

  async verify(input: AttestationInput): Promise<IntegrityResult> {
    if (input.token === null)
      return { verdict: 'DEGRADED', evaluatedAt: new Date() };
    // NOTA (prod): aquí va la llamada real a Google
    // (googleapis playintegrity.v1.decodeIntegrityToken con el service account).
    // Se deja lanzar si falla para que el llamador la trate como DEGRADED.
    const decoded = await this.decodeWithGoogle(input.token);
    return this.mapDecodedToken(decoded, input.nonce);
  }

  // Placeholder de red — implementación real requiere GOOGLE_APPLICATION_CREDENTIALS.
  private async decodeWithGoogle(_token: string): Promise<unknown> {
    throw new Error(
      'GooglePlayIntegrityVerifier.decodeWithGoogle no configurado (falta service account)',
    );
  }
}
