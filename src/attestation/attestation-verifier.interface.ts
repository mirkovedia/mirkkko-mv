import type { IntegrityVerdict, Platform } from '../verdict/types';

export interface AttestationInput {
  token: string | null;
  nonce: string;
  platform: Platform;
}

export interface IntegrityResult {
  verdict: IntegrityVerdict;
  raw?: unknown;
  evaluatedAt: Date;
}

export interface AttestationVerifier {
  verify(input: AttestationInput): Promise<IntegrityResult>;
}

// Token de inyección para el provider (Ports & Adapters).
export const ATTESTATION_VERIFIER = Symbol('ATTESTATION_VERIFIER');
