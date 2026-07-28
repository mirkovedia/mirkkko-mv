import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  AttestationInput,
  AttestationVerifier,
  IntegrityResult,
} from './attestation-verifier.interface';
import type { Env } from '../config/env.schema';
import type { IntegrityVerdict } from '../verdict/types';

@Injectable()
export class StubAttestationVerifier implements AttestationVerifier {
  constructor(private readonly config: ConfigService<Env, true>) {}

  async verify(input: AttestationInput): Promise<IntegrityResult> {
    // Sin token no se pudo atestar → DEGRADED (nunca se descarta el snapshot).
    if (input.token === null)
      return { verdict: 'DEGRADED', evaluatedAt: new Date() };
    const verdict = this.config.get('ATTESTATION_STUB_VERDICT', {
      infer: true,
    }) as IntegrityVerdict;
    return { verdict, evaluatedAt: new Date() };
  }
}
