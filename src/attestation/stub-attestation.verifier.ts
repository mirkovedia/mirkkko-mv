import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  AttestationInput,
  AttestationVerifier,
  IntegrityResult,
} from './attestation-verifier.interface';
import type { Env } from '../config/env.schema';

@Injectable()
export class StubAttestationVerifier implements AttestationVerifier {
  constructor(private readonly config: ConfigService<Env, true>) {}

  // No hace I/O real; devuelve una promesa resuelta para cumplir la interfaz.
  verify(input: AttestationInput): Promise<IntegrityResult> {
    // Sin token no se pudo atestar → DEGRADED (nunca se descarta el snapshot).
    if (input.token === null)
      return Promise.resolve({ verdict: 'DEGRADED', evaluatedAt: new Date() });
    const verdict = this.config.get('ATTESTATION_STUB_VERDICT', {
      infer: true,
    });
    return Promise.resolve({ verdict, evaluatedAt: new Date() });
  }
}
