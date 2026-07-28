import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ATTESTATION_VERIFIER } from './attestation-verifier.interface';
import { StubAttestationVerifier } from './stub-attestation.verifier';
import { GooglePlayIntegrityVerifier } from './google-play-integrity.verifier';
import type { Env } from '../config/env.schema';

@Global()
@Module({
  providers: [
    StubAttestationVerifier,
    GooglePlayIntegrityVerifier,
    {
      provide: ATTESTATION_VERIFIER,
      inject: [ConfigService, StubAttestationVerifier, GooglePlayIntegrityVerifier],
      useFactory: (
        config: ConfigService<Env, true>,
        stub: StubAttestationVerifier,
        google: GooglePlayIntegrityVerifier,
      ) =>
        config.get('ATTESTATION_PROVIDER', { infer: true }) === 'google'
          ? google
          : stub,
    },
  ],
  exports: [ATTESTATION_VERIFIER],
})
export class AttestationModule {}
