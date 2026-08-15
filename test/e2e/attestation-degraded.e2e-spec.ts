import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import {
  ATTESTATION_VERIFIER,
  type AttestationVerifier,
} from '../../src/attestation/attestation-verifier.interface';
import {
  createTestAppWith,
  enrollDevice,
  startSession,
  sendSnapshot,
  endSession,
  type EnrolledSession,
} from './helpers';

// Simula Google caído / timeout / cuota agotada: el verifier siempre lanza.
const throwingVerifier: AttestationVerifier = {
  verify: () => Promise.reject(new Error('play integrity caído')),
};

describe('Atestación DEGRADED (e2e)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    process.env.ATTESTATION_STUB_VERDICT = 'MEETS_STRONG';
    ({ app, server } = await createTestAppWith((b) =>
      b.overrideProvider(ATTESTATION_VERIFIER).useValue(throwingVerifier),
    ));
  });
  afterAll(async () => app.close());

  // §7.2: una falla de infra no descarta el snapshot ni es pase libre.
  // El catch en processSnapshot lo marca DEGRADED → INTEGRITY_DEGRADED/LOW → SUSPICIOUS.
  it('atestación que lanza excepción → DEGRADED → SUSPICIOUS', async () => {
    const { deviceId, privateKey } = await enrollDevice(server);
    const { sessionId, nonce } = await startSession(
      server,
      deviceId,
      privateKey,
    );
    const s: EnrolledSession = { privateKey, deviceId, sessionId };

    const res = await sendSnapshot(server, s, 0, nonce, {
      root: { detected: false },
    });
    expect(res.status).toBe(200);

    const end = await endSession(server, privateKey, sessionId);
    expect((end.body as { verdict: string }).verdict).toBe('SUSPICIOUS');
  });
});
