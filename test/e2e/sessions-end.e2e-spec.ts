import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import {
  buildSnapshot,
  createTestApp,
  enrollDevice,
  signBytes,
  startSession,
} from './helpers';

describe('Sessions end (e2e)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    process.env.ATTESTATION_STUB_VERDICT = 'MEETS_STRONG';
    ({ app, server } = await createTestApp());
  });
  afterAll(async () => app.close());

  const setup = async () => {
    const { deviceId, privateKey } = await enrollDevice(server);
    const { sessionId, nonce } = await startSession(
      server,
      deviceId,
      privateKey,
    );
    return { privateKey, deviceId, sessionId, nonce };
  };

  it('sesión con root → end → FLAGGED', async () => {
    const s = await setup();
    const snap = buildSnapshot(
      s.privateKey,
      s.deviceId,
      s.sessionId,
      0,
      s.nonce,
      { root: { detected: true } },
    );
    await request(server).post(`/sessions/${s.sessionId}/snapshot`).send(snap);

    const clientTimestamp = new Date().toISOString();
    const endSig = signBytes(
      s.privateKey,
      Buffer.from(`${s.sessionId}${clientTimestamp}`),
    );
    const res = await request(server)
      .post(`/sessions/${s.sessionId}/end`)
      .send({ clientTimestamp, signatureB64: endSig });
    expect(res.status).toBe(201);
    expect((res.body as { verdict: string }).verdict).toBe('FLAGGED');

    const v = await request(server).get(`/sessions/${s.sessionId}/verdict`);
    expect((v.body as { verdict: string }).verdict).toBe('FLAGGED');
  });
});
