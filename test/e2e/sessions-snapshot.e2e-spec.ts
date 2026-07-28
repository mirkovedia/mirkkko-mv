import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import {
  buildSnapshot,
  createTestApp,
  enrollDevice,
  startSession,
} from './helpers';

describe('Sessions snapshot (e2e)', () => {
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

  it('snapshot limpio → 200 + nextNonce', async () => {
    const s = await setup();
    const body = buildSnapshot(
      s.privateKey,
      s.deviceId,
      s.sessionId,
      0,
      s.nonce,
      {
        root: { detected: false },
      },
    );
    const res = await request(server)
      .post(`/sessions/${s.sessionId}/snapshot`)
      .send(body);
    expect(res.status).toBe(200);
    expect((res.body as { nextNonce: string }).nextNonce).toBeDefined();
  });

  it('replay (mismo nonce) → 409', async () => {
    const s = await setup();
    const body = buildSnapshot(
      s.privateKey,
      s.deviceId,
      s.sessionId,
      0,
      s.nonce,
      {
        root: { detected: false },
      },
    );
    await request(server).post(`/sessions/${s.sessionId}/snapshot`).send(body);
    const replay = await request(server)
      .post(`/sessions/${s.sessionId}/snapshot`)
      .send(body);
    expect(replay.status).toBe(409);
  });
});
