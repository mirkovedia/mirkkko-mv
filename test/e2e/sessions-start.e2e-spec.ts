import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import { createTestApp, enrollDevice, startSession } from './helpers';

describe('Sessions start (e2e)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    ({ app, server } = await createTestApp());
  });
  afterAll(async () => app.close());

  it('start con firma válida → sessionId + nonce', async () => {
    const { deviceId, privateKey } = await enrollDevice(server);
    const { sessionId, nonce } = await startSession(
      server,
      deviceId,
      privateKey,
    );
    expect(sessionId).toBeDefined();
    expect(nonce).toBeDefined();
  });

  it('start con firma inválida → 401', async () => {
    const { deviceId } = await enrollDevice(server);
    const res = await request(server).post('/sessions/start').send({
      deviceId,
      clientTimestamp: new Date().toISOString(),
      signatureB64: 'ZmFrZQ==',
    });
    expect(res.status).toBe(401);
  });
});
