import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import request from 'supertest';
import { createTestApp } from './helpers';

const spki = (): string =>
  generateKeyPairSync('ec', { namedCurve: 'P-256' })
    .publicKey.export({ format: 'der', type: 'spki' })
    .toString('base64');

describe('Devices (e2e)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    ({ app, server } = await createTestApp());
  });
  afterAll(async () => app.close());

  it('enroll → deviceId', async () => {
    const res = await request(server)
      .post('/devices/enroll')
      .send({ publicKey: spki(), platform: 'ANDROID' });
    expect(res.status).toBe(201);
    expect((res.body as { deviceId: string }).deviceId).toBeDefined();
  });

  it('enroll dos veces con la misma clave → mismo deviceId', async () => {
    const key = spki();
    const a = await request(server)
      .post('/devices/enroll')
      .send({ publicKey: key, platform: 'ANDROID' });
    const b = await request(server)
      .post('/devices/enroll')
      .send({ publicKey: key, platform: 'ANDROID' });
    expect((a.body as { deviceId: string }).deviceId).toBe(
      (b.body as { deviceId: string }).deviceId,
    );
  });
});
