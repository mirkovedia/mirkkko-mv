import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import { createTestApp } from './helpers';

describe('Blacklist (e2e)', () => {
  let app: INestApplication;
  let server: Server;
  let adminKey: string;

  beforeAll(async () => {
    ({ app, server, adminKey } = await createTestApp());
  });
  afterAll(async () => app.close());

  it('GET /blacklist → version + entries', async () => {
    const res = await request(server).get('/blacklist');
    const body = res.body as { version: number; entries: unknown[] };
    expect(res.status).toBe(200);
    expect(typeof body.version).toBe('number');
    expect(Array.isArray(body.entries)).toBe(true);
  });

  it('POST sin api key → 401', async () => {
    const res = await request(server)
      .post('/blacklist')
      .send({ packageName: 'com.x', label: 'x', severity: 'HIGH' });
    expect(res.status).toBe(401);
  });

  it('POST con api key agrega y sube la versión', async () => {
    const before = (
      (await request(server).get('/blacklist')).body as { version: number }
    ).version;
    const res = await request(server)
      .post('/blacklist')
      .set('x-api-key', adminKey)
      .send({
        packageName: `com.cheat.${Date.now()}`,
        label: 'aim',
        severity: 'HIGH',
      });
    expect(res.status).toBe(201);
    const after = (
      (await request(server).get('/blacklist')).body as { version: number }
    ).version;
    expect(after).toBeGreaterThan(before);
  });
});
