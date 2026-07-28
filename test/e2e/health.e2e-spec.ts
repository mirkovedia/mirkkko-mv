import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import { createTestApp } from './helpers';

describe('Health (e2e)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    ({ app, server } = await createTestApp());
  });
  afterAll(async () => app.close());

  it('GET /health → 200 { status: OK }', async () => {
    const res = await request(server).get('/health');
    expect(res.status).toBe(200);
    expect((res.body as { status: string }).status).toBe('OK');
  });
});
