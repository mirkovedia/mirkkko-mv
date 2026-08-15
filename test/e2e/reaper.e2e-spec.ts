import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import { PrismaService } from '../../src/prisma/prisma.service';
import { ReaperService } from '../../src/sessions/reaper.service';
import { createTestApp, enrollDevice, startSession } from './helpers';

describe('Reaper (e2e)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    ({ app, server } = await createTestApp());
  });
  afterAll(async () => app.close());

  it('sesión vieja → reap la marca ABORTED/INVALID', async () => {
    const { deviceId, privateKey } = await enrollDevice(server);
    const { sessionId } = await startSession(server, deviceId, privateKey);

    const reaper = app.get(ReaperService);
    const prisma = app.get(PrismaService);
    // Forzar lastSeenAt muy viejo (más de 3×45s).
    await prisma.session.update({
      where: { id: sessionId },
      data: { lastSeenAt: new Date(Date.now() - 3_600_000) },
    });

    const marked = await reaper.reap(new Date());
    expect(marked).toBeGreaterThanOrEqual(1);

    const v = await request(server).get(`/sessions/${sessionId}/verdict`);
    const body = v.body as { status: string; verdict: string };
    expect(body.status).toBe('ABORTED');
    expect(body.verdict).toBe('INVALID');
  });
});
