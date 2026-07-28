import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import { PrismaService } from '../../src/prisma/prisma.service';
import {
  createTestApp,
  enrollDevice,
  startSession,
  sendSnapshot,
  endSession,
  type EnrolledSession,
} from './helpers';

describe('Niveles de veredicto (e2e)', () => {
  let app: INestApplication;
  let server: Server;
  let adminKey: string;

  beforeAll(async () => {
    process.env.ATTESTATION_STUB_VERDICT = 'MEETS_STRONG';
    ({ app, server, adminKey } = await createTestApp());
  });
  afterAll(async () => app.close());

  const setup = async (): Promise<EnrolledSession & { nonce: string }> => {
    const { deviceId, privateKey } = await enrollDevice(server);
    const { sessionId, nonce } = await startSession(
      server,
      deviceId,
      privateKey,
    );
    return { privateKey, deviceId, sessionId, nonce };
  };

  // §8.1/§8.2: solo señales MEDIUM (sin ningún HIGH) → SUSPICIOUS, no FLAGGED.
  it('señal MEDIUM (emulador) → SUSPICIOUS', async () => {
    const s = await setup();
    const res = await sendSnapshot(server, s, 0, s.nonce, {
      emulator: { detected: true },
    });
    expect(res.status).toBe(200);

    const end = await endSession(server, s.privateKey, s.sessionId);
    expect((end.body as { verdict: string }).verdict).toBe('SUSPICIOUS');
  });

  // §8.1: un paquete de la blacklist activa → BLACKLIST_PACKAGE/HIGH → FLAGGED.
  it('paquete en blacklist → BLACKLIST_PACKAGE → FLAGGED', async () => {
    const pkg = `com.cheat.${Date.now()}`;
    const add = await request(server)
      .post('/blacklist')
      .set('x-api-key', adminKey)
      .send({ packageName: pkg, label: 'aimbot', severity: 'HIGH' });
    expect(add.status).toBe(201);

    const s = await setup();
    const res = await sendSnapshot(server, s, 0, s.nonce, { packages: [pkg] });
    expect(res.status).toBe(200);

    const end = await endSession(server, s.privateKey, s.sessionId);
    expect((end.body as { verdict: string }).verdict).toBe('FLAGGED');

    // Verificar que fue ESE flag (no un HIGH cualquiera): el wiring evaluador↔blacklist funciona.
    const prisma = app.get(PrismaService);
    const flags = await prisma.flag.findMany({
      where: { sessionId: s.sessionId },
    });
    expect(flags.some((f) => f.type === 'BLACKLIST_PACKAGE')).toBe(true);
  });

  // §6: sesión estructuralmente incompleta (cobertura ínfima) en /end → INCOMPLETE → INVALID.
  it('cobertura estructuralmente baja → INCOMPLETE → INVALID', async () => {
    const s = await setup();
    const res = await sendSnapshot(server, s, 0, s.nonce, {
      root: { detected: false },
    });
    expect(res.status).toBe(200);

    // Simular una sesión de ~1h con un solo snapshot: coverageRatio ínfimo + gap gigante.
    const prisma = app.get(PrismaService);
    await prisma.session.update({
      where: { id: s.sessionId },
      data: { startedAt: new Date(Date.now() - 3_600_000) },
    });

    const end = await endSession(server, s.privateKey, s.sessionId);
    const body = end.body as { status: string; verdict: string };
    expect(body.status).toBe('INCOMPLETE');
    expect(body.verdict).toBe('INVALID');
  });
});
