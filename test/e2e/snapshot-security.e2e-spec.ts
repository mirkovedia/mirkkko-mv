import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import request from 'supertest';
import { PrismaService } from '../../src/prisma/prisma.service';
import {
  buildSnapshot,
  createTestApp,
  enrollDevice,
  signBytes,
  startSession,
  sendSnapshot,
  endSession,
  type EnrolledSession,
} from './helpers';

describe('Rechazos de seguridad en snapshot (e2e)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    process.env.ATTESTATION_STUB_VERDICT = 'MEETS_STRONG';
    ({ app, server } = await createTestApp());
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

  // §5: firma inválida en snapshot → 401 y el nonce NO avanza (el retry legítimo con el
  // mismo nonce sigue siendo aceptado). Se firma con una clave equivocada (firma bien formada).
  it('firma con clave equivocada → 401 y el nonce no avanza', async () => {
    const s = await setup();
    const other = await enrollDevice(server); // par de claves ajeno

    const good = buildSnapshot(
      s.privateKey,
      s.deviceId,
      s.sessionId,
      0,
      s.nonce,
      {
        root: { detected: false },
      },
    );
    const forged = {
      payloadB64: good.payloadB64,
      signatureB64: signBytes(
        other.privateKey,
        Buffer.from(good.payloadB64, 'base64'),
      ),
      integrityToken: good.integrityToken,
    };

    const rejected = await request(server)
      .post(`/sessions/${s.sessionId}/snapshot`)
      .send(forged);
    expect(rejected.status).toBe(401);

    // El nonce no se consumió: un snapshot legítimo con el nonce original entra.
    const ok = await sendSnapshot(server, s, 0, s.nonce, {
      root: { detected: false },
    });
    expect(ok.status).toBe(200);
  });

  // §5.2/§8.2: reusar un nonce ya consumido → 409 + Flag(NONCE_REUSE) → sesión INVALID.
  it('replay de nonce → 409 + Flag NONCE_REUSE → INVALID', async () => {
    const s = await setup();

    const first = await sendSnapshot(server, s, 0, s.nonce, {
      root: { detected: false },
    });
    expect(first.status).toBe(200);

    // El nonce original ya quedó consumido; reusarlo dispara el rechazo.
    const replay = await sendSnapshot(server, s, 1, s.nonce, {
      root: { detected: false },
    });
    expect(replay.status).toBe(409);

    const prisma = app.get(PrismaService);
    const flags = await prisma.flag.findMany({
      where: { sessionId: s.sessionId },
    });
    expect(flags.some((f) => f.type === 'NONCE_REUSE')).toBe(true);

    const end = await endSession(server, s.privateKey, s.sessionId);
    expect((end.body as { verdict: string }).verdict).toBe('INVALID');
  });
});
