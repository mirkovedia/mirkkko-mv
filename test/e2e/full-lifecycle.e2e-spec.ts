import type { INestApplication } from '@nestjs/common';
import type { Server } from 'node:http';
import type { KeyObject } from 'node:crypto';
import request from 'supertest';
import {
  buildSnapshot,
  createTestApp,
  enrollDevice,
  signBytes,
  startSession,
} from './helpers';

describe('Ciclo completo (e2e)', () => {
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

  const sendSnapshot = async (
    s: { privateKey: KeyObject; deviceId: string; sessionId: string },
    seq: number,
    nonce: string,
    signals: object,
  ): Promise<string> => {
    const body = buildSnapshot(
      s.privateKey,
      s.deviceId,
      s.sessionId,
      seq,
      nonce,
      signals,
    );
    const res = await request(server)
      .post(`/sessions/${s.sessionId}/snapshot`)
      .send(body);
    return (res.body as { nextNonce: string }).nextNonce;
  };

  const endSession = async (s: {
    privateKey: KeyObject;
    sessionId: string;
  }): Promise<string> => {
    const clientTimestamp = new Date().toISOString();
    const endSig = signBytes(
      s.privateKey,
      Buffer.from(`${s.sessionId}${clientTimestamp}`),
    );
    const res = await request(server)
      .post(`/sessions/${s.sessionId}/end`)
      .send({ clientTimestamp, signatureB64: endSig });
    return (res.body as { verdict: string }).verdict;
  };

  it('ciclo con un snapshot de frida → FLAGGED', async () => {
    const s = await setup();
    let nonce = s.nonce;
    for (let seq = 0; seq < 3; seq += 1) {
      nonce = await sendSnapshot(s, seq, nonce, { root: { detected: false } });
    }
    await sendSnapshot(s, 3, nonce, { hooking: { frida: true } });
    expect(await endSession(s)).toBe('FLAGGED');
  });

  it('ciclo enteramente limpio → CLEAN', async () => {
    const s = await setup();
    let nonce = s.nonce;
    for (let seq = 0; seq < 3; seq += 1) {
      nonce = await sendSnapshot(s, seq, nonce, { root: { detected: false } });
    }
    expect(await endSession(s)).toBe('CLEAN');
  });
});
