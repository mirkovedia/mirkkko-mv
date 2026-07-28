import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import type { Server } from 'node:http';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
  KeyObject,
} from 'node:crypto';
import request from 'supertest';
import { AppModule } from '../../src/app.module';

export interface TestApp {
  app: INestApplication;
  server: Server;
  adminKey: string;
}

// Levanta la app con el ValidationPipe global y expone la admin key REAL que
// validó ConfigService (así los tests no dependen de un valor hardcodeado de .env).
export const createTestApp = async (): Promise<TestApp> => {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();
  const app = moduleRef.createNestApplication();
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  await app.init();
  const server = app.getHttpServer() as Server;
  const adminKey = app
    .get(ConfigService)
    .get('ADMIN_API_KEY', { infer: true }) as string;
  return { app, server, adminKey };
};

// Firma ES256 (ECDSA P-256 / SHA-256, DER) sobre los bytes exactos.
export const signBytes = (privateKey: KeyObject, bytes: Buffer): string =>
  cryptoSign('sha256', bytes, { key: privateKey, dsaEncoding: 'der' }).toString(
    'base64',
  );

// Enrola un device nuevo con un par EC P-256 recién generado.
export const enrollDevice = async (
  server: Server,
): Promise<{ deviceId: string; privateKey: KeyObject }> => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const spki = publicKey
    .export({ format: 'der', type: 'spki' })
    .toString('base64');
  const res = await request(server)
    .post('/devices/enroll')
    .send({ publicKey: spki, platform: 'ANDROID' });
  return {
    deviceId: (res.body as { deviceId: string }).deviceId,
    privateKey,
  };
};

// Inicia una sesión firmando el challenge (deviceId + clientTimestamp).
export const startSession = async (
  server: Server,
  deviceId: string,
  privateKey: KeyObject,
): Promise<{ sessionId: string; nonce: string }> => {
  const clientTimestamp = new Date().toISOString();
  const signatureB64 = signBytes(
    privateKey,
    Buffer.from(`${deviceId}${clientTimestamp}`),
  );
  const res = await request(server)
    .post('/sessions/start')
    .send({ deviceId, clientTimestamp, signatureB64 });
  const body = res.body as { sessionId: string; nonce: string };
  return { sessionId: body.sessionId, nonce: body.nonce };
};

// Construye un snapshot firmado sobre los bytes exactos del payload.
export const buildSnapshot = (
  privateKey: KeyObject,
  deviceId: string,
  sessionId: string,
  seq: number,
  nonce: string,
  signals: object,
): { payloadB64: string; signatureB64: string; integrityToken: string } => {
  const payload = {
    deviceId,
    sessionId,
    seq,
    nonce,
    clientTimestamp: new Date().toISOString(),
    integrityTokenHash: createHash('sha256').update('tok').digest('hex'),
    signals,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  return {
    payloadB64,
    signatureB64: signBytes(privateKey, Buffer.from(payloadB64, 'base64')),
    integrityToken: 'tok',
  };
};
