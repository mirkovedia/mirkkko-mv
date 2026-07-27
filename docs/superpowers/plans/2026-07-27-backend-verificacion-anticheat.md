# Backend de Verificación Anticheat — Plan de Implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir el núcleo de verificación anticheat del backend: recibir snapshots firmados de una sesión de monitoreo, validar firma + nonce + atestación, y emitir un veredicto por niveles.

**Architecture:** Monolito modular NestJS. Nest en el borde (HTTP, validación, persistencia con Prisma); dominio puro sin dependencias de Nest en el centro (`verdict/`). La atestación (Play Integrity) vive detrás de la interfaz `AttestationVerifier` (Ports & Adapters) con un stub para dev/test y el verifier real de Google intercambiable por config.

**Tech Stack:** NestJS 10, TypeScript (strict), Prisma 5 + PostgreSQL, `@nestjs/config` + Zod (validación de env), `class-validator`/`class-transformer` (DTOs), `@nestjs/throttler` (rate limit), `@nestjs/schedule` (reaper). Testing: **Jest** + Supertest + `@nestjs/testing` (Jest es el default de NestJS y se integra con `@nestjs/testing`; si preferís Vitest, avisá antes de arrancar).

## Global Constraints

Cada tarea hereda implícitamente estas reglas:

- TypeScript strict, **nunca `any`** — usar `unknown` + type guards.
- ES Modules, **named exports** por defecto, async/await siempre, early returns.
- Comentarios en español; identificadores (variables, funciones, tipos) en inglés.
- Firma: **ECDSA P-256 / SHA-256 (ES256)**, verificada sobre los **bytes exactos** que firmó el cliente (nunca re-serializar JSON).
- Nonce: **256 bits CSPRNG, base64url**, fresco por snapshot, sin reuso (constraint único en DB).
- Veredicto: precedencia **INVALID > FLAGGED > SUSPICIOUS > CLEAN**, agregado **worst-wins** sobre todos los snapshots.
- Atestación detrás de `AttestationVerifier`; fallo de infraestructura → **DEGRADED** (nunca se descarta el snapshot).
- **Device-centric**: en este spec no existe `Player` ni `discordId`.
- Modelo de datos **agnóstico de plataforma** (`platform ANDROID|IOS`); único cliente construido = Android.
- Endpoints admin detrás de `x-api-key` (`ADMIN_API_KEY`).
- Validación con `class-validator` en el borde; error shape consistente `{ error, code, details? }`.
- Migración Prisma tras cada cambio de schema; `npx prisma generate` después.

---

## File Structure

```
src/
├── main.ts                                  # bootstrap, filtro global, body limit
├── app.module.ts                            # ensambla módulos
├── config/
│   ├── env.schema.ts                        # schema Zod + validate()
│   └── config.module.ts                     # ConfigModule.forRoot({ validate })
├── common/
│   ├── guards/admin-api-key.guard.ts        # AdminApiKeyGuard
│   ├── filters/http-exception.filter.ts     # error shape { error, code, details? }
│   └── crypto/
│       ├── signature.service.ts             # verify ES256 + fingerprint
│       └── nonce.service.ts                 # generate() nonce base64url
├── prisma/
│   ├── prisma.service.ts                    # PrismaClient + onModuleInit
│   └── prisma.module.ts                     # @Global
├── verdict/                                 # DOMINIO PURO (sin Nest)
│   ├── types.ts                             # tipos: Verdict, FlagType, SignalSet, DetectedFlag...
│   ├── policy.ts                            # umbrales por defecto
│   ├── signal-evaluator.ts                  # evaluateSignals()
│   ├── gap-analyzer.ts                      # analyzeGaps()
│   └── verdict.service.ts                   # computeVerdict()
├── attestation/
│   ├── attestation-verifier.interface.ts    # AttestationVerifier + ATTESTATION_VERIFIER token
│   ├── stub-attestation.verifier.ts         # StubAttestationVerifier
│   ├── google-play-integrity.verifier.ts    # GooglePlayIntegrityVerifier (+ mapDecodedToken)
│   └── attestation.module.ts                # factory que elige provider por config
├── blacklist/
│   ├── blacklist.service.ts
│   ├── blacklist.controller.ts
│   ├── blacklist.module.ts
│   └── dto/blacklist.dto.ts
├── devices/
│   ├── devices.service.ts
│   ├── devices.controller.ts
│   ├── devices.module.ts
│   └── dto/enroll.dto.ts
└── sessions/
    ├── sessions.service.ts                  # start / snapshot / end / verdict
    ├── sessions.controller.ts
    ├── sessions.module.ts
    ├── reaper.service.ts                    # @Cron → ABORTED
    └── dto/session.dto.ts
prisma/
├── schema.prisma
└── migrations/
test/
├── unit/                                    # dominio puro + servicios cripto
└── e2e/                                     # ciclo de vida completo (Supertest)
```

---

## Task 1: Scaffolding — app Nest + config validado + health + error shape

**Files:**
- Create: `package.json`, `tsconfig.json`, `nest-cli.json`
- Create: `src/main.ts`, `src/app.module.ts`
- Create: `src/config/env.schema.ts`, `src/config/config.module.ts`
- Create: `src/common/filters/http-exception.filter.ts`
- Create: `src/health.controller.ts`
- Test: `test/e2e/health.e2e-spec.ts`

**Interfaces:**
- Produces: `AppModule`, `validateEnv(config: Record<string, unknown>) => Env`, `HttpExceptionFilter`, error shape `{ error: string; code: string; details?: unknown }`.

- [ ] **Step 1: Inicializar el proyecto Nest y dependencias**

```bash
npx @nestjs/cli new . --package-manager npm --skip-git --language TypeScript
npm i @nestjs/config zod class-validator class-transformer
npm i -D supertest @types/supertest
```

- [ ] **Step 2: Escribir el schema de env (Zod)**

`src/config/env.schema.ts`:
```typescript
import { z } from 'zod';

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(4000),
  DATABASE_URL: z.string().url(),
  ADMIN_API_KEY: z.string().min(32, 'ADMIN_API_KEY debe tener al menos 32 caracteres'),
  ATTESTATION_PROVIDER: z.enum(['stub', 'google']).default('stub'),
  ATTESTATION_STUB_VERDICT: z
    .enum(['MEETS_STRONG', 'MEETS_DEVICE', 'MEETS_BASIC', 'DEGRADED', 'FAILED'])
    .default('MEETS_STRONG'),
  SESSION_TIMEOUT_MULTIPLIER: z.coerce.number().default(3),
  SESSION_MIN_COVERAGE_RATIO: z.coerce.number().default(0.5),
  CLOCK_SKEW_TOLERANCE_SEC: z.coerce.number().default(120),
  SNAPSHOT_MAX_BODY_BYTES: z.coerce.number().default(65536),
  THROTTLE_TTL: z.coerce.number().default(60),
  THROTTLE_LIMIT: z.coerce.number().default(100),
});

export type Env = z.infer<typeof envSchema>;

// Falla al arrancar si falta una var crítica (fail fast).
export const validateEnv = (config: Record<string, unknown>): Env => {
  const parsed = envSchema.safeParse(config);
  if (!parsed.success) {
    throw new Error(`Config de entorno inválida: ${parsed.error.message}`);
  }
  return parsed.data;
};
```

- [ ] **Step 3: ConfigModule + filtro de excepción global + health controller**

`src/config/config.module.ts`:
```typescript
import { Global, Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { validateEnv } from './env.schema';

@Global()
@Module({
  imports: [NestConfigModule.forRoot({ isGlobal: true, validate: validateEnv })],
})
export class ConfigModule {}
```

`src/common/filters/http-exception.filter.ts`:
```typescript
import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus } from '@nestjs/common';
import { Response } from 'express';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const isHttp = exception instanceof HttpException;
    const status = isHttp ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    const payload = isHttp ? exception.getResponse() : null;

    // Normaliza a { error, code, details? }
    const error =
      typeof payload === 'object' && payload !== null && 'message' in payload
        ? String((payload as Record<string, unknown>).message)
        : isHttp
          ? exception.message
          : 'Internal server error';
    const code =
      typeof payload === 'object' && payload !== null && 'code' in payload
        ? String((payload as Record<string, unknown>).code)
        : isHttp
          ? exception.constructor.name.replace('Exception', '').toUpperCase()
          : 'INTERNAL_ERROR';

    res.status(status).json({ error, code });
  }
}
```

`src/health.controller.ts`:
```typescript
import { Controller, Get } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get()
  check(): { status: string; timestamp: string } {
    return { status: 'OK', timestamp: new Date().toISOString() };
  }
}
```

`src/main.ts`:
```typescript
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { json } from 'express';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import type { Env } from './config/env.schema';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService<Env, true>);
  app.use(json({ limit: config.get('SNAPSHOT_MAX_BODY_BYTES', { infer: true }) }));
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  app.useGlobalFilters(new HttpExceptionFilter());
  await app.listen(config.get('PORT', { infer: true }));
}
void bootstrap();
```

`src/app.module.ts`:
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from './config/config.module';
import { HealthController } from './health.controller';

@Module({ imports: [ConfigModule], controllers: [HealthController] })
export class AppModule {}
```

- [ ] **Step 4: Escribir el test e2e de health (debe fallar)**

`test/e2e/health.e2e-spec.ts`:
```typescript
import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../src/app.module';

describe('Health (e2e)', () => {
  let app: INestApplication;
  beforeAll(async () => {
    process.env.DATABASE_URL = 'postgresql://u:p@localhost:5432/test';
    process.env.ADMIN_API_KEY = 'x'.repeat(32);
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
  });
  afterAll(async () => app.close());

  it('GET /health → 200 { status: OK }', async () => {
    const res = await request(app.getHttpServer()).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('OK');
  });
});
```

- [ ] **Step 5: Correr, verificar que pasa, commit**

```bash
npm run test:e2e -- health && git add -A && git commit -m "feat: scaffolding Nest + config validado + health + error shape"
```

---

## Task 2: Prisma — schema, migración y PrismaService

**Files:**
- Create: `prisma/schema.prisma`
- Create: `src/prisma/prisma.service.ts`, `src/prisma/prisma.module.ts`
- Modify: `src/app.module.ts` (importar `PrismaModule`)
- Test: `test/unit/prisma.smoke.spec.ts`

**Interfaces:**
- Produces: `PrismaService` (extiende `PrismaClient`), modelos `Device`, `Session`, `Snapshot`, `Flag`, `BlacklistEntry`, `BlacklistState` con enums `Platform`, `SessionStatus`, `Verdict`, `IntegrityVerdict`, `AttestationType`, `Severity`, `FlagType`.

- [ ] **Step 1: Instalar Prisma y escribir el schema**

```bash
npm i @prisma/client && npm i -D prisma && npx prisma init --datasource-provider postgresql
```

`prisma/schema.prisma` (copiar los modelos de la §4 del spec, verbatim). Enums y modelos: `Platform`, `SessionStatus`, `Verdict`, `IntegrityVerdict`, `AttestationType`, `Severity`, `FlagType`, `Device`, `Session`, `Snapshot`, `Flag`, `BlacklistEntry`, `BlacklistState`. Constraints clave: `Device.publicKeyFp @unique`, `Snapshot @@unique([sessionId, seq])` y `@@unique([sessionId, nonceUsed])`, `Session @@index([status, lastSeenAt])`.

- [ ] **Step 2: Crear la migración y generar el cliente**

```bash
npx prisma migrate dev --name init && npx prisma generate
```
Expected: crea `prisma/migrations/*_init/` y las tablas en la DB.

- [ ] **Step 3: PrismaService + PrismaModule**

`src/prisma/prisma.service.ts`:
```typescript
import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit(): Promise<void> {
    await this.$connect();
  }
}
```

`src/prisma/prisma.module.ts`:
```typescript
import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global()
@Module({ providers: [PrismaService], exports: [PrismaService] })
export class PrismaModule {}
```
Agregar `PrismaModule` a `imports` de `AppModule`.

- [ ] **Step 4: Test de humo (crear + leer un Device)**

`test/unit/prisma.smoke.spec.ts`:
```typescript
import { PrismaService } from '../../src/prisma/prisma.service';

describe('Prisma smoke', () => {
  const prisma = new PrismaService();
  beforeAll(async () => prisma.$connect());
  afterAll(async () => prisma.$disconnect());

  it('crea y lee un Device', async () => {
    const device = await prisma.device.create({
      data: { publicKey: 'k', publicKeyFp: `fp-${Date.now()}`, platform: 'ANDROID' },
    });
    const found = await prisma.device.findUnique({ where: { id: device.id } });
    expect(found?.platform).toBe('ANDROID');
    await prisma.device.delete({ where: { id: device.id } });
  });
});
```

- [ ] **Step 5: Correr, verificar, commit**

```bash
npm test -- prisma.smoke && git add -A && git commit -m "feat: schema Prisma + PrismaService + migración init"
```

---

## Task 3: Servicios cripto — SignatureService (ES256) + NonceService

**Files:**
- Create: `src/common/crypto/signature.service.ts`, `src/common/crypto/nonce.service.ts`
- Create: `src/common/crypto/crypto.module.ts`
- Test: `test/unit/signature.service.spec.ts`, `test/unit/nonce.service.spec.ts`

**Interfaces:**
- Produces:
  - `SignatureService.verify(publicKeySpkiB64: string, payload: Buffer, signatureB64: string): boolean`
  - `SignatureService.fingerprint(publicKeySpkiB64: string): string` (sha256 hex)
  - `NonceService.generate(): string` (base64url, 32 bytes)

- [ ] **Step 1: Escribir los tests (deben fallar)**

`test/unit/signature.service.spec.ts`:
```typescript
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { SignatureService } from '../../src/common/crypto/signature.service';

describe('SignatureService', () => {
  const service = new SignatureService();
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spkiB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const payload = Buffer.from('{"seq":1}');
  const sigB64 = cryptoSign('sha256', payload, { key: privateKey, dsaEncoding: 'der' }).toString('base64');

  it('acepta una firma válida', () => {
    expect(service.verify(spkiB64, payload, sigB64)).toBe(true);
  });
  it('rechaza payload manipulado', () => {
    expect(service.verify(spkiB64, Buffer.from('{"seq":2}'), sigB64)).toBe(false);
  });
  it('rechaza clave equivocada', () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey
      .export({ format: 'der', type: 'spki' }).toString('base64');
    expect(service.verify(other, payload, sigB64)).toBe(false);
  });
  it('rechaza clave malformada sin lanzar', () => {
    expect(service.verify('no-base64-valido', payload, sigB64)).toBe(false);
  });
  it('fingerprint es estable y hex', () => {
    expect(service.fingerprint(spkiB64)).toMatch(/^[0-9a-f]{64}$/);
    expect(service.fingerprint(spkiB64)).toBe(service.fingerprint(spkiB64));
  });
});
```

`test/unit/nonce.service.spec.ts`:
```typescript
import { NonceService } from '../../src/common/crypto/nonce.service';

describe('NonceService', () => {
  const service = new NonceService();
  it('genera nonces base64url distintos', () => {
    const a = service.generate();
    const b = service.generate();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(a, 'base64url')).toHaveLength(32);
  });
});
```

- [ ] **Step 2: Correr → FAIL** (`npm test -- signature nonce`), esperado: "Cannot find module".

- [ ] **Step 3: Implementar**

`src/common/crypto/signature.service.ts`:
```typescript
import { Injectable } from '@nestjs/common';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

@Injectable()
export class SignatureService {
  // Verifica ECDSA P-256 / SHA-256 sobre los bytes exactos del payload.
  verify(publicKeySpkiB64: string, payload: Buffer, signatureB64: string): boolean {
    try {
      const keyObject = createPublicKey({
        key: Buffer.from(publicKeySpkiB64, 'base64'),
        format: 'der',
        type: 'spki',
      });
      return cryptoVerify(
        'sha256',
        payload,
        { key: keyObject, dsaEncoding: 'der' },
        Buffer.from(signatureB64, 'base64'),
      );
    } catch {
      // Clave malformada o firma inválida → no autenticado (nunca 500).
      return false;
    }
  }

  // Huella de la clave pública para idempotencia de enrolamiento.
  fingerprint(publicKeySpkiB64: string): string {
    return createHash('sha256').update(Buffer.from(publicKeySpkiB64, 'base64')).digest('hex');
  }
}
```

`src/common/crypto/nonce.service.ts`:
```typescript
import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';

@Injectable()
export class NonceService {
  // Nonce de 256 bits (32 bytes) en base64url.
  generate(): string {
    return randomBytes(32).toString('base64url');
  }
}
```

`src/common/crypto/crypto.module.ts`:
```typescript
import { Global, Module } from '@nestjs/common';
import { SignatureService } from './signature.service';
import { NonceService } from './nonce.service';

@Global()
@Module({ providers: [SignatureService, NonceService], exports: [SignatureService, NonceService] })
export class CryptoModule {}
```
Agregar `CryptoModule` a `AppModule`.

- [ ] **Step 4: Correr → PASS** (`npm test -- signature nonce`).

- [ ] **Step 5: Commit** — `git commit -am "feat: SignatureService ES256 + NonceService"`

---

## Task 4: Dominio — tipos, policy y SignalEvaluator

**Files:**
- Create: `src/verdict/types.ts`, `src/verdict/policy.ts`, `src/verdict/signal-evaluator.ts`
- Test: `test/unit/signal-evaluator.spec.ts`

**Interfaces:**
- Produces:
  - Tipos: `Platform`, `IntegrityVerdict`, `Verdict`, `Severity`, `FlagType`, `SessionStatus`, `DetectedFlag { type; severity; details? }`, `SignalSet`.
  - `evaluateSignals(signals: SignalSet, integrityVerdict: IntegrityVerdict, blacklist: ReadonlySet<string>): DetectedFlag[]`

- [ ] **Step 1: Escribir el test (debe fallar)**

`test/unit/signal-evaluator.spec.ts`:
```typescript
import { evaluateSignals } from '../../src/verdict/signal-evaluator';
import type { SignalSet } from '../../src/verdict/types';

const empty: SignalSet = {};
const bl = new Set<string>(['com.cheat.aim']);

describe('evaluateSignals', () => {
  it('root → ROOT/HIGH', () => {
    const flags = evaluateSignals({ root: { detected: true } }, 'MEETS_STRONG', bl);
    expect(flags).toContainEqual(expect.objectContaining({ type: 'ROOT', severity: 'HIGH' }));
  });
  it('frida → HOOKING_FRAMEWORK/HIGH', () => {
    const flags = evaluateSignals({ hooking: { frida: true } }, 'MEETS_STRONG', bl);
    expect(flags.some((f) => f.type === 'HOOKING_FRAMEWORK')).toBe(true);
  });
  it('paquete en blacklist → BLACKLIST_PACKAGE con packageName', () => {
    const flags = evaluateSignals({ packages: ['com.cheat.aim', 'com.ok'] }, 'MEETS_STRONG', bl);
    expect(flags).toContainEqual(
      expect.objectContaining({ type: 'BLACKLIST_PACKAGE', details: { packageName: 'com.cheat.aim' } }),
    );
    expect(flags.filter((f) => f.type === 'BLACKLIST_PACKAGE')).toHaveLength(1);
  });
  it('emulador → EMULATOR/MEDIUM', () => {
    expect(evaluateSignals({ emulator: { detected: true } }, 'MEETS_STRONG', bl)[0].severity).toBe('MEDIUM');
  });
  it('integridad DEGRADED → INTEGRITY_DEGRADED/LOW', () => {
    expect(evaluateSignals(empty, 'DEGRADED', bl)).toContainEqual(
      expect.objectContaining({ type: 'INTEGRITY_DEGRADED', severity: 'LOW' }),
    );
  });
  it('integridad FAILED → INTEGRITY_FAILED/HIGH', () => {
    expect(evaluateSignals(empty, 'FAILED', bl)).toContainEqual(
      expect.objectContaining({ type: 'INTEGRITY_FAILED', severity: 'HIGH' }),
    );
  });
  it('MEETS_BASIC → INTEGRITY_BASIC/LOW', () => {
    expect(evaluateSignals(empty, 'MEETS_BASIC', bl)).toContainEqual(
      expect.objectContaining({ type: 'INTEGRITY_BASIC', severity: 'LOW' }),
    );
  });
  it('limpio + STRONG → sin flags', () => {
    expect(evaluateSignals(empty, 'MEETS_STRONG', bl)).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Correr → FAIL** (`npm test -- signal-evaluator`).

- [ ] **Step 3: Implementar tipos, policy y evaluador**

`src/verdict/types.ts`:
```typescript
export type Platform = 'ANDROID' | 'IOS';
export type IntegrityVerdict =
  | 'MEETS_STRONG' | 'MEETS_DEVICE' | 'MEETS_BASIC' | 'DEGRADED' | 'FAILED' | 'UNKNOWN';
export type Verdict = 'CLEAN' | 'SUSPICIOUS' | 'FLAGGED' | 'INVALID';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH';
export type SessionStatus = 'ACTIVE' | 'COMPLETE' | 'INCOMPLETE' | 'ABORTED';
export type FlagType =
  | 'ROOT' | 'HOOKING_FRAMEWORK' | 'BLACKLIST_PACKAGE' | 'APK_SIGNATURE_MISMATCH' | 'INTEGRITY_FAILED'
  | 'EMULATOR' | 'OVERLAY' | 'ACCESSIBILITY' | 'INTEGRITY_BASIC' | 'INTEGRITY_DEGRADED'
  | 'SNAPSHOT_GAP' | 'SIGNATURE_INVALID' | 'NONCE_REUSE';

export interface DetectedFlag {
  type: FlagType;
  severity: Severity;
  details?: Record<string, unknown>;
}

export interface SignalSet {
  root?: { detected: boolean };
  hooking?: { frida?: boolean; xposed?: boolean };
  packages?: string[];
  emulator?: { detected: boolean };
  overlay?: { activeDuringSession: boolean };
  accessibility?: { suspiciousServiceActive: boolean };
  apkSignature?: { mismatch: boolean };
}
```

`src/verdict/policy.ts`:
```typescript
// Umbrales por defecto del gap analysis (los valores runtime vienen de env).
export const DEFAULT_POLICY = {
  minCoverageRatio: 0.5,
  timeoutMultiplier: 3,
  gapSuspiciousMultiplier: 2,
  gapWarnCoverageRatio: 0.8,
} as const;
```

`src/verdict/signal-evaluator.ts`:
```typescript
import type { DetectedFlag, IntegrityVerdict, SignalSet } from './types';

// Función pura: mapea señales del dispositivo + veredicto de integridad a flags.
export const evaluateSignals = (
  signals: SignalSet,
  integrityVerdict: IntegrityVerdict,
  blacklist: ReadonlySet<string>,
): DetectedFlag[] => {
  const flags: DetectedFlag[] = [];

  if (signals.root?.detected) flags.push({ type: 'ROOT', severity: 'HIGH' });
  if (signals.hooking?.frida || signals.hooking?.xposed) {
    flags.push({ type: 'HOOKING_FRAMEWORK', severity: 'HIGH', details: { ...signals.hooking } });
  }
  for (const pkg of signals.packages ?? []) {
    if (blacklist.has(pkg)) {
      flags.push({ type: 'BLACKLIST_PACKAGE', severity: 'HIGH', details: { packageName: pkg } });
    }
  }
  if (signals.apkSignature?.mismatch) flags.push({ type: 'APK_SIGNATURE_MISMATCH', severity: 'HIGH' });
  if (integrityVerdict === 'FAILED') flags.push({ type: 'INTEGRITY_FAILED', severity: 'HIGH' });

  if (signals.emulator?.detected) flags.push({ type: 'EMULATOR', severity: 'MEDIUM' });
  if (signals.overlay?.activeDuringSession) flags.push({ type: 'OVERLAY', severity: 'MEDIUM' });
  if (signals.accessibility?.suspiciousServiceActive) {
    flags.push({ type: 'ACCESSIBILITY', severity: 'MEDIUM' });
  }

  if (integrityVerdict === 'MEETS_BASIC' || integrityVerdict === 'MEETS_DEVICE') {
    flags.push({ type: 'INTEGRITY_BASIC', severity: 'LOW' });
  }
  if (integrityVerdict === 'DEGRADED') flags.push({ type: 'INTEGRITY_DEGRADED', severity: 'LOW' });

  return flags;
};
```

- [ ] **Step 4: Correr → PASS** (`npm test -- signal-evaluator`).

- [ ] **Step 5: Commit** — `git commit -am "feat: dominio de veredicto (tipos, policy, signal-evaluator)"`

---

## Task 5: Dominio — SessionGapAnalyzer

**Files:**
- Create: `src/verdict/gap-analyzer.ts`
- Test: `test/unit/gap-analyzer.spec.ts`

**Interfaces:**
- Consumes: `DEFAULT_POLICY` (Task 4).
- Produces: `analyzeGaps(input: GapInput): GapResult` con
  `GapInput { startedAt: number; endedAt: number; snapshotTimestamps: number[]; expectedIntervalSec: number; timeoutMultiplier: number; minCoverageRatio: number; gapSuspiciousMultiplier: number; gapWarnCoverageRatio: number }`
  y `GapResult { status: 'COMPLETE' | 'INCOMPLETE'; gapFlag: boolean }`.

- [ ] **Step 1: Escribir el test (debe fallar)**

`test/unit/gap-analyzer.spec.ts`:
```typescript
import { analyzeGaps } from '../../src/verdict/gap-analyzer';

const base = {
  expectedIntervalSec: 45,
  timeoutMultiplier: 3,
  minCoverageRatio: 0.5,
  gapSuspiciousMultiplier: 2,
  gapWarnCoverageRatio: 0.8,
};
const ts = (startMs: number, count: number, stepSec: number): number[] =>
  Array.from({ length: count }, (_, i) => startMs + (i + 1) * stepSec * 1000);

describe('analyzeGaps', () => {
  it('cobertura completa y regular → COMPLETE sin gapFlag', () => {
    const startedAt = 0;
    const endedAt = 45_000 * 11; // ~10 intervalos
    const r = analyzeGaps({ ...base, startedAt, endedAt, snapshotTimestamps: ts(0, 10, 45) });
    expect(r).toEqual({ status: 'COMPLETE', gapFlag: false });
  });
  it('un gap grande (> timeout) → INCOMPLETE', () => {
    const startedAt = 0;
    const endedAt = 45_000 * 11;
    // salta del snapshot 2 al 9 (hueco de ~7 intervalos)
    const snaps = [45_000, 90_000, 9 * 45_000, 10 * 45_000];
    const r = analyzeGaps({ ...base, startedAt, endedAt, snapshotTimestamps: snaps });
    expect(r.status).toBe('INCOMPLETE');
  });
  it('cobertura baja (< 0.5) → INCOMPLETE', () => {
    const r = analyzeGaps({ ...base, startedAt: 0, endedAt: 45_000 * 11, snapshotTimestamps: ts(0, 3, 45) });
    expect(r.status).toBe('INCOMPLETE');
  });
  it('gap mediano (2x–3x) → COMPLETE + gapFlag', () => {
    const startedAt = 0;
    const endedAt = 45_000 * 9;
    // 7 snapshots regulares y uno con hueco de ~2.5x
    const snaps = [45_000, 90_000, 135_000, 247_500, 292_500, 337_500, 382_500];
    const r = analyzeGaps({ ...base, startedAt, endedAt, snapshotTimestamps: snaps });
    expect(r).toEqual({ status: 'COMPLETE', gapFlag: true });
  });
});
```

- [ ] **Step 2: Correr → FAIL** (`npm test -- gap-analyzer`).

- [ ] **Step 3: Implementar**

`src/verdict/gap-analyzer.ts`:
```typescript
export interface GapInput {
  startedAt: number; // epoch ms
  endedAt: number; // epoch ms
  snapshotTimestamps: number[]; // epoch ms, orden ascendente
  expectedIntervalSec: number;
  timeoutMultiplier: number;
  minCoverageRatio: number;
  gapSuspiciousMultiplier: number;
  gapWarnCoverageRatio: number;
}

export interface GapResult {
  status: 'COMPLETE' | 'INCOMPLETE';
  gapFlag: boolean;
}

// Función pura: decide si la sesión cubrió su lapso o quedó estructuralmente incompleta.
export const analyzeGaps = (input: GapInput): GapResult => {
  const intervalMs = input.expectedIntervalSec * 1000;
  const durationMs = Math.max(input.endedAt - input.startedAt, 0);
  const expectedCount = Math.floor(durationMs / intervalMs);
  const coverageRatio = input.snapshotTimestamps.length / Math.max(expectedCount, 1);

  // Mayor hueco entre eventos consecutivos: start → snapshots… → end.
  const points = [input.startedAt, ...input.snapshotTimestamps, input.endedAt];
  let maxGap = 0;
  for (let i = 1; i < points.length; i += 1) {
    maxGap = Math.max(maxGap, points[i] - points[i - 1]);
  }

  const timeoutMs = input.timeoutMultiplier * intervalMs;
  if (maxGap > timeoutMs || coverageRatio < input.minCoverageRatio) {
    return { status: 'INCOMPLETE', gapFlag: false };
  }

  const suspiciousMs = input.gapSuspiciousMultiplier * intervalMs;
  if (maxGap > suspiciousMs || coverageRatio < input.gapWarnCoverageRatio) {
    return { status: 'COMPLETE', gapFlag: true };
  }
  return { status: 'COMPLETE', gapFlag: false };
};
```

- [ ] **Step 4: Correr → PASS** (`npm test -- gap-analyzer`).

- [ ] **Step 5: Commit** — `git commit -am "feat: gap-analyzer del ciclo de vida de sesión"`

---

## Task 6: Dominio — VerdictService

**Files:**
- Create: `src/verdict/verdict.service.ts`
- Test: `test/unit/verdict.service.spec.ts`

**Interfaces:**
- Consumes: `DetectedFlag`, `SessionStatus`, `Verdict` (Task 4).
- Produces: `computeVerdict(status: SessionStatus, snapshots: SnapshotFlags[]): Verdict` con `SnapshotFlags { flags: DetectedFlag[] }`.

- [ ] **Step 1: Escribir el test (debe fallar)**

`test/unit/verdict.service.spec.ts`:
```typescript
import { computeVerdict } from '../../src/verdict/verdict.service';
import type { DetectedFlag } from '../../src/verdict/types';

const snap = (...flags: DetectedFlag[]) => ({ flags });
const high: DetectedFlag = { type: 'ROOT', severity: 'HIGH' };
const med: DetectedFlag = { type: 'EMULATOR', severity: 'MEDIUM' };
const sigInvalid: DetectedFlag = { type: 'SIGNATURE_INVALID', severity: 'HIGH' };

describe('computeVerdict', () => {
  it('status ABORTED → INVALID', () => {
    expect(computeVerdict('ABORTED', [snap()])).toBe('INVALID');
  });
  it('status INCOMPLETE → INVALID', () => {
    expect(computeVerdict('INCOMPLETE', [snap()])).toBe('INVALID');
  });
  it('cero snapshots → INVALID', () => {
    expect(computeVerdict('COMPLETE', [])).toBe('INVALID');
  });
  it('firma inválida → INVALID (gana sobre FLAGGED)', () => {
    expect(computeVerdict('COMPLETE', [snap(sigInvalid)])).toBe('INVALID');
  });
  it('un flag HIGH → FLAGGED', () => {
    expect(computeVerdict('COMPLETE', [snap(), snap(high)])).toBe('FLAGGED');
  });
  it('solo flags MEDIUM/LOW → SUSPICIOUS', () => {
    expect(computeVerdict('COMPLETE', [snap(med)])).toBe('SUSPICIOUS');
  });
  it('sin flags y COMPLETE → CLEAN', () => {
    expect(computeVerdict('COMPLETE', [snap(), snap()])).toBe('CLEAN');
  });
  it('worst-wins: un snapshot sucio entre limpios → FLAGGED', () => {
    expect(computeVerdict('COMPLETE', [snap(), snap(), snap(high)])).toBe('FLAGGED');
  });
});
```

- [ ] **Step 2: Correr → FAIL** (`npm test -- verdict.service`).

- [ ] **Step 3: Implementar**

`src/verdict/verdict.service.ts`:
```typescript
import type { DetectedFlag, SessionStatus, Verdict } from './types';

export interface SnapshotFlags {
  flags: DetectedFlag[];
}

const INVALIDATING_TYPES = new Set(['SIGNATURE_INVALID', 'NONCE_REUSE']);

// Función pura: precedencia INVALID > FLAGGED > SUSPICIOUS > CLEAN, worst-wins sobre todos los snapshots.
export const computeVerdict = (status: SessionStatus, snapshots: SnapshotFlags[]): Verdict => {
  if (status === 'INCOMPLETE' || status === 'ABORTED') return 'INVALID';
  if (snapshots.length === 0) return 'INVALID';

  const allFlags = snapshots.flatMap((s) => s.flags);
  if (allFlags.some((f) => INVALIDATING_TYPES.has(f.type))) return 'INVALID';
  if (allFlags.some((f) => f.severity === 'HIGH')) return 'FLAGGED';
  if (allFlags.length > 0) return 'SUSPICIOUS';
  return 'CLEAN';
};
```

- [ ] **Step 4: Correr → PASS** (`npm test -- verdict.service`).

- [ ] **Step 5: Commit** — `git commit -am "feat: computeVerdict con precedencia worst-wins"`

---

## Task 7: Atestación — interfaz + StubAttestationVerifier + módulo

**Files:**
- Create: `src/attestation/attestation-verifier.interface.ts`, `src/attestation/stub-attestation.verifier.ts`, `src/attestation/attestation.module.ts`
- Test: `test/unit/stub-attestation.verifier.spec.ts`

**Interfaces:**
- Consumes: `IntegrityVerdict`, `Platform` (Task 4).
- Produces:
  - `AttestationVerifier { verify(input: AttestationInput): Promise<IntegrityResult> }`
  - `AttestationInput { token: string | null; nonce: string; platform: Platform }`
  - `IntegrityResult { verdict: IntegrityVerdict; raw?: unknown; evaluatedAt: Date }`
  - Token DI: `ATTESTATION_VERIFIER` (symbol).

- [ ] **Step 1: Escribir el test (debe fallar)**

`test/unit/stub-attestation.verifier.spec.ts`:
```typescript
import { ConfigService } from '@nestjs/config';
import { StubAttestationVerifier } from '../../src/attestation/stub-attestation.verifier';

const cfg = (verdict: string) =>
  ({ get: () => verdict }) as unknown as ConfigService;

describe('StubAttestationVerifier', () => {
  it('devuelve el veredicto configurado con token presente', async () => {
    const v = new StubAttestationVerifier(cfg('MEETS_STRONG'));
    const r = await v.verify({ token: 'tok', nonce: 'n', platform: 'ANDROID' });
    expect(r.verdict).toBe('MEETS_STRONG');
  });
  it('token null → DEGRADED (no se pudo evaluar)', async () => {
    const v = new StubAttestationVerifier(cfg('MEETS_STRONG'));
    const r = await v.verify({ token: null, nonce: 'n', platform: 'ANDROID' });
    expect(r.verdict).toBe('DEGRADED');
  });
});
```

- [ ] **Step 2: Correr → FAIL** (`npm test -- stub-attestation`).

- [ ] **Step 3: Implementar interfaz, stub y módulo**

`src/attestation/attestation-verifier.interface.ts`:
```typescript
import type { IntegrityVerdict, Platform } from '../verdict/types';

export interface AttestationInput {
  token: string | null;
  nonce: string;
  platform: Platform;
}

export interface IntegrityResult {
  verdict: IntegrityVerdict;
  raw?: unknown;
  evaluatedAt: Date;
}

export interface AttestationVerifier {
  verify(input: AttestationInput): Promise<IntegrityResult>;
}

// Token de inyección para el provider (Ports & Adapters).
export const ATTESTATION_VERIFIER = Symbol('ATTESTATION_VERIFIER');
```

`src/attestation/stub-attestation.verifier.ts`:
```typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AttestationInput, AttestationVerifier, IntegrityResult } from './attestation-verifier.interface';
import type { Env } from '../config/env.schema';
import type { IntegrityVerdict } from '../verdict/types';

@Injectable()
export class StubAttestationVerifier implements AttestationVerifier {
  constructor(private readonly config: ConfigService<Env, true>) {}

  async verify(input: AttestationInput): Promise<IntegrityResult> {
    // Sin token no se pudo atestar → DEGRADED (nunca se descarta el snapshot).
    if (input.token === null) return { verdict: 'DEGRADED', evaluatedAt: new Date() };
    const verdict = this.config.get('ATTESTATION_STUB_VERDICT', { infer: true }) as IntegrityVerdict;
    return { verdict, evaluatedAt: new Date() };
  }
}
```

`src/attestation/attestation.module.ts`:
```typescript
import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ATTESTATION_VERIFIER } from './attestation-verifier.interface';
import { StubAttestationVerifier } from './stub-attestation.verifier';
import { GooglePlayIntegrityVerifier } from './google-play-integrity.verifier';
import type { Env } from '../config/env.schema';

@Global()
@Module({
  providers: [
    StubAttestationVerifier,
    GooglePlayIntegrityVerifier,
    {
      provide: ATTESTATION_VERIFIER,
      inject: [ConfigService, StubAttestationVerifier, GooglePlayIntegrityVerifier],
      useFactory: (
        config: ConfigService<Env, true>,
        stub: StubAttestationVerifier,
        google: GooglePlayIntegrityVerifier,
      ) => (config.get('ATTESTATION_PROVIDER', { infer: true }) === 'google' ? google : stub),
    },
  ],
  exports: [ATTESTATION_VERIFIER],
})
export class AttestationModule {}
```
> Nota: `GooglePlayIntegrityVerifier` se implementa en Task 8. Para que este módulo compile ahora, crear en Task 8 primero el archivo o dejar la clase en Task 8 y reordenar. **Dependencia:** Task 7 y 8 se implementan juntas (el módulo referencia ambas clases).

- [ ] **Step 4: Correr → PASS** (`npm test -- stub-attestation`). (El módulo se valida en Task 8.)

- [ ] **Step 5: Commit** — `git commit -am "feat: interfaz AttestationVerifier + stub"`

---

## Task 8: Atestación — GooglePlayIntegrityVerifier (mapeo con fixtures)

**Files:**
- Create: `src/attestation/google-play-integrity.verifier.ts`
- Test: `test/unit/google-play-integrity.verifier.spec.ts`

**Interfaces:**
- Consumes: `AttestationVerifier`, `AttestationInput`, `IntegrityResult` (Task 7).
- Produces: `GooglePlayIntegrityVerifier` con método puro `mapDecodedToken(decoded: unknown, expectedNonce: string): IntegrityResult` (testeable sin credenciales). El método `verify()` (llamada de red a Google) es delgado y se prueba en prod, no en unit.

- [ ] **Step 1: Escribir el test del mapeo (debe fallar)**

`test/unit/google-play-integrity.verifier.spec.ts`:
```typescript
import { GooglePlayIntegrityVerifier } from '../../src/attestation/google-play-integrity.verifier';

const v = new GooglePlayIntegrityVerifier();
const decoded = (labels: string[], requestHash = 'n1') => ({
  requestDetails: { nonce: requestHash },
  deviceIntegrity: { deviceRecognitionVerdict: labels },
});

describe('GooglePlayIntegrityVerifier.mapDecodedToken', () => {
  it('MEETS_STRONG_INTEGRITY → MEETS_STRONG', () => {
    expect(v.mapDecodedToken(decoded(['MEETS_STRONG_INTEGRITY', 'MEETS_DEVICE_INTEGRITY']), 'n1').verdict)
      .toBe('MEETS_STRONG');
  });
  it('solo device → MEETS_DEVICE', () => {
    expect(v.mapDecodedToken(decoded(['MEETS_DEVICE_INTEGRITY']), 'n1').verdict).toBe('MEETS_DEVICE');
  });
  it('solo basic → MEETS_BASIC', () => {
    expect(v.mapDecodedToken(decoded(['MEETS_BASIC_INTEGRITY']), 'n1').verdict).toBe('MEETS_BASIC');
  });
  it('veredictos vacíos → FAILED (device comprometido)', () => {
    expect(v.mapDecodedToken(decoded([]), 'n1').verdict).toBe('FAILED');
  });
  it('nonce que no coincide → FAILED (posible replay)', () => {
    expect(v.mapDecodedToken(decoded(['MEETS_STRONG_INTEGRITY'], 'otro'), 'n1').verdict).toBe('FAILED');
  });
});
```

- [ ] **Step 2: Correr → FAIL** (`npm test -- google-play-integrity`).

- [ ] **Step 3: Implementar**

`src/attestation/google-play-integrity.verifier.ts`:
```typescript
import { Injectable } from '@nestjs/common';
import type { AttestationInput, AttestationVerifier, IntegrityResult } from './attestation-verifier.interface';
import type { IntegrityVerdict } from '../verdict/types';

// Forma parcial del payload decodificado de Play Integrity que nos interesa.
interface DecodedToken {
  requestDetails?: { nonce?: string };
  deviceIntegrity?: { deviceRecognitionVerdict?: string[] };
}

@Injectable()
export class GooglePlayIntegrityVerifier implements AttestationVerifier {
  // Mapeo puro (testeable con fixtures) del token decodificado a nuestro veredicto.
  mapDecodedToken(decoded: unknown, expectedNonce: string): IntegrityResult {
    const token = decoded as DecodedToken;
    const now = new Date();

    // El nonce del token debe coincidir con el nonce de servidor (anti-replay).
    if (token.requestDetails?.nonce !== expectedNonce) {
      return { verdict: 'FAILED', raw: decoded, evaluatedAt: now };
    }
    const labels = token.deviceIntegrity?.deviceRecognitionVerdict ?? [];
    let verdict: IntegrityVerdict = 'FAILED';
    if (labels.includes('MEETS_STRONG_INTEGRITY')) verdict = 'MEETS_STRONG';
    else if (labels.includes('MEETS_DEVICE_INTEGRITY')) verdict = 'MEETS_DEVICE';
    else if (labels.includes('MEETS_BASIC_INTEGRITY')) verdict = 'MEETS_BASIC';
    // labels vacío → FAILED (device no alcanzó integridad).
    return { verdict, raw: decoded, evaluatedAt: now };
  }

  async verify(input: AttestationInput): Promise<IntegrityResult> {
    if (input.token === null) return { verdict: 'DEGRADED', evaluatedAt: new Date() };
    // NOTA (prod): aquí va la llamada real a Google
    // (googleapis playintegrity.v1.decodeIntegrityToken con el service account).
    // Se deja lanzar si falla para que el llamador la trate como DEGRADED.
    const decoded = await this.decodeWithGoogle(input.token);
    return this.mapDecodedToken(decoded, input.nonce);
  }

  // Placeholder de red — implementación real requiere GOOGLE_APPLICATION_CREDENTIALS.
  private async decodeWithGoogle(_token: string): Promise<unknown> {
    throw new Error('GooglePlayIntegrityVerifier.decodeWithGoogle no configurado (falta service account)');
  }
}
```
> `decodeWithGoogle` queda sin implementar (lanza) hasta tener credenciales; el mapeo, que es la lógica, está cubierto por tests. En prod se implementa la llamada real.

- [ ] **Step 4: Correr → PASS** (`npm test -- google-play-integrity`).

- [ ] **Step 5: Compilar el AttestationModule y commitear**

```bash
npm run build && git add -A && git commit -m "feat: GooglePlayIntegrityVerifier con mapeo testeado + módulo de atestación"
```

---

## Task 9: Common — AdminApiKeyGuard

**Files:**
- Create: `src/common/guards/admin-api-key.guard.ts`
- Test: `test/unit/admin-api-key.guard.spec.ts`

**Interfaces:**
- Produces: `AdminApiKeyGuard implements CanActivate` (lee `x-api-key`, compara con `ADMIN_API_KEY`).

- [ ] **Step 1: Escribir el test (debe fallar)**

`test/unit/admin-api-key.guard.spec.ts`:
```typescript
import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AdminApiKeyGuard } from '../../src/common/guards/admin-api-key.guard';

const ctx = (apiKey?: string) =>
  ({
    switchToHttp: () => ({ getRequest: () => ({ header: (_: string) => apiKey }) }),
  }) as any;
const cfg = { get: () => 'k'.repeat(32) } as unknown as ConfigService;

describe('AdminApiKeyGuard', () => {
  const guard = new AdminApiKeyGuard(cfg);
  it('permite con la key correcta', () => {
    expect(guard.canActivate(ctx('k'.repeat(32)))).toBe(true);
  });
  it('rechaza sin key', () => {
    expect(() => guard.canActivate(ctx(undefined))).toThrow(UnauthorizedException);
  });
  it('rechaza con key equivocada', () => {
    expect(() => guard.canActivate(ctx('mala'))).toThrow(UnauthorizedException);
  });
});
```

- [ ] **Step 2: Correr → FAIL** (`npm test -- admin-api-key`).

- [ ] **Step 3: Implementar**

`src/common/guards/admin-api-key.guard.ts`:
```typescript
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import type { Env } from '../../config/env.schema';

@Injectable()
export class AdminApiKeyGuard implements CanActivate {
  constructor(private readonly config: ConfigService<Env, true>) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const provided = req.header('x-api-key');
    const expected = this.config.get('ADMIN_API_KEY', { infer: true });
    if (!provided || provided !== expected) {
      throw new UnauthorizedException({ message: 'API key inválida', code: 'UNAUTHORIZED' });
    }
    return true;
  }
}
```

- [ ] **Step 4: Correr → PASS** (`npm test -- admin-api-key`).

- [ ] **Step 5: Commit** — `git commit -am "feat: AdminApiKeyGuard"`

---

## Task 10: BlacklistModule — lectura versionada + gestión admin

**Files:**
- Create: `src/blacklist/blacklist.service.ts`, `src/blacklist/blacklist.controller.ts`, `src/blacklist/blacklist.module.ts`, `src/blacklist/dto/blacklist.dto.ts`
- Modify: `src/app.module.ts`
- Test: `test/e2e/blacklist.e2e-spec.ts`

**Interfaces:**
- Consumes: `PrismaService` (Task 2), `AdminApiKeyGuard` (Task 9).
- Produces:
  - `BlacklistService.list(): Promise<{ version: number; entries: {...}[] }>`
  - `BlacklistService.activeSet(): Promise<Set<string>>` (usado por Sessions en Task 12)
  - `BlacklistService.currentVersion(): Promise<number>`
  - `BlacklistService.add(dto): Promise<Entry>` (bumpea versión), `remove(id)` (soft-delete + bump)

- [ ] **Step 1: DTOs + servicio + controller**

`src/blacklist/dto/blacklist.dto.ts`:
```typescript
import { IsIn, IsString, MinLength } from 'class-validator';

export class CreateBlacklistEntryDto {
  @IsString() @MinLength(3)
  packageName!: string;

  @IsString() @MinLength(1)
  label!: string;

  @IsIn(['LOW', 'MEDIUM', 'HIGH'])
  severity!: 'LOW' | 'MEDIUM' | 'HIGH';
}
```

`src/blacklist/blacklist.service.ts`:
```typescript
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { CreateBlacklistEntryDto } from './dto/blacklist.dto';

@Injectable()
export class BlacklistService {
  constructor(private readonly prisma: PrismaService) {}

  private async bumpVersion(): Promise<number> {
    // Fila singleton id=1; se crea si no existe y se incrementa.
    const state = await this.prisma.blacklistState.upsert({
      where: { id: 1 },
      create: { id: 1, version: 1 },
      update: { version: { increment: 1 } },
    });
    return state.version;
  }

  async currentVersion(): Promise<number> {
    const state = await this.prisma.blacklistState.findUnique({ where: { id: 1 } });
    return state?.version ?? 1;
  }

  async list(): Promise<{ version: number; entries: Array<{ packageName: string; label: string; severity: string }> }> {
    const [version, rows] = await Promise.all([
      this.currentVersion(),
      this.prisma.blacklistEntry.findMany({ where: { active: true }, orderBy: { addedAt: 'asc' } }),
    ]);
    return {
      version,
      entries: rows.map((r) => ({ packageName: r.packageName, label: r.label, severity: r.severity })),
    };
  }

  async activeSet(): Promise<Set<string>> {
    const rows = await this.prisma.blacklistEntry.findMany({
      where: { active: true },
      select: { packageName: true },
    });
    return new Set(rows.map((r) => r.packageName));
  }

  async add(dto: CreateBlacklistEntryDto) {
    const entry = await this.prisma.blacklistEntry.upsert({
      where: { packageName: dto.packageName },
      create: { ...dto, active: true },
      update: { label: dto.label, severity: dto.severity, active: true },
    });
    await this.bumpVersion();
    return entry;
  }

  async remove(id: string): Promise<void> {
    await this.prisma.blacklistEntry.update({ where: { id }, data: { active: false } });
    await this.bumpVersion();
  }
}
```

`src/blacklist/blacklist.controller.ts`:
```typescript
import { Body, Controller, Delete, Get, Param, Post, UseGuards } from '@nestjs/common';
import { AdminApiKeyGuard } from '../common/guards/admin-api-key.guard';
import { BlacklistService } from './blacklist.service';
import { CreateBlacklistEntryDto } from './dto/blacklist.dto';

@Controller('blacklist')
export class BlacklistController {
  constructor(private readonly blacklist: BlacklistService) {}

  @Get()
  list() {
    return this.blacklist.list();
  }

  @Post()
  @UseGuards(AdminApiKeyGuard)
  add(@Body() dto: CreateBlacklistEntryDto) {
    return this.blacklist.add(dto);
  }

  @Delete(':id')
  @UseGuards(AdminApiKeyGuard)
  async remove(@Param('id') id: string) {
    await this.blacklist.remove(id);
    return { removed: true };
  }
}
```

`src/blacklist/blacklist.module.ts`:
```typescript
import { Module } from '@nestjs/common';
import { BlacklistService } from './blacklist.service';
import { BlacklistController } from './blacklist.controller';

@Module({ providers: [BlacklistService], controllers: [BlacklistController], exports: [BlacklistService] })
export class BlacklistModule {}
```
Agregar `BlacklistModule` a `AppModule`.

- [ ] **Step 2: Escribir el test e2e (debe fallar)**

`test/e2e/blacklist.e2e-spec.ts`:
```typescript
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../src/app.module';

const KEY = 'k'.repeat(32);
describe('Blacklist (e2e)', () => {
  let app: INestApplication;
  beforeAll(async () => {
    process.env.ADMIN_API_KEY = KEY;
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
  });
  afterAll(async () => app.close());

  it('GET /blacklist → version + entries', async () => {
    const res = await request(app.getHttpServer()).get('/blacklist');
    expect(res.status).toBe(200);
    expect(typeof res.body.version).toBe('number');
    expect(Array.isArray(res.body.entries)).toBe(true);
  });
  it('POST sin api key → 401', async () => {
    const res = await request(app.getHttpServer())
      .post('/blacklist')
      .send({ packageName: 'com.x', label: 'x', severity: 'HIGH' });
    expect(res.status).toBe(401);
  });
  it('POST con api key agrega y sube la versión', async () => {
    const before = (await request(app.getHttpServer()).get('/blacklist')).body.version;
    const res = await request(app.getHttpServer())
      .post('/blacklist')
      .set('x-api-key', KEY)
      .send({ packageName: `com.cheat.${Date.now()}`, label: 'aim', severity: 'HIGH' });
    expect(res.status).toBe(201);
    const after = (await request(app.getHttpServer()).get('/blacklist')).body.version;
    expect(after).toBeGreaterThan(before);
  });
});
```

- [ ] **Step 3: Correr → PASS** (`npm run test:e2e -- blacklist`). Ajustar hasta verde.

- [ ] **Step 4: Commit** — `git commit -am "feat: BlacklistModule (lectura versionada + gestión admin)"`

---

## Task 11: DevicesModule — enrolamiento idempotente + consulta admin

**Files:**
- Create: `src/devices/devices.service.ts`, `src/devices/devices.controller.ts`, `src/devices/devices.module.ts`, `src/devices/dto/enroll.dto.ts`
- Modify: `src/app.module.ts`
- Test: `test/e2e/devices.e2e-spec.ts`

**Interfaces:**
- Consumes: `PrismaService`, `SignatureService` (fingerprint), `AdminApiKeyGuard`.
- Produces:
  - `DevicesService.enroll(dto): Promise<{ deviceId: string; createdAt: Date }>` (idempotente por fingerprint)
  - `DevicesService.getByIdOrThrow(id): Promise<Device>` (usado por Sessions)
  - `DevicesService.history(id): Promise<...>`

- [ ] **Step 1: DTO + servicio + controller**

`src/devices/dto/enroll.dto.ts`:
```typescript
import { IsIn, IsObject, IsOptional, IsString, MinLength } from 'class-validator';

export class EnrollDeviceDto {
  @IsString() @MinLength(40) // SPKI DER en base64 (~44+ chars para P-256)
  publicKey!: string;

  @IsIn(['ANDROID', 'IOS'])
  platform!: 'ANDROID' | 'IOS';

  @IsOptional() @IsString()
  keyAlgo?: string;

  @IsOptional() @IsObject()
  attestation?: { type: string; certificateChain?: string[] };
}
```

`src/devices/devices.service.ts`:
```typescript
import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SignatureService } from '../common/crypto/signature.service';
import type { EnrollDeviceDto } from './dto/enroll.dto';

@Injectable()
export class DevicesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly signature: SignatureService,
  ) {}

  async enroll(dto: EnrollDeviceDto): Promise<{ deviceId: string; createdAt: Date }> {
    const fp = this.signature.fingerprint(dto.publicKey);
    // Idempotente: misma clave → mismo device.
    const device = await this.prisma.device.upsert({
      where: { publicKeyFp: fp },
      create: {
        publicKey: dto.publicKey,
        publicKeyFp: fp,
        platform: dto.platform,
        keyAlgo: dto.keyAlgo ?? 'ES256',
        attestationType: dto.attestation?.type === 'PLAY_INTEGRITY' ? 'PLAY_INTEGRITY' : 'NONE',
        attestationData: dto.attestation ? (dto.attestation as object) : undefined,
      },
      update: { lastSeenAt: new Date() },
    });
    return { deviceId: device.id, createdAt: device.createdAt };
  }

  async getByIdOrThrow(id: string) {
    const device = await this.prisma.device.findUnique({ where: { id } });
    if (!device) throw new NotFoundException({ message: 'Device no encontrado', code: 'DEVICE_NOT_FOUND' });
    return device;
  }

  async history(id: string) {
    const device = await this.getByIdOrThrow(id);
    const sessions = await this.prisma.session.findMany({
      where: { deviceId: id },
      orderBy: { startedAt: 'desc' },
      include: { flags: true },
    });
    return { deviceId: device.id, platform: device.platform, revoked: device.revoked, sessions };
  }
}
```

`src/devices/devices.controller.ts`:
```typescript
import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { AdminApiKeyGuard } from '../common/guards/admin-api-key.guard';
import { DevicesService } from './devices.service';
import { EnrollDeviceDto } from './dto/enroll.dto';

@Controller('devices')
export class DevicesController {
  constructor(private readonly devices: DevicesService) {}

  @Post('enroll')
  enroll(@Body() dto: EnrollDeviceDto) {
    return this.devices.enroll(dto);
  }

  @Get(':id')
  @UseGuards(AdminApiKeyGuard)
  history(@Param('id') id: string) {
    return this.devices.history(id);
  }
}
```

`src/devices/devices.module.ts`:
```typescript
import { Module } from '@nestjs/common';
import { DevicesService } from './devices.service';
import { DevicesController } from './devices.controller';

@Module({ providers: [DevicesService], controllers: [DevicesController], exports: [DevicesService] })
export class DevicesModule {}
```
Agregar `DevicesModule` a `AppModule`.

- [ ] **Step 2: Test e2e (debe fallar)**

`test/e2e/devices.e2e-spec.ts`:
```typescript
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { generateKeyPairSync } from 'node:crypto';
import { AppModule } from '../../src/app.module';

const spki = () =>
  generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey
    .export({ format: 'der', type: 'spki' }).toString('base64');

describe('Devices (e2e)', () => {
  let app: INestApplication;
  beforeAll(async () => {
    process.env.ADMIN_API_KEY = 'k'.repeat(32);
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
  });
  afterAll(async () => app.close());

  it('enroll → deviceId', async () => {
    const res = await request(app.getHttpServer())
      .post('/devices/enroll').send({ publicKey: spki(), platform: 'ANDROID' });
    expect(res.status).toBe(201);
    expect(res.body.deviceId).toBeDefined();
  });
  it('enroll dos veces con la misma clave → mismo deviceId', async () => {
    const key = spki();
    const a = await request(app.getHttpServer()).post('/devices/enroll').send({ publicKey: key, platform: 'ANDROID' });
    const b = await request(app.getHttpServer()).post('/devices/enroll').send({ publicKey: key, platform: 'ANDROID' });
    expect(a.body.deviceId).toBe(b.body.deviceId);
  });
});
```

- [ ] **Step 3: Correr → PASS** (`npm run test:e2e -- devices`).

- [ ] **Step 4: Commit** — `git commit -am "feat: DevicesModule (enroll idempotente + historial admin)"`

---

## Task 12: SessionsModule — start (auth por firma del device)

**Files:**
- Create: `src/sessions/sessions.service.ts`, `src/sessions/sessions.controller.ts`, `src/sessions/sessions.module.ts`, `src/sessions/dto/session.dto.ts`
- Modify: `src/app.module.ts`
- Test: `test/e2e/sessions-start.e2e-spec.ts`

**Interfaces:**
- Consumes: `PrismaService`, `SignatureService`, `NonceService`, `DevicesService`, `BlacklistService`.
- Produces:
  - `SessionsService.start(dto): Promise<{ sessionId; nonce; expectedIntervalSec; jitterSec; blacklistVersion }>`
  - DTO `StartSessionDto { deviceId; clientTimestamp; signatureB64 }`

- [ ] **Step 1: DTO + método `start`**

`src/sessions/dto/session.dto.ts`:
```typescript
import { IsISO8601, IsOptional, IsString, MinLength } from 'class-validator';

export class StartSessionDto {
  @IsString() deviceId!: string;
  @IsISO8601() clientTimestamp!: string;
  @IsString() @MinLength(1) signatureB64!: string;
}

export class SnapshotDto {
  @IsString() @MinLength(1) payloadB64!: string;
  @IsString() @MinLength(1) signatureB64!: string;
  @IsOptional() @IsString() integrityToken?: string | null;
}

export class EndSessionDto {
  @IsISO8601() clientTimestamp!: string;
  @IsString() @MinLength(1) signatureB64!: string;
}
```

`src/sessions/sessions.service.ts` (parte 1 — `start`):
```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { SignatureService } from '../common/crypto/signature.service';
import { NonceService } from '../common/crypto/nonce.service';
import { DevicesService } from '../devices/devices.service';
import { BlacklistService } from '../blacklist/blacklist.service';
import type { Env } from '../config/env.schema';
import type { StartSessionDto } from './dto/session.dto';

@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly signature: SignatureService,
    private readonly nonce: NonceService,
    private readonly devices: DevicesService,
    private readonly blacklist: BlacklistService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  async start(dto: StartSessionDto) {
    const device = await this.devices.getByIdOrThrow(dto.deviceId);
    // El device prueba posesión de su clave firmando (deviceId + clientTimestamp).
    const challenge = Buffer.from(`${dto.deviceId}${dto.clientTimestamp}`);
    if (!this.signature.verify(device.publicKey, challenge, dto.signatureB64)) {
      throw new UnauthorizedException({ message: 'Firma de device inválida', code: 'DEVICE_AUTH_FAILED' });
    }
    const nonce = this.nonce.generate();
    const blacklistVersion = await this.blacklist.currentVersion();
    const session = await this.prisma.session.create({
      data: { deviceId: device.id, currentNonce: nonce, blacklistVersion, status: 'ACTIVE' },
    });
    return {
      sessionId: session.id,
      nonce,
      expectedIntervalSec: session.expectedIntervalSec,
      jitterSec: session.jitterSec,
      blacklistVersion,
    };
  }
}
```

`src/sessions/sessions.controller.ts` (parte 1):
```typescript
import { Body, Controller, Post } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { StartSessionDto } from './dto/session.dto';

@Controller('sessions')
export class SessionsController {
  constructor(private readonly sessions: SessionsService) {}

  @Post('start')
  start(@Body() dto: StartSessionDto) {
    return this.sessions.start(dto);
  }
}
```

`src/sessions/sessions.module.ts`:
```typescript
import { Module } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { SessionsController } from './sessions.controller';
import { DevicesModule } from '../devices/devices.module';
import { BlacklistModule } from '../blacklist/blacklist.module';

@Module({
  imports: [DevicesModule, BlacklistModule],
  providers: [SessionsService],
  controllers: [SessionsController],
})
export class SessionsModule {}
```
Agregar `SessionsModule` a `AppModule`.

- [ ] **Step 2: Test e2e de start (debe fallar)**

`test/e2e/sessions-start.e2e-spec.ts`:
```typescript
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { generateKeyPairSync, sign as cryptoSign, KeyObject } from 'node:crypto';
import { AppModule } from '../../src/app.module';

const enroll = async (app: INestApplication, publicKey: KeyObject) => {
  const spki = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const res = await request(app.getHttpServer()).post('/devices/enroll').send({ publicKey: spki, platform: 'ANDROID' });
  return res.body.deviceId as string;
};

describe('Sessions start (e2e)', () => {
  let app: INestApplication;
  beforeAll(async () => {
    process.env.ADMIN_API_KEY = 'k'.repeat(32);
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
  });
  afterAll(async () => app.close());

  it('start con firma válida → sessionId + nonce', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const deviceId = await enroll(app, publicKey);
    const clientTimestamp = new Date().toISOString();
    const signatureB64 = cryptoSign('sha256', Buffer.from(`${deviceId}${clientTimestamp}`), {
      key: privateKey, dsaEncoding: 'der',
    }).toString('base64');
    const res = await request(app.getHttpServer())
      .post('/sessions/start').send({ deviceId, clientTimestamp, signatureB64 });
    expect(res.status).toBe(201);
    expect(res.body.sessionId).toBeDefined();
    expect(res.body.nonce).toBeDefined();
  });

  it('start con firma inválida → 401', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const deviceId = await enroll(app, publicKey);
    const res = await request(app.getHttpServer())
      .post('/sessions/start')
      .send({ deviceId, clientTimestamp: new Date().toISOString(), signatureB64: 'ZmFrZQ==' });
    expect(res.status).toBe(401);
  });
});
```

- [ ] **Step 3: Correr → PASS** (`npm run test:e2e -- sessions-start`).

- [ ] **Step 4: Commit** — `git commit -am "feat: sessions/start con auth por firma de device"`

---

## Task 13: SessionsModule — snapshot (pipeline de ingesta)

**Files:**
- Modify: `src/sessions/sessions.service.ts` (agregar `processSnapshot`), `src/sessions/sessions.controller.ts` (endpoint + mapeo de errores)
- Modify: `src/sessions/sessions.module.ts` (importar `AttestationModule` está global; inyectar `ATTESTATION_VERIFIER`)
- Test: `test/e2e/sessions-snapshot.e2e-spec.ts`

**Interfaces:**
- Consumes: todo lo anterior + `ATTESTATION_VERIFIER` (Task 7), `evaluateSignals` (Task 4).
- Produces: `SessionsService.processSnapshot(sessionId, dto): Promise<{ accepted: true; nextNonce: string; seq: number }>`. Lanza `UnauthorizedException` (401, firma), `ConflictException` (409, nonce), `GoneException` (410, no ACTIVE).

- [ ] **Step 1: Implementar `processSnapshot`**

Agregar al constructor: `@Inject(ATTESTATION_VERIFIER) private readonly attestation: AttestationVerifier`. Agregar imports de `createHash`, excepciones, `evaluateSignals`, `SignalSet`.

`src/sessions/sessions.service.ts` (agregar método):
```typescript
async processSnapshot(sessionId: string, dto: SnapshotDto) {
  const session = await this.prisma.session.findUnique({ where: { id: sessionId }, include: { device: true } });
  if (!session) throw new NotFoundException({ message: 'Sesión no encontrada', code: 'SESSION_NOT_FOUND' });
  if (session.status !== 'ACTIVE') {
    throw new GoneException({ message: 'Sesión no activa', code: 'SESSION_NOT_ACTIVE' });
  }

  const payloadBytes = Buffer.from(dto.payloadB64, 'base64');

  // 1) Verificar firma sobre los bytes exactos. Si falla, se registra como evidencia y se corta.
  const signatureValid = this.signature.verify(session.device.publicKey, payloadBytes, dto.signatureB64);
  if (!signatureValid) {
    await this.recordRejected(session.id, session.currentNonce, 'SIGNATURE_INVALID', payloadBytes);
    throw new UnauthorizedException({ message: 'Firma inválida', code: 'SIGNATURE_INVALID' });
  }

  // 2) Parsear el payload (recién ahora que la firma es válida).
  const payload = this.parsePayload(payloadBytes);

  // 3) Validar binding y nonce.
  if (payload.sessionId !== session.id || payload.deviceId !== session.deviceId) {
    throw new UnauthorizedException({ message: 'Binding inválido', code: 'BINDING_MISMATCH' });
  }
  if (payload.nonce !== session.currentNonce) {
    await this.recordRejected(session.id, `${session.currentNonce}:reuse`, 'NONCE_REUSE', payloadBytes);
    throw new ConflictException({ message: 'Nonce inválido o reusado', code: 'NONCE_REUSE' });
  }

  // 4) Validar skew temporal.
  const skewSec = Math.abs(Date.now() - new Date(payload.clientTimestamp).getTime()) / 1000;
  const maxSkew = this.config.get('CLOCK_SKEW_TOLERANCE_SEC', { infer: true });
  if (skewSec > maxSkew) {
    throw new UnauthorizedException({ message: 'Timestamp fuera de ventana', code: 'CLOCK_SKEW' });
  }

  // 5) Validar que el hash del integrityToken coincida con el firmado.
  const token = dto.integrityToken ?? null;
  if (token !== null) {
    const tokenHash = createHash('sha256').update(token).digest('hex');
    if (tokenHash !== payload.integrityTokenHash) {
      throw new UnauthorizedException({ message: 'integrityTokenHash no coincide', code: 'TOKEN_HASH_MISMATCH' });
    }
  }

  // 6) Atestación — un fallo de infra se trata como DEGRADED (nunca se descarta).
  let integrityVerdict: IntegrityVerdict = 'DEGRADED';
  try {
    const result = await this.attestation.verify({
      token, nonce: session.currentNonce, platform: session.device.platform,
    });
    integrityVerdict = result.verdict;
  } catch {
    integrityVerdict = 'DEGRADED';
  }

  // 7) Evaluar señales → flags.
  const blacklist = await this.blacklist.activeSet();
  const flags = evaluateSignals(payload.signals, integrityVerdict, blacklist);

  // 8) Persistir snapshot + flags + próximo nonce (los @@unique atrapan replays por carrera).
  const nextNonce = this.nonce.generate();
  const seq = payload.seq;
  await this.prisma.$transaction([
    this.prisma.snapshot.create({
      data: {
        sessionId: session.id, seq, clientTimestamp: new Date(payload.clientTimestamp),
        signals: payload.signals as object, signedPayload: payloadBytes, signatureValid: true,
        nonceUsed: session.currentNonce, integrityVerdict,
        flags: { create: flags.map((f) => ({ sessionId: session.id, type: f.type, severity: f.severity, details: f.details as object | undefined })) },
      },
    }),
    this.prisma.session.update({
      where: { id: session.id }, data: { currentNonce: nextNonce, lastSeenAt: new Date() },
    }),
  ]);

  return { accepted: true as const, nextNonce, seq };
}

// Registra un intento rechazado como evidencia inmutable + flag, sin avanzar el nonce.
private async recordRejected(sessionId: string, nonceUsed: string, type: 'SIGNATURE_INVALID' | 'NONCE_REUSE', bytes: Buffer): Promise<void> {
  try {
    await this.prisma.snapshot.create({
      data: {
        sessionId, seq: -1, clientTimestamp: new Date(), signals: {}, signedPayload: bytes,
        signatureValid: false, nonceUsed, integrityVerdict: 'UNKNOWN',
        flags: { create: [{ sessionId, type, severity: 'HIGH' }] },
      },
    });
  } catch {
    // Si choca con un @@unique (replay), el rechazo ya quedó registrado; no relanzar.
  }
}

private parsePayload(bytes: Buffer): {
  deviceId: string; sessionId: string; seq: number; nonce: string;
  clientTimestamp: string; integrityTokenHash?: string; signals: SignalSet;
} {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new BadRequestException({ message: 'Payload no es JSON válido', code: 'BAD_PAYLOAD' });
  }
}
```

Controller (agregar):
```typescript
@Post(':id/snapshot')
snapshot(@Param('id') id: string, @Body() dto: SnapshotDto) {
  return this.sessions.processSnapshot(id, dto);
}
```

- [ ] **Step 2: Test e2e de snapshot (debe fallar)**

`test/e2e/sessions-snapshot.e2e-spec.ts` — helper que enrola, inicia sesión, y manda un snapshot firmado. Casos: snapshot limpio → 200 + nextNonce; snapshot con `root.detected` luego marcará FLAGGED en end (se valida en Task 14); replay del mismo payload → 409.
```typescript
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { AppModule } from '../../src/app.module';

const signBytes = (privateKey: any, bytes: Buffer) =>
  cryptoSign('sha256', bytes, { key: privateKey, dsaEncoding: 'der' }).toString('base64');

describe('Sessions snapshot (e2e)', () => {
  let app: INestApplication;
  beforeAll(async () => {
    process.env.ADMIN_API_KEY = 'k'.repeat(32);
    process.env.ATTESTATION_STUB_VERDICT = 'MEETS_STRONG';
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
  });
  afterAll(async () => app.close());

  const setup = async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spki = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const deviceId = (await request(app.getHttpServer()).post('/devices/enroll')
      .send({ publicKey: spki, platform: 'ANDROID' })).body.deviceId;
    const clientTimestamp = new Date().toISOString();
    const startSig = signBytes(privateKey, Buffer.from(`${deviceId}${clientTimestamp}`));
    const start = (await request(app.getHttpServer()).post('/sessions/start')
      .send({ deviceId, clientTimestamp, signatureB64: startSig })).body;
    return { privateKey, deviceId, sessionId: start.sessionId, nonce: start.nonce };
  };

  const buildSnapshot = (privateKey: any, deviceId: string, sessionId: string, seq: number, nonce: string, signals: object) => {
    const payload = { deviceId, sessionId, seq, nonce, clientTimestamp: new Date().toISOString(),
      integrityTokenHash: createHash('sha256').update('tok').digest('hex'), signals };
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    return { payloadB64, signatureB64: signBytes(privateKey, Buffer.from(payloadB64, 'base64')), integrityToken: 'tok' };
  };

  it('snapshot limpio → 200 + nextNonce', async () => {
    const s = await setup();
    const body = buildSnapshot(s.privateKey, s.deviceId, s.sessionId, 0, s.nonce, { root: { detected: false } });
    const res = await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/snapshot`).send(body);
    expect(res.status).toBe(200);
    expect(res.body.nextNonce).toBeDefined();
  });

  it('replay (mismo nonce) → 409', async () => {
    const s = await setup();
    const body = buildSnapshot(s.privateKey, s.deviceId, s.sessionId, 0, s.nonce, { root: { detected: false } });
    await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/snapshot`).send(body);
    const replay = await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/snapshot`).send(body);
    expect(replay.status).toBe(409);
  });
});
```

- [ ] **Step 3: Correr → PASS** (`npm run test:e2e -- sessions-snapshot`). Ajustar imports/excepciones (`BadRequestException`, `ConflictException`, `GoneException`, `NotFoundException`, `Inject`) hasta verde.

- [ ] **Step 4: Commit** — `git commit -am "feat: pipeline de ingesta de snapshots (firma+nonce+atestación+flags)"`

---

## Task 14: SessionsModule — end (gap + veredicto) + GET verdict

**Files:**
- Modify: `src/sessions/sessions.service.ts` (agregar `end`, `getVerdict`), `src/sessions/sessions.controller.ts`
- Test: `test/e2e/sessions-end.e2e-spec.ts`

**Interfaces:**
- Consumes: `analyzeGaps` (Task 5), `computeVerdict` (Task 6), `DEFAULT_POLICY` (Task 4).
- Produces:
  - `SessionsService.end(sessionId, dto): Promise<{ sessionId; status; verdict; flags }>`
  - `SessionsService.getVerdict(sessionId): Promise<{ sessionId; status; verdict }>`

- [ ] **Step 1: Implementar `end` + `getVerdict`**

`src/sessions/sessions.service.ts` (agregar):
```typescript
async end(sessionId: string, dto: EndSessionDto) {
  const session = await this.prisma.session.findUnique({
    where: { id: sessionId }, include: { device: true, snapshots: true, flags: true },
  });
  if (!session) throw new NotFoundException({ message: 'Sesión no encontrada', code: 'SESSION_NOT_FOUND' });
  if (session.status !== 'ACTIVE') throw new GoneException({ message: 'Sesión ya cerrada', code: 'SESSION_NOT_ACTIVE' });

  // El device firma (sessionId + clientTimestamp) para cerrar.
  const challenge = Buffer.from(`${sessionId}${dto.clientTimestamp}`);
  if (!this.signature.verify(session.device.publicKey, challenge, dto.signatureB64)) {
    throw new UnauthorizedException({ message: 'Firma inválida', code: 'DEVICE_AUTH_FAILED' });
  }

  const endedAt = new Date();
  const validSnaps = session.snapshots.filter((s) => s.signatureValid);
  const gap = analyzeGaps({
    startedAt: session.startedAt.getTime(),
    endedAt: endedAt.getTime(),
    snapshotTimestamps: validSnaps.map((s) => s.receivedAt.getTime()).sort((a, b) => a - b),
    expectedIntervalSec: session.expectedIntervalSec,
    timeoutMultiplier: this.config.get('SESSION_TIMEOUT_MULTIPLIER', { infer: true }),
    minCoverageRatio: this.config.get('SESSION_MIN_COVERAGE_RATIO', { infer: true }),
    gapSuspiciousMultiplier: DEFAULT_POLICY.gapSuspiciousMultiplier,
    gapWarnCoverageRatio: DEFAULT_POLICY.gapWarnCoverageRatio,
  });

  // Si hay gap medio, agregar un flag SNAPSHOT_GAP a la sesión.
  if (gap.gapFlag) {
    await this.prisma.flag.create({ data: { sessionId, type: 'SNAPSHOT_GAP', severity: 'MEDIUM' } });
  }

  // Recolectar flags por snapshot para el veredicto.
  const allFlags = await this.prisma.flag.findMany({ where: { sessionId } });
  const snapshotViews = session.snapshots.map((s) => ({
    flags: allFlags.filter((f) => f.snapshotId === s.id).map((f) => ({ type: f.type, severity: f.severity })),
  }));
  // Flags a nivel sesión (p.ej. SNAPSHOT_GAP) → como un "snapshot" extra de flags.
  const sessionLevelFlags = allFlags.filter((f) => f.snapshotId === null)
    .map((f) => ({ type: f.type, severity: f.severity }));
  const views = [...snapshotViews, { flags: sessionLevelFlags }];

  const verdict = computeVerdict(gap.status, views);
  await this.prisma.session.update({
    where: { id: sessionId }, data: { status: gap.status, verdict, endedAt },
  });
  return { sessionId, status: gap.status, verdict, flags: allFlags };
}

async getVerdict(sessionId: string) {
  const session = await this.prisma.session.findUnique({
    where: { id: sessionId }, select: { id: true, status: true, verdict: true },
  });
  if (!session) throw new NotFoundException({ message: 'Sesión no encontrada', code: 'SESSION_NOT_FOUND' });
  return { sessionId: session.id, status: session.status, verdict: session.verdict };
}
```

Controller (agregar):
```typescript
@Post(':id/end')
end(@Param('id') id: string, @Body() dto: EndSessionDto) {
  return this.sessions.end(id, dto);
}

@Get(':id/verdict')
verdict(@Param('id') id: string) {
  return this.sessions.getVerdict(id);
}
```

- [ ] **Step 2: Test e2e (debe fallar)** — sesión con un snapshot `root.detected:true` → `end` → `verdict FLAGGED`; sesión limpia → `CLEAN`.

`test/e2e/sessions-end.e2e-spec.ts` (reusar helpers de Task 13; mostrar el caso FLAGGED):
```typescript
it('sesión con root → end → FLAGGED', async () => {
  const s = await setup();
  const snap = buildSnapshot(s.privateKey, s.deviceId, s.sessionId, 0, s.nonce, { root: { detected: true } });
  await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/snapshot`).send(snap);
  const clientTimestamp = new Date().toISOString();
  const endSig = signBytes(s.privateKey, Buffer.from(`${s.sessionId}${clientTimestamp}`));
  const res = await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/end`)
    .send({ clientTimestamp, signatureB64: endSig });
  expect(res.status).toBe(201);
  expect(res.body.verdict).toBe('FLAGGED');

  const v = await request(app.getHttpServer()).get(`/sessions/${s.sessionId}/verdict`);
  expect(v.body.verdict).toBe('FLAGGED');
});
```

- [ ] **Step 3: Correr → PASS** (`npm run test:e2e -- sessions-end`).

- [ ] **Step 4: Commit** — `git commit -am "feat: sessions/end (gap + veredicto) + GET verdict"`

---

## Task 15: ReaperService — sesiones huérfanas → ABORTED

**Files:**
- Create: `src/sessions/reaper.service.ts`
- Modify: `src/sessions/sessions.module.ts` (registrar `ReaperService`), `src/app.module.ts` (`ScheduleModule.forRoot()`)
- Test: `test/e2e/reaper.e2e-spec.ts`

**Interfaces:**
- Consumes: `PrismaService`, `ConfigService`.
- Produces: `ReaperService.reap(now?: Date): Promise<number>` (devuelve cuántas marcó ABORTED). El `@Cron` llama a `reap()`.

- [ ] **Step 1: Instalar schedule + implementar**

```bash
npm i @nestjs/schedule
```

`src/sessions/reaper.service.ts`:
```typescript
import { Injectable } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import type { Env } from '../config/env.schema';

@Injectable()
export class ReaperService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  @Cron(CronExpression.EVERY_30_SECONDS)
  async handleCron(): Promise<void> {
    await this.reap();
  }

  // Marca ABORTED + veredicto INVALID las sesiones ACTIVE sin actividad > timeout.
  async reap(now: Date = new Date()): Promise<number> {
    const multiplier = this.config.get('SESSION_TIMEOUT_MULTIPLIER', { infer: true });
    const stale = await this.prisma.session.findMany({ where: { status: 'ACTIVE' } });
    let count = 0;
    for (const session of stale) {
      const timeoutMs = multiplier * session.expectedIntervalSec * 1000;
      if (now.getTime() - session.lastSeenAt.getTime() > timeoutMs) {
        await this.prisma.session.update({
          where: { id: session.id }, data: { status: 'ABORTED', verdict: 'INVALID', endedAt: now },
        });
        count += 1;
      }
    }
    return count;
  }
}
```
Registrar `ReaperService` en `SessionsModule.providers`; agregar `ScheduleModule.forRoot()` a `AppModule.imports`.

- [ ] **Step 2: Test e2e (debe fallar)** — crear sesión, forzar `lastSeenAt` viejo, llamar `reap(now)` → estado ABORTED/INVALID.

`test/e2e/reaper.e2e-spec.ts`:
```typescript
it('sesión vieja → reap la marca ABORTED/INVALID', async () => {
  const s = await setup(); // enrola + start
  const reaper = app.get(ReaperService);
  const prisma = app.get(PrismaService);
  // Forzar lastSeenAt muy viejo (más de 3×45s).
  await prisma.session.update({ where: { id: s.sessionId }, data: { lastSeenAt: new Date(Date.now() - 3600_000) } });
  const marked = await reaper.reap(new Date());
  expect(marked).toBeGreaterThanOrEqual(1);
  const v = await request(app.getHttpServer()).get(`/sessions/${s.sessionId}/verdict`);
  expect(v.body.status).toBe('ABORTED');
  expect(v.body.verdict).toBe('INVALID');
});
```

- [ ] **Step 3: Correr → PASS** (`npm run test:e2e -- reaper`).

- [ ] **Step 4: Commit** — `git commit -am "feat: ReaperService marca sesiones huérfanas como ABORTED/INVALID"`

---

## Task 16: Cross-cutting — rate limiting + E2E de ciclo completo

**Files:**
- Modify: `src/app.module.ts` (`ThrottlerModule`), `src/devices/devices.controller.ts` y `src/sessions/sessions.controller.ts` (`@Throttle` en enroll/snapshot)
- Create: `test/e2e/full-lifecycle.e2e-spec.ts`

**Interfaces:**
- Produces: rate limit configurado por `THROTTLE_TTL`/`THROTTLE_LIMIT`; test de integración del ciclo completo.

- [ ] **Step 1: Configurar throttler**

```bash
npm i @nestjs/throttler
```
`AppModule`: agregar
```typescript
ThrottlerModule.forRootAsync({
  inject: [ConfigService],
  useFactory: (config: ConfigService<Env, true>) => [
    { ttl: config.get('THROTTLE_TTL', { infer: true }) * 1000, limit: config.get('THROTTLE_LIMIT', { infer: true }) },
  ],
}),
```
y el guard global:
```typescript
{ provide: APP_GUARD, useClass: ThrottlerGuard },
```

- [ ] **Step 2: Escribir el E2E de ciclo completo (debe fallar/validar todo junto)**

`test/e2e/full-lifecycle.e2e-spec.ts`: enrolar → start → 3 snapshots limpios → 1 snapshot con `hooking.frida:true` → end → `verdict FLAGGED`; y un caso paralelo enteramente limpio → `CLEAN`. Reusar los helpers de Task 13 (extraer a `test/e2e/helpers.ts`).
```typescript
it('ciclo completo con un snapshot de frida → FLAGGED', async () => {
  const s = await setup();
  let nonce = s.nonce;
  for (let seq = 0; seq < 3; seq += 1) {
    const body = buildSnapshot(s.privateKey, s.deviceId, s.sessionId, seq, nonce, { root: { detected: false } });
    nonce = (await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/snapshot`).send(body)).body.nextNonce;
  }
  const dirty = buildSnapshot(s.privateKey, s.deviceId, s.sessionId, 3, nonce, { hooking: { frida: true } });
  await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/snapshot`).send(dirty);
  const clientTimestamp = new Date().toISOString();
  const endSig = signBytes(s.privateKey, Buffer.from(`${s.sessionId}${clientTimestamp}`));
  const end = await request(app.getHttpServer()).post(`/sessions/${s.sessionId}/end`)
    .send({ clientTimestamp, signatureB64: endSig });
  expect(end.body.verdict).toBe('FLAGGED');
});
```

- [ ] **Step 3: Correr toda la suite → PASS**

```bash
npm test && npm run test:e2e
```

- [ ] **Step 4: Crear `.env.example` + README con las limitaciones**

Copiar las env vars de la §13 del spec a `.env.example` y las limitaciones documentadas de la §16 del spec al `README.md` (verbatim, no esconderlas).

- [ ] **Step 5: Commit** — `git commit -am "feat: rate limiting + E2E de ciclo completo + .env.example + README con limitaciones"`

---

## Self-Review (hecho por el autor del plan)

**1. Cobertura del spec:**
- §4 modelo de datos → Task 2 ✅
- §5.1 firma bytes exactos → Task 3 (SignatureService) + Task 13 (uso) ✅
- §5.2 nonce cadena → Task 3 (NonceService) + Task 13/12 ✅
- §6 ciclo de vida + reaper → Task 5 (gap) + Task 14 (end) + Task 15 (reaper) ✅
- §7 atestación interfaz/stub/google/degraded → Task 7 + Task 8 + Task 13 (catch→DEGRADED) ✅
- §8 SignalEvaluator + VerdictService → Task 4 + Task 6 ✅
- §9 endpoints (8) → enroll/get (Task 11), start/snapshot/end/verdict (Task 12–14), blacklist (Task 10) ✅
- §10 auth (firma device + admin key + capability) → Task 12/13/14 + Task 9 ✅
- §11 cross-cutting (validación, throttle, config, error shape, body limit) → Task 1 + Task 16 ✅
- §14 testing → cada task tiene su ciclo TDD; Task 16 el E2E completo ✅
- §16 limitaciones documentadas → Task 16 Step 4 (README) ✅

**2. Placeholder scan:** el único `throw new Error(...no configurado)` es intencional y documentado (`decodeWithGoogle` sin credenciales; su lógica de mapeo sí está testeada). No hay TODOs, "implementar después", ni tests sin código.

**3. Consistencia de tipos:** `evaluateSignals(signals, integrityVerdict, blacklist)`, `computeVerdict(status, snapshots)`, `analyzeGaps(GapInput)`, `AttestationVerifier.verify(AttestationInput)`, `SignatureService.verify(spkiB64, Buffer, sigB64)` se usan con las mismas firmas en las tasks consumidoras (12–15). `DetectedFlag`/`FlagType`/`Severity` compartidos vía `verdict/types.ts`.

---

## Notas de ejecución

- **Postgres para tests:** los e2e necesitan una DB Postgres accesible vía `DATABASE_URL`. Levantar una descartable: `docker run --rm -e POSTGRES_PASSWORD=p -p 5432:5432 postgres:16` y correr `npx prisma migrate deploy` antes de la suite e2e. (El Docker Compose completo es un spec aparte.)
- **Orden de tasks:** 1→2→3 (base), 4→5→6 (dominio puro, sin DB), 7→8 (atestación), 9 (guard), 10→11 (blacklist/devices), 12→13→14→15 (sesiones), 16 (cross-cutting + E2E). Las tasks 4–9 pueden paralelizarse tras la 3.
- **Config de Jest (ajustar en Task 1):** el `jest` por defecto de `nest new` usa `rootDir: src` con `testRegex: .*\.spec\.ts$`, así que **no** levanta los `test/unit/*.spec.ts` de este plan. En Task 1, ajustar la config unit a `rootDir: .` con `testMatch: ['**/src/**/*.spec.ts', '**/test/unit/**/*.spec.ts']` (o colocar los `*.spec.ts` unit junto al código en `src/`, que es la convención de NestJS). Los e2e usan `test/jest-e2e.json` aparte, sin cambios.
