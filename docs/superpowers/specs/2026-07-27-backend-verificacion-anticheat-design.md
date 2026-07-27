# Backend de verificación anticheat — Diseño (Spec 1)

- **Fecha:** 2026-07-27
- **Estado:** Aprobado para plan de implementación
- **Alcance de este spec:** Núcleo de verificación del backend (NestJS + Prisma + PostgreSQL)
- **Fuera de alcance (specs aparte):** App Android, bot de Discord, módulo de análisis estadístico de partidas, infraestructura Docker Compose

---

## 1. Contexto y objetivo

Sistema de verificación anticheat **opt-in** para una comunidad de Free Fire. Un jugador instala voluntariamente una app en su propio dispositivo, la app corre una **sesión de monitoreo** con notificación persistente durante una partida, toma snapshots firmados cada 30–60s (con jitter), y al terminar envía un reporte agregado. El backend recibe esos snapshots, valida su autenticidad, evalúa señales de integridad del dispositivo, y emite un **veredicto por niveles**.

El modelo central es **sesión de monitoreo, no snapshot único**: un escaneo antes o después de la partida tiene huecos (el cheat se activa/desactiva alrededor del escaneo). Monitorear toda la sesión y agregar por *el peor snapshot* cierra ese hueco.

Este spec cubre **solo el backend**, que es la pieza de la que dependen las otras tres (app, bot, stats) a través de contratos HTTP. Se diseña primero para congelar esos contratos.

---

## 2. Decisiones de diseño fijadas

| # | Decisión | Elección | Razón |
|---|---|---|---|
| 1 | Alcance del spec | Solo núcleo de verificación | Revisable y ejecutable con checkpoints; el resto son ciclos spec→plan→impl aparte |
| 2 | Play Integrity | Interfaz `AttestationVerifier` + `StubAttestationVerifier` ahora; `GooglePlayIntegrityVerifier` detrás de la misma interfaz | Backend testeable hoy sin credenciales de Google; la integración real es un swap de clase + config (inversión de dependencias) |
| 3 | Enrolamiento | Centrado en dispositivo, **sin** código de Discord | El backend evalúa el dispositivo. El vínculo con Discord (roles) vive en el spec del bot |
| 4 | Plataformas | Backend **agnóstico** (`platform ANDROID\|IOS`, señales JSONB, verifier pluggable); único cliente construido = Android | El modelo de datos multiplataforma cuesta poco. La cobertura de detección real en iOS es mínima por el sandbox de Apple (ver §16) |

**Consecuencia de la decisión #3:** la entidad central es `Device`, no `Player`. En este spec **no existe** `Player` ni `discordId`. El endpoint `GET /players/:discordId` del prompt original se convierte en `GET /devices/:id`.

---

## 3. Arquitectura

Monolito modular NestJS. Nest en el borde (validación, HTTP, persistencia); **dominio puro sin dependencias de Nest** en el centro (`verdict/`), donde vive la lógica de seguridad que importa.

**Patrón Ports & Adapters para la atestación:** la validación de Play Integrity es un servicio externo detrás de la interfaz `AttestationVerifier`. Providers intercambiables por config sin tocar el resto del sistema.

**Módulos:**
- `DevicesModule` — enrolamiento y consulta de dispositivos.
- `SessionsModule` — start / snapshot / end / verdict, generación de nonce, y el *reaper* de sesiones huérfanas.
- `BlacklistModule` — lectura versionada + gestión admin.
- `AttestationModule` — la interfaz + los providers (stub / google).
- `verdict/` — dominio puro: `VerdictService`, `SignalEvaluator`, `policy`.
- `PrismaModule`, `ConfigModule`, `common/` (guards, filtros, servicio de verificación de firma).

---

## 4. Modelo de datos (Prisma)

Esquema de referencia a nivel diseño. El `schema.prisma` final se produce en el plan de implementación.

```prisma
enum Platform         { ANDROID IOS }
enum SessionStatus    { ACTIVE COMPLETE INCOMPLETE ABORTED }
enum Verdict          { CLEAN SUSPICIOUS FLAGGED INVALID }
enum IntegrityVerdict { MEETS_STRONG MEETS_DEVICE MEETS_BASIC DEGRADED FAILED UNKNOWN }
enum AttestationType  { PLAY_INTEGRITY APP_ATTEST NONE }
enum Severity         { LOW MEDIUM HIGH }
enum FlagType {
  ROOT HOOKING_FRAMEWORK BLACKLIST_PACKAGE APK_SIGNATURE_MISMATCH INTEGRITY_FAILED
  EMULATOR OVERLAY ACCESSIBILITY INTEGRITY_BASIC INTEGRITY_DEGRADED SNAPSHOT_GAP
  SIGNATURE_INVALID NONCE_REUSE
}

model Device {
  id              String          @id @default(cuid())
  publicKey       String          // SPKI DER en base64
  publicKeyFp     String          @unique // sha256 de la clave → idempotencia de enrolamiento
  platform        Platform
  keyAlgo         String          @default("ES256")
  attestationType AttestationType @default(NONE)
  attestationData Json?           // cadena de Key Attestation si el cliente la envía (verificación dura = mejora futura)
  label           String?
  revoked         Boolean         @default(false)
  createdAt       DateTime        @default(now())
  lastSeenAt      DateTime        @default(now())
  sessions        Session[]
  @@index([platform])
}

model Session {
  id                  String        @id @default(cuid())
  deviceId            String
  device              Device        @relation(fields: [deviceId], references: [id])
  status              SessionStatus @default(ACTIVE)
  verdict             Verdict?
  currentNonce        String        // próximo nonce esperado
  expectedIntervalSec Int           @default(45)
  jitterSec           Int           @default(15)
  blacklistVersion    Int
  startedAt           DateTime      @default(now())
  endedAt             DateTime?
  lastSeenAt          DateTime      @default(now())
  snapshots           Snapshot[]
  flags               Flag[]
  @@index([status, lastSeenAt]) // consulta del reaper
  @@index([deviceId])
}

model Snapshot {
  id               String           @id @default(cuid())
  sessionId        String
  session          Session          @relation(fields: [sessionId], references: [id])
  seq              Int
  clientTimestamp  DateTime
  receivedAt       DateTime         @default(now())
  signals          Json
  signedPayload    Bytes            // bytes exactos firmados → evidencia inmutable
  signatureValid   Boolean
  nonceUsed        String
  integrityVerdict IntegrityVerdict @default(UNKNOWN)
  flags            Flag[]
  @@unique([sessionId, seq])
  @@unique([sessionId, nonceUsed]) // anti-replay a nivel DB
}

model Flag {
  id         String    @id @default(cuid())
  sessionId  String
  session    Session   @relation(fields: [sessionId], references: [id])
  snapshotId String?
  snapshot   Snapshot? @relation(fields: [snapshotId], references: [id])
  type       FlagType
  severity   Severity
  details    Json?
  createdAt  DateTime  @default(now())
  @@index([sessionId])
}

model BlacklistEntry {
  id          String   @id @default(cuid())
  packageName String   @unique
  label       String
  severity    Severity @default(HIGH)
  active      Boolean  @default(true)
  addedAt     DateTime @default(now())
}

model BlacklistState {
  id      Int @id @default(1) // fila singleton
  version Int @default(1)     // se incrementa en cada cambio de blacklist
}
```

---

## 5. Firma y nonce

### 5.1 Firma sobre bytes exactos

El dispositivo sostiene un par EC **P-256** en Android Keystore (StrongBox si está disponible). La clave pública (SPKI) se registra en el enrolamiento. Cada snapshot se firma con **ECDSA P-256 / SHA-256 (ES256)** sobre los **bytes exactos** del payload serializado.

El cliente envía:
```jsonc
{ "payloadB64": "<base64 de los bytes exactos firmados>",
  "signatureB64": "<firma ES256 sobre esos bytes>",
  "integrityToken": "<token Play Integrity | null>" }
```

Estructura del payload firmado (dentro de `payloadB64`):
```json
{ "deviceId": "dev_x", "sessionId": "ses_x", "seq": 3,
  "nonce": "<nonce actual del server>",
  "clientTimestamp": "2026-07-27T15:04:05Z",
  "integrityTokenHash": "<sha256 del integrityToken>",
  "signals": { "root": {}, "hooking": {}, "packages": [], "emulator": {},
               "overlay": {}, "accessibility": {}, "apkSignature": {} } }
```

Orden estricto de verificación en el server:
1. Cargar `Device` vía la sesión.
2. **Verificar la firma sobre los bytes literales de `payloadB64`** con `Device.publicKey`. Si falla → registrar Snapshot con `signatureValid=false` + `Flag(SIGNATURE_INVALID, HIGH)`, **no** avanzar el nonce, responder 401. La sesión terminará INVALID.
3. Recién ahí, parsear el JSON del payload.
4. Validar binding: `sessionId` == `:id`, `deviceId` == `session.deviceId`, `seq` == esperado, `nonce` == `session.currentNonce`.
5. Validar frescura: `nonceUsed` no repetido (el `@@unique` de la DB atrapa la carrera) y `clientTimestamp` dentro de `CLOCK_SKEW_TOLERANCE_SEC`.

**Por qué bytes exactos y no JSON canónico:** dos serializadores producen bytes distintos para el mismo objeto (orden de claves, espacios, formato de números); re-serializar en el server rompería firmas válidas por diferencias cosméticas. Verificar sobre los bytes literales elimina toda esa clase de bugs.

**Por qué `integrityTokenHash` va firmado:** ata el token de Play Integrity a *este* snapshot, impidiendo pegar un token válido de un dispositivo limpio a un snapshot de un dispositivo sucio.

### 5.2 Nonce: cadena de custodia

- `start` genera `currentNonce` = 256 bits CSPRNG (base64url).
- Cada snapshot aceptado → el server genera un **`nextNonce` fresco**, lo persiste como `session.currentNonce` (update atómico), lo devuelve, y el snapshot registra el `nonceUsed`.
- Cadena: `start→n0`, `snapshot(n0)→n1`, `snapshot(n1)→n2`…
- Un replay trae un nonce ya consumido → rechazado por el `@@unique([sessionId, nonceUsed])` y por el mismatch con `currentNonce` → `Flag(NONCE_REUSE)`.
- Nonce fresco aleatorio por snapshot; **no** hash-chain (mismo nivel de seguridad, sin complejidad extra).

---

## 6. Ciclo de vida de la sesión

| Estado | Cómo se llega | Veredicto |
|---|---|---|
| **ACTIVE** | `start` la crea | — |
| **COMPLETE** | `end` limpio, snapshots cubren el lapso dentro de tolerancia | CLEAN / SUSPICIOUS / FLAGGED según señales |
| **INCOMPLETE** | `end` pero cobertura muy por debajo de lo esperado (servicio suspendido) | **INVALID** |
| **ABORTED** | nunca llegó `end`; el *reaper* marca ACTIVE con `lastSeenAt` > timeout | **INVALID** |

**Reaper:** tarea programada (`@nestjs/schedule`) que cada N segundos busca sesiones ACTIVE cuyo `lastSeenAt` sea más viejo que `SESSION_TIMEOUT_MULTIPLIER × expectedIntervalSec` y las marca ABORTED → INVALID. Esto hace cumplir la regla "si matan el servicio, no vale": la ausencia de señal se convierte en un veredicto explícito en vez de una sesión colgada para siempre.

**Gap analysis (regla concreta, ejecutada en `end`).** Con `startedAt`, `endedAt`, y los `clientTimestamp` de los snapshots:
- `expectedCount = floor((endedAt − startedAt) / expectedIntervalSec)`
- `coverageRatio = actualSnapshots / max(expectedCount, 1)`
- `maxGap` = el mayor intervalo entre eventos consecutivos (incluyendo `startedAt`→primer snapshot y último snapshot→`endedAt`)

Clasificación (umbrales en `verdict/policy.ts`, configurables):
- `maxGap > SESSION_TIMEOUT_MULTIPLIER × expectedIntervalSec` **o** `coverageRatio < SESSION_MIN_COVERAGE_RATIO` (default 0.5) → **INCOMPLETE** → **INVALID**. Indica servicio suspendido/matado a mitad.
- `2 × expectedIntervalSec < maxGap ≤ SESSION_TIMEOUT_MULTIPLIER × expectedIntervalSec`, o `0.5 ≤ coverageRatio < 0.8` → **COMPLETE** + `Flag(SNAPSHOT_GAP, MEDIUM)` → **SUSPICIOUS**.
- Resto → **COMPLETE** sin flag de gap.

Esto alinea con tu distinción: *gaps chicos* = señal débil (SUSPICIOUS); *sesión estructuralmente incompleta* = INVALID.

---

## 7. Atestación

### 7.1 Interfaz y providers

```typescript
interface AttestationVerifier {
  verify(input: { token: string; nonce: string; platform: Platform }): Promise<IntegrityResult>;
}

interface IntegrityResult {
  verdict: IntegrityVerdict; // MEETS_STRONG | MEETS_DEVICE | MEETS_BASIC | DEGRADED | FAILED
  raw?: unknown;             // payload decodificado, para auditoría
  evaluatedAt: Date;
}
```

- **`StubAttestationVerifier`** (dev/test): devuelve `ATTESTATION_STUB_VERDICT` (default `MEETS_STRONG`). Determinista. Hace correr todo el flujo sin Google.
- **`GooglePlayIntegrityVerifier`** (prod, Android): `decodeIntegrityToken` con service account; mapea `strongIntegrity→MEETS_STRONG`, `deviceIntegrity→MEETS_DEVICE`, `basicIntegrity→MEETS_BASIC`; verifica que el `requestHash`/nonce del token coincida con el nonce de servidor.
- **`AppleAppAttestVerifier`** (iOS, spec futuro): mismo contrato.

Selección por provider token de Nest + `ATTESTATION_PROVIDER`.

**Doble binding del nonce contra replay:** el nonce va (a) firmado dentro del payload vía `integrityTokenHash` y (b) dentro del propio token de Play Integrity como `requestHash`, firmado por Google. Romper el replay exigiría vencer las dos ataduras a la vez.

### 7.2 Degraded ≠ Failed

- **DEGRADED** — *no se pudo evaluar* (timeout/excepción/cuota de Google). El snapshot **se guarda igual**, sus señales locales se evalúan, integridad = `DEGRADED` → `Flag(INTEGRITY_DEGRADED, LOW)` → **SUSPICIOUS**. Nunca se descarta.
- **FAILED** — Google evaluó y el dispositivo **no alcanzó** integridad de dispositivo → `Flag(INTEGRITY_FAILED, HIGH)` → **FLAGGED**.

Una falla de infraestructura no puede ser ni un pase libre (tumbar la red para evadir la atestación) ni una acusación falsa (banear por un problema de Google). DEGRADED→SUSPICIOUS es el punto medio correcto: "no pude confirmar, revisar con lupa".

---

## 8. Lógica de veredicto

### 8.1 `SignalEvaluator` — señales JSONB → Flags (función pura)

| Señal | Flag | Severidad |
|---|---|---|
| `root.detected` | ROOT | HIGH |
| `hooking.frida \|\| hooking.xposed` | HOOKING_FRAMEWORK | HIGH |
| paquete ∈ blacklist | BLACKLIST_PACKAGE | HIGH (uno por match) |
| `apkSignature.mismatch` | APK_SIGNATURE_MISMATCH | HIGH |
| integridad `FAILED` | INTEGRITY_FAILED | HIGH |
| `emulator.detected` | EMULATOR | MEDIUM |
| `overlay.activeDuringSession` | OVERLAY | MEDIUM |
| `accessibility.suspiciousServiceActive` | ACCESSIBILITY | MEDIUM |
| integridad `< STRONG` (basic/device) | INTEGRITY_BASIC | LOW |
| integridad `DEGRADED` | INTEGRITY_DEGRADED | LOW |

Umbrales/severidades en un **objeto de política centralizado** (`verdict/policy.ts`), ajustable sin tocar la lógica.

### 8.2 `VerdictService` — agregación con precedencia

Precedencia (gana el más alto), evaluada sobre **todos** los snapshots de la sesión: **INVALID > FLAGGED > SUSPICIOUS > CLEAN**.

- **INVALID** si: `status ∈ {INCOMPLETE, ABORTED}`, o algún snapshot con firma inválida, o nonce reusado, o cero snapshots.
- **FLAGGED** si: existe cualquier flag **HIGH**.
- **SUSPICIOUS** si: solo flags MEDIUM/LOW (o integridad `< STRONG` / `DEGRADED` / gaps).
- **CLEAN** si: sin flags, todas las firmas válidas, `status COMPLETE`, e integridad `MEETS_STRONG` en todos.

**Worst-wins:** un solo snapshot sucio condena la sesión entera. Es la traducción directa del modelo de amenaza (el cheat se activa a mitad de partida) — el veredicto no promedia ni perdona.

---

## 9. Endpoints

| # | Endpoint | Auth | Descripción |
|---|---|---|---|
| 1 | `POST /devices/enroll` | Abierto (rate-limited) | Registra `publicKey` + `platform`; devuelve `deviceId`. Idempotente por fingerprint |
| 2 | `POST /sessions/start` | Firma del device | Crea sesión ACTIVE; devuelve `sessionId` + nonce inicial + intervalos + `blacklistVersion` |
| 3 | `POST /sessions/:id/snapshot` | Payload firmado | Verifica firma+nonce, evalúa señales, atesta; devuelve `nextNonce` |
| 4 | `POST /sessions/:id/end` | Firma del device | Cierra, gap analysis, computa veredicto |
| 5 | `GET /sessions/:id/verdict` | Capability (sessionId) | Veredicto mínimo: `status` + `verdict` |
| 6 | `GET /devices/:id` | Admin API key | Historial: sesiones + flags acumulados |
| 7 | `GET /blacklist` | Abierto | Lista versionada `{ version, entries[] }` |
| 8 | `POST/PATCH/DELETE /blacklist` | Admin API key | Gestión; cada cambio incrementa `BlacklistState.version` |

Contratos principales:

```jsonc
// 1. POST /devices/enroll
// req:
{ "publicKey": "<SPKI DER base64>", "platform": "ANDROID", "keyAlgo": "ES256",
  "attestation": { "type": "PLAY_INTEGRITY", "certificateChain": ["...","..."] } } // attestation opcional
// res 201:
{ "deviceId": "dev_x", "createdAt": "..." }

// 2. POST /sessions/start
// req:
{ "deviceId": "dev_x", "clientTimestamp": "...",
  "signatureB64": "<firma ES256 sobre (deviceId + clientTimestamp)>" }
// res 201:
{ "sessionId": "ses_x", "nonce": "<n0>", "expectedIntervalSec": 45,
  "jitterSec": 15, "blacklistVersion": 7 }

// 3. POST /sessions/:id/snapshot
// req:
{ "payloadB64": "<bytes exactos firmados>", "signatureB64": "<ES256>",
  "integrityToken": "<token | null>" }
// res 200:
{ "accepted": true, "nextNonce": "<n1>", "seq": 3 }

// 4. POST /sessions/:id/end
// req:
{ "clientTimestamp": "...", "signatureB64": "<firma sobre (sessionId + clientTimestamp)>" }
// res 200:
{ "sessionId": "ses_x", "status": "COMPLETE", "verdict": "CLEAN", "flags": [] }

// 5. GET /sessions/:id/verdict
// res 200:
{ "sessionId": "ses_x", "status": "COMPLETE", "verdict": "CLEAN" }

// 7. GET /blacklist
// res 200:
{ "version": 7, "entries": [ { "packageName": "com.cheat.x", "label": "...", "severity": "HIGH" } ] }
```

Errores del snapshot:
- **401** firma inválida → se registra Snapshot `signatureValid=false` + `Flag(SIGNATURE_INVALID)`, no avanza nonce.
- **409** nonce reusado/mismatch → `Flag(NONCE_REUSE)`, rechazado.
- **410** sesión no ACTIVE.

---

## 10. Auth (spec 1, sin Discord/JWT)

- **Endpoints de device** (enroll, start, snapshot, end): autenticación por **posesión de la clave** enrolada (el device firma cada request; la clave nunca sale del Keystore). `enroll` es abierto (rate-limited) porque es el bootstrap.
- **Endpoints admin** (gestión de blacklist, `GET /devices/:id`): **API key estática** (`x-api-key`, desde `ADMIN_API_KEY`) vía `AdminApiKeyGuard`. El bot recibirá su propio service key en su spec.
- **`GET /sessions/:id/verdict`**: capability por `sessionId` opaco (conocer el id = autorización de lectura del veredicto mínimo).

---

## 11. Cross-cutting

- **Validación:** DTOs con `class-validator` en cada endpoint → 400 en el borde.
- **Rate limiting:** `@nestjs/throttler` en `enroll` y `snapshot` (por IP y por device).
- **Config:** `@nestjs/config` con schema de env validado (Zod) — *fail fast* si falta una var crítica.
- **Error shape:** filtro de excepción global → `{ error, code, details? }`.
- **Límite de body** en snapshot: `SNAPSHOT_MAX_BODY_BYTES` (default 64KB).
- **Logging:** estructurado (pino), correlacionado por `sessionId`/`deviceId`; se loguean identificadores, no payloads crudos.

---

## 12. Estructura de carpetas

```
src/
├── main.ts
├── app.module.ts
├── config/                 # schema de env (Zod), ConfigModule
├── common/
│   ├── guards/admin-api-key.guard.ts
│   ├── filters/http-exception.filter.ts
│   └── crypto/signature.service.ts    # verificación ES256
├── devices/                # module, controller, service, dto/
├── sessions/
│   ├── sessions.{module,controller,service}.ts
│   ├── nonce.service.ts
│   ├── reaper.service.ts   # @Cron
│   └── dto/
├── blacklist/              # module, controller, service
├── attestation/
│   ├── attestation.module.ts
│   ├── attestation-verifier.interface.ts
│   ├── stub-attestation.verifier.ts
│   └── google-play-integrity.verifier.ts
├── verdict/                # dominio puro, sin Nest
│   ├── verdict.service.ts
│   ├── signal-evaluator.ts
│   ├── policy.ts
│   └── types.ts
└── prisma/                 # prisma.module.ts, prisma.service.ts
prisma/  schema.prisma, migrations/
test/    unit/, e2e/
```

---

## 13. Variables de entorno

```
DATABASE_URL=postgresql://user:password@localhost:5432/anticheat
PORT=4000
NODE_ENV=development
ADMIN_API_KEY=<min 32 chars>
ATTESTATION_PROVIDER=stub                 # stub | google
ATTESTATION_STUB_VERDICT=MEETS_STRONG
GOOGLE_CLOUD_PROJECT_NUMBER=              # para GooglePlayIntegrityVerifier
GOOGLE_APPLICATION_CREDENTIALS=           # path al service account JSON
PLAY_INTEGRITY_PACKAGE_NAME=
SESSION_TIMEOUT_MULTIPLIER=3              # reaper + gap analysis: N×interval
SESSION_MIN_COVERAGE_RATIO=0.5           # < este ratio de snapshots → INCOMPLETE
CLOCK_SKEW_TOLERANCE_SEC=120
SNAPSHOT_MAX_BODY_BYTES=65536
THROTTLE_TTL=60
THROTTLE_LIMIT=100
```

---

## 14. Estrategia de testing

- **Unit (dominio puro):** `VerdictService` y `SignalEvaluator` con tests table-driven que cubren cada camino señal→flag→veredicto; `NonceService`; `StubAttestationVerifier`.
- **Firma/nonce:** generar un par EC P-256 real en el test (`crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })`), firmar payloads, afirmar que el server acepta el válido y rechaza el manipulado / el de clave equivocada.
- **E2E (Nest TestingModule + Postgres descartable):** ciclo completo `enroll → start → N snapshots (uno con root) → end → FLAGGED`; replay → 409 + NONCE_REUSE; matar a mitad → reaper → ABORTED/INVALID; stub que lanza excepción → DEGRADED + SUSPICIOUS.
- La única pieza sin cobertura unit es la llamada real a Google (`GooglePlayIntegrityVerifier`), que se prueba con **fixtures grabados**.

---

## 15. Lo que el sistema NO hace (restricciones)

- No corre sin consentimiento explícito y visible del usuario (la app tiene notificación persistente durante toda la sesión — responsabilidad del cliente Android, pero el backend no acepta reportes que no vengan de una sesión iniciada por el usuario).
- No hookea, inyecta ni hace ingeniería inversa del proceso de Free Fire. Solo recibe señales de integridad del **dispositivo**.
- No recolecta datos personales más allá de las señales de integridad del dispositivo. Los logs guardan identificadores (`deviceId`, `sessionId`), no payloads crudos.

---

## 16. Limitaciones documentadas (explícitas, no escondidas)

1. **Root vence los checks locales.** Magisk con DenyList puede ocultar todo lo que la app busca en el dispositivo. La atestación (Play Integrity validada del lado servidor) es la única señal que resiste presión real — y aun así existen bypasses.
2. **iOS no es viable como cliente.** El sandbox de Apple impide listar apps instaladas, inspeccionar otros procesos, detectar overlays/accesibilidad, o leer el hash del APK de Free Fire. Solo se puede intentar detección de jailbreak (débil) + App Attest. El backend es agnóstico de plataforma, pero *soportar Apple en el modelo de datos* ≠ *detectar cheats en iPhone*. La distribución además requiere cuenta de desarrollador de pago y App Review probablemente rechace la app.
3. **El que cheatea desde emulador en PC o segundo dispositivo simplemente no instala la app.** Ningún check técnico lo cubre — lo cubre el **módulo de análisis estadístico** (spec aparte) y las reglas de la comunidad.
4. **`QUERY_ALL_PACKAGES` no está permitido en Play Store** para este caso de uso. Distribución por APK directo.
5. **Falsos positivos:** desarrolladores con root legítimo, ROMs custom, y dispositivos con Play Integrity roto de fábrica. Requiere proceso de apelación manual (fuera de alcance de este spec; el modelo permite `Device.revoked` y notas en `label` como base).

---

## 17. Próximos specs (decomposición)

1. **App Android** (Kotlin, minSdk 26) — recolección de señales, Foreground Service, firma en Keystore, cliente de los endpoints de acá.
2. **Bot de Discord** (discord.js v14) — `/verificar`, vínculo `Player`↔`deviceId`, rol `Verificado ✅`, canal de logs, `/historial`.
3. **Módulo de análisis estadístico** — K/D, headshot rate, precisión, detección de outliers. NestJS + Postgres, sin tocar dispositivos. Independiente; puede arrancar en paralelo.
4. **Infraestructura** — Docker Compose (backend + Postgres, luego bot).
