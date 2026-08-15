# Backend de Verificación Anticheat

Backend NestJS para verificación anticheat **por consentimiento** de la comunidad de Free Fire.
Recibe snapshots firmados de una sesión de monitoreo, valida **firma + nonce + atestación**, y
emite un veredicto por niveles (`CLEAN | SUSPICIOUS | FLAGGED | INVALID`).

## Arquitectura

Monolito modular NestJS. Nest en el borde (HTTP, validación, persistencia con Prisma); dominio
puro sin dependencias de Nest en el centro (`src/verdict/`). La atestación (Play Integrity) vive
detrás de la interfaz `AttestationVerifier` (Ports & Adapters), con un stub para dev/test y el
verifier real de Google intercambiable por config.

- **Firma:** ECDSA P-256 / SHA-256 (ES256), verificada sobre los **bytes exactos** que firmó el cliente.
- **Nonce:** 256 bits CSPRNG (base64url), fresco por snapshot, sin reuso (constraint único en DB).
- **Veredicto:** precedencia `INVALID > FLAGGED > SUSPICIOUS > CLEAN`, agregado *worst-wins*.
- **Atestación:** un fallo de infraestructura → `DEGRADED` (nunca se descarta el snapshot).
- **Device-centric:** el modelo es agnóstico de plataforma (`ANDROID | IOS`); el único cliente construido es Android.

## Requisitos

- Node.js 20+
- Docker (para Postgres local) o un PostgreSQL accesible

## Puesta en marcha

```bash
cp .env.example .env          # y completar ADMIN_API_KEY, DATABASE_URL, etc.
docker compose up -d          # levanta Postgres (mapeado a 5435 por defecto)
npm install
npx prisma migrate deploy     # aplica migraciones
npm run start:dev             # server en :4000
```

> El `docker-compose.yml` expone Postgres en **5435** en el host para no chocar con un Postgres
> nativo en 5432. Ajustá el puerto de `DATABASE_URL` al que uses.

## Testing

```bash
npm test              # unit (dominio puro + servicios cripto + smoke Prisma)
npm run test:e2e      # e2e (ciclo de vida completo con Supertest + Postgres)
```

Los tests e2e requieren la DB accesible vía `DATABASE_URL`.

## Endpoints

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| `GET` | `/health` | — | Health check |
| `GET` | `/blacklist` | — | Lista versionada de paquetes en blacklist |
| `POST` | `/blacklist` | `x-api-key` | Agrega entrada (sube la versión) |
| `DELETE` | `/blacklist/:id` | `x-api-key` | Soft-delete (sube la versión) |
| `POST` | `/devices/enroll` | — | Enrolamiento idempotente por fingerprint de clave |
| `GET` | `/devices/:id` | `x-api-key` | Historial del device |
| `POST` | `/sessions/start` | firma device | Inicia sesión, devuelve nonce |
| `POST` | `/sessions/:id/snapshot` | firma device | Ingesta de snapshot firmado |
| `POST` | `/sessions/:id/end` | firma device | Cierra sesión, computa veredicto |
| `GET` | `/sessions/:id/verdict` | — | Estado + veredicto de la sesión |

## Lo que el sistema NO hace (restricciones)

- No corre sin consentimiento explícito y visible del usuario (la app tiene notificación
  persistente durante toda la sesión — responsabilidad del cliente Android, pero el backend no
  acepta reportes que no vengan de una sesión iniciada por el usuario).
- No hookea, inyecta ni hace ingeniería inversa del proceso de Free Fire. Solo recibe señales de
  integridad del **dispositivo**.
- No recolecta datos personales más allá de las señales de integridad del dispositivo. Los logs
  guardan identificadores (`deviceId`, `sessionId`), no payloads crudos.

## Limitaciones documentadas (explícitas, no escondidas)

1. **Root vence los checks locales.** Magisk con DenyList puede ocultar todo lo que la app busca en
   el dispositivo. La atestación (Play Integrity validada del lado servidor) es la única señal que
   resiste presión real — y aun así existen bypasses.
2. **iOS no es viable como cliente.** El sandbox de Apple impide listar apps instaladas, inspeccionar
   otros procesos, detectar overlays/accesibilidad, o leer el hash del APK de Free Fire. Solo se
   puede intentar detección de jailbreak (débil) + App Attest. El backend es agnóstico de plataforma,
   pero *soportar Apple en el modelo de datos* ≠ *detectar cheats en iPhone*.
3. **El que cheatea desde emulador en PC o segundo dispositivo simplemente no instala la app.** Ningún
   check técnico lo cubre — lo cubre el módulo de análisis estadístico (spec aparte) y las reglas de
   la comunidad.
4. **`QUERY_ALL_PACKAGES` no está permitido en Play Store** para este caso de uso. Distribución por
   APK directo.
5. **Falsos positivos:** desarrolladores con root legítimo, ROMs custom, y dispositivos con Play
   Integrity roto de fábrica. Requiere proceso de apelación manual (fuera de alcance de este spec; el
   modelo permite `Device.revoked` y notas en `label` como base).

## Atestación real (Google Play Integrity)

`GooglePlayIntegrityVerifier.mapDecodedToken` (mapeo puro decoded→veredicto) está cubierto por tests
con fixtures. La llamada de red real (`decodeWithGoogle`) queda sin implementar hasta tener el service
account (`GOOGLE_APPLICATION_CREDENTIALS`); lanza si se invoca sin configurar, y el pipeline lo trata
como `DEGRADED`.
