# Diseño: App Android de auto-verificación anticheat (cliente)

**Fecha:** 2026-07-28
**Estado:** Aprobado para escribir plan de implementación
**Backend relacionado:** `backend-verificacion-anticheat` (NestJS, este repo)
**Inspiración / referencia:** KellerSS-Android (herramienta forense manual en Termux) — este proyecto la reemplaza con un modelo *server-authoritative* y con atestación de hardware.

---

## 1. Objetivo y contexto

Construir una **app Android nativa (Kotlin)** que permita a un jugador de Free Fire **auto-verificar** su dispositivo de forma **opt-in y transparente**, produciendo un **veredicto firmado por el servidor** que puede compartir con un organizador de torneo.

A diferencia de KellerSS (un binario opaco de ~17MB que un analista corre a mano en Termux y que confía 100% en lo que el dispositivo reporta), esta app:

- Corre bajo control del propio jugador y **muestra en pantalla qué se está revisando** (transparencia).
- Firma cada reporte con una clave en **hardware seguro** (Android Keystore), de modo que el **servidor** — no el dispositivo — decide el veredicto.
- Es resistente a manipulación: sin firma válida + nonce vigente, el backend rechaza el snapshot.

### Modelo de confianza
*Server-authoritative*: el dispositivo recolecta señales y las firma, pero el backend verifica firma + nonce + skew + atestación y **computa el veredicto**. El cliente nunca es autoridad sobre el resultado.

---

## 2. Alcance

### En alcance (este spec / MVP)
- App Android nativa en Kotlin + Jetpack Compose.
- **Modelo de uso:** verificación bajo demanda (self-check), corrida corta de ~60-90s.
- Generación de par EC P-256 en Android Keystore + enrolamiento del device.
- Ciclo de sesión completo: `start → N snapshots → end → verdict`.
- Colectores para las señales que el backend **ya** entiende (ver §5).
- **Key Attestation** del Keystore enviada en el enroll (atestación de hardware de dispositivo).
- Pantalla de resultado con veredicto + flags + **QR/enlace verificable** contra el servidor.

### Fuera de alcance (specs futuros)
- iOS.
- Monitoreo continuo en background durante la partida.
- Heurísticas específicas de Free Fire de KellerSS (replay tampering, mods de OBB/shaders, bypass de fecha/hora, MTP, reboot reciente) → **requieren extender el `SignalSet` del backend**; segundo spec.
- **Play Integrity real** → queda *enchufable* (hook listo, sin token todavía). El backend ya trata la atestación ausente/fallida como `DEGRADED → SUSPICIOUS`.
- Binding del veredicto a la identidad del jugador (IGN/UID).
- Endurecimiento de producción: certificate pinning, ofuscación/anti-tamper de la app, root-hiding evasion.

---

## 3. Contrato del backend (fijo — la app debe cumplirlo)

Todos los endpoints bajo la base URL del backend.

### 3.1 Enrollment — `POST /devices/enroll`
```jsonc
{
  "publicKey": "<SPKI DER en base64, EC P-256>",
  "platform": "ANDROID",
  "keyAlgo": "EC_P256",                       // opcional
  "attestation": {                            // opcional (usamos Key Attestation)
    "type": "ANDROID_KEY_ATTESTATION",
    "certificateChain": ["<cert b64>", ...]
  }
}
```
Idempotente por fingerprint de la clave pública. Devuelve el `deviceId`.

### 3.2 Session start — `POST /sessions/start`
```jsonc
{ "deviceId": "...", "clientTimestamp": "<ISO8601>", "signatureB64": "sign(deviceId + clientTimestamp)" }
```
Devuelve `{ sessionId, nonce, expectedIntervalSec, jitterSec, blacklistVersion }`.

### 3.3 Snapshot — `POST /sessions/:id/snapshot`
`payloadB64` = base64 del JSON:
```jsonc
{
  "deviceId": "...", "sessionId": "...", "seq": 0,
  "nonce": "<nonce vigente>", "clientTimestamp": "<ISO8601>",
  "integrityTokenHash": "<sha256(token) hex, opcional>",
  "signals": { /* SignalSet, ver §5 */ }
}
```
Body: `{ payloadB64, signatureB64: sign(payloadBytes), integrityToken?: null }`.
Devuelve `{ accepted, nextNonce, seq }`. **El nonce rota en cada snapshot.**

Rechazos relevantes: `401 SIGNATURE_INVALID`, `409 NONCE_REUSE`, `401 BINDING_MISMATCH`, `401 CLOCK_SKEW`, `410 SESSION_NOT_ACTIVE`.

### 3.4 Session end — `POST /sessions/:id/end`
```jsonc
{ "clientTimestamp": "<ISO8601>", "signatureB64": "sign(sessionId + clientTimestamp)" }
```
Devuelve `{ sessionId, status, verdict, flags }`.

### 3.5 Verdict (para terceros) — `GET /sessions/:id/verdict`
Devuelve `{ sessionId, status, verdict }`. Lectura pública → base de la verificación por el organizador.

---

## 4. Arquitectura de la app (módulos)

Cada módulo tiene una única responsabilidad y se testea aislado.

- **`crypto/`** — `KeystoreManager`: genera/usa el par EC P-256, exporta SPKI, firma bytes, obtiene la cadena de Key Attestation.
- **`signals/`** — un colector por señal (interfaz `SignalCollector`), más un `SignalAggregator` que arma el `SignalSet`.
- **`net/`** — `AntiCheatApi` (Retrofit) + DTOs (enroll/start/snapshot/end/verdict) + serialización (kotlinx.serialization).
- **`session/`** — `VerificationOrchestrator`: máquina de estados que corre el ciclo completo y expone un `StateFlow` a la UI.
- **`ui/`** — Compose: pantalla principal (botón, progreso por paso, resultado con QR).

### Máquina de estados del orquestador
```
Idle → Enrolling → Starting → Snapshotting(seq, nonce) → Ending → Result(verdict, flags)
                                     │
                                     └── (repite hasta cubrir la corrida)
Cualquier paso → Error(code, message)  // 401/409/red/etc.
```

---

## 5. Criptografía y manejo de claves

- **Generación:** `KeyGenParameterSpec` con `ECGenParameterSpec("secp256r1")`, `PURPOSE_SIGN`, `setDigests(DIGEST_SHA256)`, `setIsStrongBoxBacked(true)` con fallback a TEE si StrongBox no existe. Alias único p.ej. `anticheat_device_key`. La clave privada **nunca sale del hardware**.
- **Clave pública:** `publicKey.encoded` ya es X.509 **SubjectPublicKeyInfo (SPKI) DER** → base64. Calza exacto con el `createPublicKey({ format:'der', type:'spki' })` del backend.
- **Firma:** `Signature.getInstance("SHA256withECDSA")` produce firma **DER** → base64. Calza con `dsaEncoding:'der'` del backend (`crypto.verify('sha256', ...)`).
- **Key Attestation:** al generar la clave, `setAttestationChallenge(<challenge>)` produce una cadena de certificados que prueba que la clave reside en hardware seguro. Se envía en `attestation.certificateChain` del enroll.

> **Nota:** Key Attestation (nivel dispositivo: "la clave está en hardware") y Play Integrity (nivel app: "la instalación es legítima") son complementarias. Este MVP entrega Key Attestation; Play Integrity queda enchufable.

---

## 6. Colectores de señales → `SignalSet`

`SignalSet` que el backend entiende hoy:
```ts
{ root?, hooking?{frida,xposed}, packages?[], emulator?, overlay?, accessibility?, apkSignature? }
```

| Señal | Detección (Kotlin) | Notas |
|---|---|---|
| `root.detected` | binarios `su` en PATHs comunes, paths/paquetes de Magisk, `test-keys` en `Build.TAGS` | heurística propia, sin depender de libs externas |
| `hooking.frida` / `xposed` | Frida: puertos/named-pipes y `frida-agent` en `/proc/self/maps`; Xposed: clase `XposedBridge`, paquete instalador | |
| `packages[]` | `getPackageInfo` sobre la lista `<queries>` declarada (paquetes de cheat conocidos); reporta los presentes | ver §6.1 |
| `emulator.detected` | fingerprints/props de emulador (`Build.FINGERPRINT/MODEL/BRAND/HARDWARE`, props qemu) | |
| `overlay.activeDuringSession` | toques con `FLAG_WINDOW_IS_OBSCURED` durante la corrida | proxy práctico de overlay malicioso |
| `accessibility.suspiciousServiceActive` | `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES`, marca servicios no-sistema/sospechosos | |
| `apkSignature.mismatch` | hash del cert de firma propio vs valor **pineado** en `BuildConfig` | detecta app repackaged/tampered |

### 6.1 Enumeración de paquetes (decisión resuelta)
Se usa una **lista `<queries>` declarada en el manifest**, no `QUERY_ALL_PACKAGES`. La lista se mantiene **sincronizada con la blacklist del servidor por release** (paquetes de cheat conocidos). La app reporta cuáles están instalados; el **servidor sigue siendo la fuente de verdad** del match y la severidad (blacklist versionada). Ventaja: más privado, sin permiso restringido, compatible con Play Store; costo: sólo detecta paquetes conocidos al momento del build (aceptable — la severidad/versionado vive en el server).

---

## 7. Orquestación de la corrida de verificación

1. **Enroll (si hace falta):** si no hay `deviceId` guardado, genera claves → `POST /devices/enroll` con SPKI + Key Attestation → persiste `deviceId` (DataStore).
2. **Start:** firma `deviceId+clientTimestamp` → `POST /sessions/start` → guarda `sessionId`, `nonce`, `expectedIntervalSec`, `jitterSec`.
3. **Snapshots:** en bucle (~6-9 veces, cada `expectedIntervalSec` ± jitter):
   - recolecta señales frescas,
   - arma el JSON con `seq`, `nonce` vigente y `clientTimestamp`,
   - firma los bytes exactos, `POST /sessions/:id/snapshot`,
   - guarda `nextNonce` de la respuesta.
4. **End:** firma `sessionId+clientTimestamp` → `POST /sessions/:id/end` → recibe veredicto.
5. **Result:** muestra veredicto + flags + QR/enlace.

Errores (`401` firma, `409` nonce, red) se propagan a un estado `Error` con código y mensaje legibles.

---

## 8. Resultado y verificación por terceros

La pantalla de resultado muestra:
- **Veredicto** (`CLEAN` / `SUSPICIOUS` / `FLAGGED` / `INVALID`) con color.
- Lista de **flags** detectados.
- Un **QR / enlace** que codifica el `sessionId` y resuelve a `GET /sessions/:id/verdict` **del servidor**.

El organizador escanea/abre → su navegador consulta al **servidor directamente** → ve el veredicto autoritativo. **No falsificable**: el veredicto vive en el servidor, no en el artefacto compartido. Esta es la base de la transparencia.

(Binding a identidad de jugador = fuera de alcance; el veredicto representa "esta sesión fue X".)

---

## 9. Networking

- **Retrofit + OkHttp + kotlinx.serialization**.
- Base URL desde `BuildConfig` (dev: IP LAN del backend o `10.0.2.2` para emulador; el backend corre en su puerto local).
- Manejo de errores mapeando el shape del backend (`{ message, code }`).
- Certificate pinning → **fuera de alcance** (pass de producción).

---

## 10. Repositorio, build y estructura

- Nuevo directorio **`client-android/`** en la raíz del repo con proyecto Gradle Android estándar (Kotlin DSL). El backend NestJS queda intacto.
- `minSdk` moderno (p.ej. 26+) para Keystore/StrongBox; `targetSdk` reciente.
- Configuración de la base URL y el hash de firma pineado vía `BuildConfig`.

---

## 11. Testing

- **Unit (JUnit):**
  - `crypto`: round-trip de exportación SPKI y firma (vector conocido); verificar que el formato calza con lo que el backend espera.
  - `signals`: cada colector con inputs falsos/inyectados (lógica pura separada del acceso a Android API vía interfaces).
  - `net`: `MockWebServer` para enroll/start/snapshot/end, incluyendo rechazos `401`/`409`.
  - `session`: la máquina de estados del orquestador con un `AntiCheatApi` falso.
- **Test de interoperabilidad (crítico):** verificar que una firma + payload reales producidos por la app son **aceptados por el backend corriendo local**. Puede ser un test instrumentado apuntando al backend, o un test JVM que reproduce el `SignatureService.verify` del backend con el mismo par de claves.
- Instrumented/UI tests → mínimos (smoke del flujo feliz), no bloqueantes del MVP.

---

## 12. Riesgos y decisiones abiertas

- **StrongBox no universal:** no todos los dispositivos lo tienen → fallback a TEE. Registrar en la señal/atestación el nivel de seguridad alcanzado.
- **Detección de root/hooking es una carrera armamentista:** las heurísticas del MVP son razonables pero evadibles por atacantes sofisticados; el valor real está en la combinación firma+atestación+servidor, no en un único check.
- **`<queries>` estático vs blacklist dinámica:** la lista del manifest se actualiza por release; paquetes de cheat nuevos entre releases no se detectan por nombre hasta el próximo build (mitigado por severidad/versionado en el server y otras señales).
- **Base URL en dev:** el dispositivo/emulador debe alcanzar el backend (LAN o `10.0.2.2`); documentarlo en el README de `client-android/`.

---

## 13. Definición de "hecho" (MVP)

- La app genera claves en Keystore, enrola el device y corre una verificación completa contra el backend local.
- El backend acepta los snapshots firmados (firma + nonce válidos) y produce un veredicto.
- La pantalla de resultado muestra veredicto + flags + QR verificable.
- Suite de tests unitarios verde + test de interoperabilidad de firma con el backend.
