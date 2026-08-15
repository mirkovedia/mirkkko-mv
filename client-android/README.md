# client-android — Cliente Anti-Cheat de auto-verificación

App Android que recolecta señales de integridad del dispositivo, las firma con una
clave respaldada por hardware (Android Keystore) y las envía al backend anti-cheat,
que emite el veredicto. El modelo de confianza es **server-authoritative**: el cliente
solo reporta señales firmadas; toda decisión la toma el servidor.

## Requisitos

- Android SDK (compileSdk 34, build-tools 35.0.0).
- JDK 17.
- Un emulador o dispositivo físico con **minSdk 26** (Android 8.0+).
- Backend anti-cheat corriendo localmente (ver más abajo).

## Apuntar la app al backend

La URL del backend se define en `app/build.gradle.kts` vía `BACKEND_BASE_URL`:

- **Emulador:** `http://10.0.2.2:3000/` (10.0.2.2 es el `localhost` de la máquina host
  visto desde el emulador). Este es el valor por defecto.
- **Dispositivo físico:** reemplaza por la IP LAN de tu máquina, p. ej.
  `http://192.168.1.50:3000/`. El teléfono y la PC deben estar en la misma red.

Recompila tras cambiar la URL para regenerar `BuildConfig`.

## Correr el backend localmente

Desde el repositorio del backend anti-cheat:

```bash
npm install
npm run start:dev
```

El backend escucha en el puerto `3000` y usa PostgreSQL en el puerto `5435`
(según la configuración de entorno del proyecto). Asegúrate de que la base de datos
esté levantada y migrada antes de iniciar sesiones.

## Compilar y correr los tests

```bash
./gradlew :app:testDebugUnitTest   # tests unitarios JVM (lógica pura, crypto, orchestrator)
./gradlew :app:assembleDebug       # APK debug
```

## Prueba manual de interop end-to-end (prueba real cross-stack)

1. Levanta el backend (`npm run start:dev`) con Postgres arriba.
2. Instala y abre la app en el emulador/dispositivo.
3. Pulsa **Verificar**. La app enrola el dispositivo (si es la primera vez), abre una
   sesión, envía varios snapshots firmados con pacing de intervalo, y cierra la sesión.
4. La pantalla muestra el **veredicto** (p. ej. `CLEAN`) y una URL verificable.
5. Abre `GET /sessions/:id/verdict` en un navegador y confirma que coincide con lo que
   muestra la app.

Este paso es la **prueba real de que las firmas ECDSA/DER del Android Keystore son
aceptadas por el backend Node** (interop cross-stack). El gate automatizado equivalente
es el test de interop en `JvmSigningKey` (verificación ECDSA estándar sobre SPKI + DER
exportados, idéntico a `crypto.verify` de Node).

## Notas de seguridad

- `usesCleartextTraffic` está habilitado **solo para desarrollo local** (HTTP a
  `10.0.2.2`/LAN). En producción se requiere **HTTPS + certificate pinning**.
- Mantén `<queries>` en el manifest y `knownCheatPackages` sincronizados con la
  blacklist del servidor en cada release.
- La clave de firma vive en el Android Keystore (idealmente StrongBox/TEE) y nunca se
  exporta; solo se usa para firmar. La cadena de attestation permite al backend probar
  que la clave reside en hardware real.
