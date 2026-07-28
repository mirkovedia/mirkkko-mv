// Configura variables de entorno de prueba antes de que los módulos sean importados.
// Necesario porque @nestjs/config llama a validate() sincrónicamente en la
// evaluación del decorador @Module, antes de que beforeAll() de Jest pueda ejecutarse.
import { config } from 'dotenv';

// Carga .env para que los e2e (que sí tocan la DB) usen el DATABASE_URL real.
// dotenv no pisa variables ya definidas, así que un override inline sigue ganando.
config();

if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://u:p@localhost:5432/test';
}
if (!process.env.ADMIN_API_KEY) {
  process.env.ADMIN_API_KEY = 'x'.repeat(32);
}
// Rate limit alto en tests: todos los requests salen de la misma IP y no queremos 429 flaky.
if (!process.env.THROTTLE_LIMIT) {
  process.env.THROTTLE_LIMIT = '100000';
}
