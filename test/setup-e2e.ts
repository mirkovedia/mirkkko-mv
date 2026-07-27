// Configura variables de entorno de prueba antes de que los módulos sean importados.
// Necesario porque @nestjs/config llama a validate() sincrónicamente en la
// evaluación del decorador @Module, antes de que beforeAll() de Jest pueda ejecutarse.

if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://u:p@localhost:5432/test';
}
if (!process.env.ADMIN_API_KEY) {
  process.env.ADMIN_API_KEY = 'x'.repeat(32);
}
