// Carga .env antes de importar módulos, para que los tests que tocan la DB
// (p. ej. prisma.smoke) usen el DATABASE_URL real. dotenv no pisa variables ya
// definidas, así que un override inline (DATABASE_URL=... npx jest) sigue teniendo prioridad.
import { config } from 'dotenv';

config();
