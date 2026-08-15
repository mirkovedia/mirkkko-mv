import { z } from 'zod';

export const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  PORT: z.coerce.number().default(4000),
  DATABASE_URL: z.string().url(),
  ADMIN_API_KEY: z
    .string()
    .min(32, 'ADMIN_API_KEY debe tener al menos 32 caracteres'),
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
