// Umbrales por defecto del gap analysis (los valores runtime vienen de env).
export const DEFAULT_POLICY = {
  minCoverageRatio: 0.5,
  timeoutMultiplier: 3,
  gapSuspiciousMultiplier: 2,
  gapWarnCoverageRatio: 0.8,
} as const;
