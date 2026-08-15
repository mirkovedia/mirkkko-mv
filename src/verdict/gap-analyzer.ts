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
  const coverageRatio =
    input.snapshotTimestamps.length / Math.max(expectedCount, 1);

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
