import { analyzeGaps } from '../../src/verdict/gap-analyzer';

const base = {
  expectedIntervalSec: 45,
  timeoutMultiplier: 3,
  minCoverageRatio: 0.5,
  gapSuspiciousMultiplier: 2,
  gapWarnCoverageRatio: 0.8,
};
const ts = (startMs: number, count: number, stepSec: number): number[] =>
  Array.from({ length: count }, (_, i) => startMs + (i + 1) * stepSec * 1000);

describe('analyzeGaps', () => {
  it('cobertura completa y regular → COMPLETE sin gapFlag', () => {
    const startedAt = 0;
    const endedAt = 45_000 * 11; // ~10 intervalos
    const r = analyzeGaps({
      ...base,
      startedAt,
      endedAt,
      snapshotTimestamps: ts(0, 10, 45),
    });
    expect(r).toEqual({ status: 'COMPLETE', gapFlag: false });
  });
  it('un gap grande (> timeout) → INCOMPLETE', () => {
    const startedAt = 0;
    const endedAt = 45_000 * 11;
    // salta del snapshot 2 al 9 (hueco de ~7 intervalos)
    const snaps = [45_000, 90_000, 9 * 45_000, 10 * 45_000];
    const r = analyzeGaps({
      ...base,
      startedAt,
      endedAt,
      snapshotTimestamps: snaps,
    });
    expect(r.status).toBe('INCOMPLETE');
  });
  it('cobertura baja (< 0.5) → INCOMPLETE', () => {
    const r = analyzeGaps({
      ...base,
      startedAt: 0,
      endedAt: 45_000 * 11,
      snapshotTimestamps: ts(0, 3, 45),
    });
    expect(r.status).toBe('INCOMPLETE');
  });
  it('gap mediano (2x–3x) → COMPLETE + gapFlag', () => {
    const startedAt = 0;
    const endedAt = 45_000 * 9;
    // 7 snapshots regulares y uno con hueco de ~2.5x
    const snaps = [45_000, 90_000, 135_000, 247_500, 292_500, 337_500, 382_500];
    const r = analyzeGaps({
      ...base,
      startedAt,
      endedAt,
      snapshotTimestamps: snaps,
    });
    expect(r).toEqual({ status: 'COMPLETE', gapFlag: true });
  });
});
