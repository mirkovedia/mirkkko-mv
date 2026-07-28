import { computeVerdict } from '../../src/verdict/verdict.service';
import type { DetectedFlag } from '../../src/verdict/types';

const snap = (...flags: DetectedFlag[]) => ({ flags });
const high: DetectedFlag = { type: 'ROOT', severity: 'HIGH' };
const med: DetectedFlag = { type: 'EMULATOR', severity: 'MEDIUM' };
const sigInvalid: DetectedFlag = {
  type: 'SIGNATURE_INVALID',
  severity: 'HIGH',
};

describe('computeVerdict', () => {
  it('status ABORTED → INVALID', () => {
    expect(computeVerdict('ABORTED', [snap()])).toBe('INVALID');
  });
  it('status INCOMPLETE → INVALID', () => {
    expect(computeVerdict('INCOMPLETE', [snap()])).toBe('INVALID');
  });
  it('cero snapshots → INVALID', () => {
    expect(computeVerdict('COMPLETE', [])).toBe('INVALID');
  });
  it('firma inválida → INVALID (gana sobre FLAGGED)', () => {
    expect(computeVerdict('COMPLETE', [snap(sigInvalid)])).toBe('INVALID');
  });
  it('un flag HIGH → FLAGGED', () => {
    expect(computeVerdict('COMPLETE', [snap(), snap(high)])).toBe('FLAGGED');
  });
  it('solo flags MEDIUM/LOW → SUSPICIOUS', () => {
    expect(computeVerdict('COMPLETE', [snap(med)])).toBe('SUSPICIOUS');
  });
  it('sin flags y COMPLETE → CLEAN', () => {
    expect(computeVerdict('COMPLETE', [snap(), snap()])).toBe('CLEAN');
  });
  it('worst-wins: un snapshot sucio entre limpios → FLAGGED', () => {
    expect(computeVerdict('COMPLETE', [snap(), snap(), snap(high)])).toBe(
      'FLAGGED',
    );
  });
});
