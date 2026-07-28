import { evaluateSignals } from '../../src/verdict/signal-evaluator';
import type { SignalSet } from '../../src/verdict/types';

const empty: SignalSet = {};
const bl = new Set<string>(['com.cheat.aim']);

describe('evaluateSignals', () => {
  it('root → ROOT/HIGH', () => {
    const flags = evaluateSignals(
      { root: { detected: true } },
      'MEETS_STRONG',
      bl,
    );
    expect(flags).toContainEqual(
      expect.objectContaining({ type: 'ROOT', severity: 'HIGH' }),
    );
  });
  it('frida → HOOKING_FRAMEWORK/HIGH', () => {
    const flags = evaluateSignals(
      { hooking: { frida: true } },
      'MEETS_STRONG',
      bl,
    );
    expect(flags.some((f) => f.type === 'HOOKING_FRAMEWORK')).toBe(true);
  });
  it('paquete en blacklist → BLACKLIST_PACKAGE con packageName', () => {
    const flags = evaluateSignals(
      { packages: ['com.cheat.aim', 'com.ok'] },
      'MEETS_STRONG',
      bl,
    );
    expect(flags).toContainEqual(
      expect.objectContaining({
        type: 'BLACKLIST_PACKAGE',
        details: { packageName: 'com.cheat.aim' },
      }),
    );
    expect(flags.filter((f) => f.type === 'BLACKLIST_PACKAGE')).toHaveLength(1);
  });
  it('emulador → EMULATOR/MEDIUM', () => {
    expect(
      evaluateSignals({ emulator: { detected: true } }, 'MEETS_STRONG', bl)[0]
        .severity,
    ).toBe('MEDIUM');
  });
  it('integridad DEGRADED → INTEGRITY_DEGRADED/LOW', () => {
    expect(evaluateSignals(empty, 'DEGRADED', bl)).toContainEqual(
      expect.objectContaining({ type: 'INTEGRITY_DEGRADED', severity: 'LOW' }),
    );
  });
  it('integridad FAILED → INTEGRITY_FAILED/HIGH', () => {
    expect(evaluateSignals(empty, 'FAILED', bl)).toContainEqual(
      expect.objectContaining({ type: 'INTEGRITY_FAILED', severity: 'HIGH' }),
    );
  });
  it('MEETS_BASIC → INTEGRITY_BASIC/LOW', () => {
    expect(evaluateSignals(empty, 'MEETS_BASIC', bl)).toContainEqual(
      expect.objectContaining({ type: 'INTEGRITY_BASIC', severity: 'LOW' }),
    );
  });
  it('limpio + STRONG → sin flags', () => {
    expect(evaluateSignals(empty, 'MEETS_STRONG', bl)).toHaveLength(0);
  });
});
