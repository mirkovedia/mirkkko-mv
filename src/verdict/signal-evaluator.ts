import type { DetectedFlag, IntegrityVerdict, SignalSet } from './types';

// Función pura: mapea señales del dispositivo + veredicto de integridad a flags.
export const evaluateSignals = (
  signals: SignalSet,
  integrityVerdict: IntegrityVerdict,
  blacklist: ReadonlySet<string>,
): DetectedFlag[] => {
  const flags: DetectedFlag[] = [];

  if (signals.root?.detected) flags.push({ type: 'ROOT', severity: 'HIGH' });
  if (signals.hooking?.frida || signals.hooking?.xposed) {
    flags.push({
      type: 'HOOKING_FRAMEWORK',
      severity: 'HIGH',
      details: { ...signals.hooking },
    });
  }
  for (const pkg of signals.packages ?? []) {
    if (blacklist.has(pkg)) {
      flags.push({
        type: 'BLACKLIST_PACKAGE',
        severity: 'HIGH',
        details: { packageName: pkg },
      });
    }
  }
  if (signals.apkSignature?.mismatch)
    flags.push({ type: 'APK_SIGNATURE_MISMATCH', severity: 'HIGH' });
  if (integrityVerdict === 'FAILED')
    flags.push({ type: 'INTEGRITY_FAILED', severity: 'HIGH' });

  if (signals.emulator?.detected)
    flags.push({ type: 'EMULATOR', severity: 'MEDIUM' });
  if (signals.overlay?.activeDuringSession)
    flags.push({ type: 'OVERLAY', severity: 'MEDIUM' });
  if (signals.accessibility?.suspiciousServiceActive) {
    flags.push({ type: 'ACCESSIBILITY', severity: 'MEDIUM' });
  }

  if (integrityVerdict === 'MEETS_BASIC' || integrityVerdict === 'MEETS_DEVICE') {
    flags.push({ type: 'INTEGRITY_BASIC', severity: 'LOW' });
  }
  if (integrityVerdict === 'DEGRADED')
    flags.push({ type: 'INTEGRITY_DEGRADED', severity: 'LOW' });

  return flags;
};
