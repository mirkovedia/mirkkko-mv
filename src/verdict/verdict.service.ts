import type { DetectedFlag, SessionStatus, Verdict } from './types';

export interface SnapshotFlags {
  flags: DetectedFlag[];
}

const INVALIDATING_TYPES = new Set(['SIGNATURE_INVALID', 'NONCE_REUSE']);

// Función pura: precedencia INVALID > FLAGGED > SUSPICIOUS > CLEAN, worst-wins sobre todos los snapshots.
export const computeVerdict = (
  status: SessionStatus,
  snapshots: SnapshotFlags[],
): Verdict => {
  if (status === 'INCOMPLETE' || status === 'ABORTED') return 'INVALID';
  if (snapshots.length === 0) return 'INVALID';

  const allFlags = snapshots.flatMap((s) => s.flags);
  if (allFlags.some((f) => INVALIDATING_TYPES.has(f.type))) return 'INVALID';
  if (allFlags.some((f) => f.severity === 'HIGH')) return 'FLAGGED';
  if (allFlags.length > 0) return 'SUSPICIOUS';
  return 'CLEAN';
};
