export type Platform = 'ANDROID' | 'IOS';
export type IntegrityVerdict =
  | 'MEETS_STRONG'
  | 'MEETS_DEVICE'
  | 'MEETS_BASIC'
  | 'DEGRADED'
  | 'FAILED'
  | 'UNKNOWN';
export type Verdict = 'CLEAN' | 'SUSPICIOUS' | 'FLAGGED' | 'INVALID';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH';
export type SessionStatus = 'ACTIVE' | 'COMPLETE' | 'INCOMPLETE' | 'ABORTED';
export type FlagType =
  | 'ROOT'
  | 'HOOKING_FRAMEWORK'
  | 'BLACKLIST_PACKAGE'
  | 'APK_SIGNATURE_MISMATCH'
  | 'INTEGRITY_FAILED'
  | 'EMULATOR'
  | 'OVERLAY'
  | 'ACCESSIBILITY'
  | 'INTEGRITY_BASIC'
  | 'INTEGRITY_DEGRADED'
  | 'SNAPSHOT_GAP'
  | 'SIGNATURE_INVALID'
  | 'NONCE_REUSE';

export interface DetectedFlag {
  type: FlagType;
  severity: Severity;
  details?: Record<string, unknown>;
}

export interface SignalSet {
  root?: { detected: boolean };
  hooking?: { frida?: boolean; xposed?: boolean };
  packages?: string[];
  emulator?: { detected: boolean };
  overlay?: { activeDuringSession: boolean };
  accessibility?: { suspiciousServiceActive: boolean };
  apkSignature?: { mismatch: boolean };
}
