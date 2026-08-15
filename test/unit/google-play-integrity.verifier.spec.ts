import { GooglePlayIntegrityVerifier } from '../../src/attestation/google-play-integrity.verifier';

const v = new GooglePlayIntegrityVerifier();
const decoded = (labels: string[], requestHash = 'n1') => ({
  requestDetails: { nonce: requestHash },
  deviceIntegrity: { deviceRecognitionVerdict: labels },
});

describe('GooglePlayIntegrityVerifier.mapDecodedToken', () => {
  it('MEETS_STRONG_INTEGRITY → MEETS_STRONG', () => {
    expect(
      v.mapDecodedToken(
        decoded(['MEETS_STRONG_INTEGRITY', 'MEETS_DEVICE_INTEGRITY']),
        'n1',
      ).verdict,
    ).toBe('MEETS_STRONG');
  });
  it('solo device → MEETS_DEVICE', () => {
    expect(
      v.mapDecodedToken(decoded(['MEETS_DEVICE_INTEGRITY']), 'n1').verdict,
    ).toBe('MEETS_DEVICE');
  });
  it('solo basic → MEETS_BASIC', () => {
    expect(
      v.mapDecodedToken(decoded(['MEETS_BASIC_INTEGRITY']), 'n1').verdict,
    ).toBe('MEETS_BASIC');
  });
  it('veredictos vacíos → FAILED (device comprometido)', () => {
    expect(v.mapDecodedToken(decoded([]), 'n1').verdict).toBe('FAILED');
  });
  it('nonce que no coincide → FAILED (posible replay)', () => {
    expect(
      v.mapDecodedToken(decoded(['MEETS_STRONG_INTEGRITY'], 'otro'), 'n1')
        .verdict,
    ).toBe('FAILED');
  });
});
