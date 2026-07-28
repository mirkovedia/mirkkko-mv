import { ConfigService } from '@nestjs/config';
import { StubAttestationVerifier } from '../../src/attestation/stub-attestation.verifier';

const cfg = (verdict: string) =>
  ({ get: () => verdict }) as unknown as ConfigService;

describe('StubAttestationVerifier', () => {
  it('devuelve el veredicto configurado con token presente', async () => {
    const v = new StubAttestationVerifier(cfg('MEETS_STRONG'));
    const r = await v.verify({ token: 'tok', nonce: 'n', platform: 'ANDROID' });
    expect(r.verdict).toBe('MEETS_STRONG');
  });
  it('token null → DEGRADED (no se pudo evaluar)', async () => {
    const v = new StubAttestationVerifier(cfg('MEETS_STRONG'));
    const r = await v.verify({ token: null, nonce: 'n', platform: 'ANDROID' });
    expect(r.verdict).toBe('DEGRADED');
  });
});
