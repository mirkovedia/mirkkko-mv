import { NonceService } from '../../src/common/crypto/nonce.service';

describe('NonceService', () => {
  const service = new NonceService();
  it('genera nonces base64url distintos', () => {
    const a = service.generate();
    const b = service.generate();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(a, 'base64url')).toHaveLength(32);
  });
});
