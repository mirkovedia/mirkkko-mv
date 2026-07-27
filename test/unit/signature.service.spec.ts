import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { SignatureService } from '../../src/common/crypto/signature.service';

describe('SignatureService', () => {
  const service = new SignatureService();
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spkiB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const payload = Buffer.from('{"seq":1}');
  const sigB64 = cryptoSign('sha256', payload, { key: privateKey, dsaEncoding: 'der' }).toString('base64');

  it('acepta una firma válida', () => {
    expect(service.verify(spkiB64, payload, sigB64)).toBe(true);
  });
  it('rechaza payload manipulado', () => {
    expect(service.verify(spkiB64, Buffer.from('{"seq":2}'), sigB64)).toBe(false);
  });
  it('rechaza clave equivocada', () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey
      .export({ format: 'der', type: 'spki' }).toString('base64');
    expect(service.verify(other, payload, sigB64)).toBe(false);
  });
  it('rechaza clave malformada sin lanzar', () => {
    expect(service.verify('no-base64-valido', payload, sigB64)).toBe(false);
  });
  it('fingerprint es estable y hex', () => {
    expect(service.fingerprint(spkiB64)).toMatch(/^[0-9a-f]{64}$/);
    expect(service.fingerprint(spkiB64)).toBe(service.fingerprint(spkiB64));
  });
});
