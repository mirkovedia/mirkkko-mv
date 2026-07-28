import { Injectable } from '@nestjs/common';
import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from 'node:crypto';

@Injectable()
export class SignatureService {
  // Verifica ECDSA P-256 / SHA-256 sobre los bytes exactos del payload.
  verify(
    publicKeySpkiB64: string,
    payload: Buffer,
    signatureB64: string,
  ): boolean {
    try {
      const keyObject = createPublicKey({
        key: Buffer.from(publicKeySpkiB64, 'base64'),
        format: 'der',
        type: 'spki',
      });
      return cryptoVerify(
        'sha256',
        payload,
        { key: keyObject, dsaEncoding: 'der' },
        Buffer.from(signatureB64, 'base64'),
      );
    } catch {
      // Clave malformada o firma inválida → no autenticado (nunca 500).
      return false;
    }
  }

  // Huella de la clave pública para idempotencia de enrolamiento.
  // Valida que sea un SPKI legítimo antes de hashear; lanza si es inválido.
  fingerprint(publicKeySpkiB64: string): string {
    const keyObject = createPublicKey({
      key: Buffer.from(publicKeySpkiB64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const spkiBytes = keyObject.export({ format: 'der', type: 'spki' });
    return createHash('sha256').update(spkiBytes).digest('hex');
  }
}
