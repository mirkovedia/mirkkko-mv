import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';

@Injectable()
export class NonceService {
  // Nonce de 256 bits (32 bytes) en base64url.
  generate(): string {
    return randomBytes(32).toString('base64url');
  }
}
