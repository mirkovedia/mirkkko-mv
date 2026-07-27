import { Global, Module } from '@nestjs/common';
import { SignatureService } from './signature.service';
import { NonceService } from './nonce.service';

@Global()
@Module({ providers: [SignatureService, NonceService], exports: [SignatureService, NonceService] })
export class CryptoModule {}
