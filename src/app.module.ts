import { Module } from '@nestjs/common';
import { ConfigModule } from './config/config.module';
import { PrismaModule } from './prisma/prisma.module';
import { CryptoModule } from './common/crypto/crypto.module';
import { AttestationModule } from './attestation/attestation.module';
import { HealthController } from './health.controller';

@Module({
  imports: [ConfigModule, PrismaModule, CryptoModule, AttestationModule],
  controllers: [HealthController],
})
export class AppModule {}
