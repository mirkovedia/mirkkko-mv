import { Module } from '@nestjs/common';
import { ConfigModule } from './config/config.module';
import { CryptoModule } from './common/crypto/crypto.module';
import { HealthController } from './health.controller';

@Module({
  imports: [ConfigModule, CryptoModule],
  controllers: [HealthController],
})
export class AppModule {}
