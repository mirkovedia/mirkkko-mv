import { Module } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { SessionsController } from './sessions.controller';
import { DevicesModule } from '../devices/devices.module';
import { BlacklistModule } from '../blacklist/blacklist.module';

@Module({
  imports: [DevicesModule, BlacklistModule],
  providers: [SessionsService],
  controllers: [SessionsController],
})
export class SessionsModule {}
