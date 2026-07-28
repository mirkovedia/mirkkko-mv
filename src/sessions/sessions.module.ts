import { Module } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { SessionsController } from './sessions.controller';
import { ReaperService } from './reaper.service';
import { DevicesModule } from '../devices/devices.module';
import { BlacklistModule } from '../blacklist/blacklist.module';

@Module({
  imports: [DevicesModule, BlacklistModule],
  providers: [SessionsService, ReaperService],
  controllers: [SessionsController],
})
export class SessionsModule {}
