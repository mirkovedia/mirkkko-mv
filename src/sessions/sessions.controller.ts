import { Body, Controller, HttpCode, Param, Post } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { StartSessionDto, SnapshotDto } from './dto/session.dto';

@Controller('sessions')
export class SessionsController {
  constructor(private readonly sessions: SessionsService) {}

  @Post('start')
  start(@Body() dto: StartSessionDto) {
    return this.sessions.start(dto);
  }

  @Post(':id/snapshot')
  @HttpCode(200)
  snapshot(@Param('id') id: string, @Body() dto: SnapshotDto) {
    return this.sessions.processSnapshot(id, dto);
  }
}
