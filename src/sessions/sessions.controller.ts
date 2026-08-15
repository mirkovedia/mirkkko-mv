import { Body, Controller, Get, HttpCode, Param, Post } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { StartSessionDto, SnapshotDto, EndSessionDto } from './dto/session.dto';

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

  @Post(':id/end')
  end(@Param('id') id: string, @Body() dto: EndSessionDto) {
    return this.sessions.end(id, dto);
  }

  @Get(':id/verdict')
  verdict(@Param('id') id: string) {
    return this.sessions.getVerdict(id);
  }
}
