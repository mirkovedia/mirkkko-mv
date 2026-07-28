import { Body, Controller, Post } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { StartSessionDto } from './dto/session.dto';

@Controller('sessions')
export class SessionsController {
  constructor(private readonly sessions: SessionsService) {}

  @Post('start')
  start(@Body() dto: StartSessionDto) {
    return this.sessions.start(dto);
  }
}
