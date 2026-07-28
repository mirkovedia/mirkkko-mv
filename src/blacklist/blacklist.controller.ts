import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AdminApiKeyGuard } from '../common/guards/admin-api-key.guard';
import { BlacklistService } from './blacklist.service';
import { CreateBlacklistEntryDto } from './dto/blacklist.dto';

@Controller('blacklist')
export class BlacklistController {
  constructor(private readonly blacklist: BlacklistService) {}

  @Get()
  list() {
    return this.blacklist.list();
  }

  @Post()
  @UseGuards(AdminApiKeyGuard)
  add(@Body() dto: CreateBlacklistEntryDto) {
    return this.blacklist.add(dto);
  }

  @Delete(':id')
  @UseGuards(AdminApiKeyGuard)
  async remove(@Param('id') id: string) {
    await this.blacklist.remove(id);
    return { removed: true };
  }
}
