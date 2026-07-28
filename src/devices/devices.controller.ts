import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { AdminApiKeyGuard } from '../common/guards/admin-api-key.guard';
import { DevicesService } from './devices.service';
import { EnrollDeviceDto } from './dto/enroll.dto';

@Controller('devices')
export class DevicesController {
  constructor(private readonly devices: DevicesService) {}

  @Post('enroll')
  enroll(@Body() dto: EnrollDeviceDto) {
    return this.devices.enroll(dto);
  }

  @Get(':id')
  @UseGuards(AdminApiKeyGuard)
  history(@Param('id') id: string) {
    return this.devices.history(id);
  }
}
