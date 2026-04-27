import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { ScanConfigService } from './scan-config.service';
import { CreateScanConfigDto, UpdateScanConfigDto } from './dto/scan-config.dto';

@ApiTags('scan-configs')
@Controller('scan-configs')
export class ScanConfigController {
  constructor(private readonly service: ScanConfigService) {}

  @Post()
  @ApiOperation({ summary: 'Create scan configuration' })
  create(@Body() dto: CreateScanConfigDto) {
    return this.service.create(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List all active configurations' })
  findAll() {
    return this.service.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get configuration by ID' })
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update configuration' })
  update(@Param('id') id: string, @Body() dto: UpdateScanConfigDto) {
    return this.service.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Soft delete configuration' })
  remove(@Param('id') id: string) {
    return this.service.remove(id);
  }
}
