import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { ScanExecutionService } from './scan-execution.service';
import { CreateScanExecutionDto } from './dto/scan-execution.dto';

@ApiTags('scan-executions')
@Controller('scan-executions')
export class ScanExecutionController {
  constructor(private readonly service: ScanExecutionService) {}

  @Post()
  @ApiOperation({ summary: 'Execute a scan' })
  create(@Body() dto: CreateScanExecutionDto) {
    return this.service.create(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List all executions' })
  findAll() {
    return this.service.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get execution detail (includes live progress)' })
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }
}
