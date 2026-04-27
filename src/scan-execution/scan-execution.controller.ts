import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

type AuthUser = { id: string; email: string; name: string };
import { ScanExecutionService } from './scan-execution.service';
import { CreateScanExecutionDto } from './dto/scan-execution.dto';

@ApiTags('scan-executions')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('scan-executions')
export class ScanExecutionController {
  constructor(private readonly service: ScanExecutionService) {}

  @Post()
  @ApiOperation({ summary: 'Execute a scan' })
  create(@Body() dto: CreateScanExecutionDto, @CurrentUser() user: AuthUser) {
    return this.service.create(dto, user.id);
  }

  @Get()
  @ApiOperation({ summary: 'List all executions' })
  findAll(@CurrentUser() user: AuthUser) {
    return this.service.findAll(user.id);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get execution detail (includes live progress)' })
  findOne(@Param('id') id: string, @CurrentUser() user: AuthUser) {
    return this.service.findOne(id, user.id);
  }
}
