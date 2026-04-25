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
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

type AuthUser = { id: string; email: string; name: string };
import { ScanConfigService } from './scan-config.service';
import {
  CreateScanConfigDto,
  UpdateScanConfigDto,
} from './dto/scan-config.dto';

@ApiTags('scan-configs')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('scan-configs')
export class ScanConfigController {
  constructor(private readonly service: ScanConfigService) {}

  @Post()
  @ApiOperation({ summary: 'Create scan configuration' })
  create(@Body() dto: CreateScanConfigDto, @CurrentUser() user: AuthUser) {
    return this.service.create(dto, user.id);
  }

  @Get()
  @ApiOperation({ summary: 'List all active configurations' })
  findAll(@CurrentUser() user: AuthUser) {
    return this.service.findAll(user.id);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get configuration by ID' })
  findOne(@Param('id') id: string, @CurrentUser() user: AuthUser) {
    return this.service.findOne(id, user.id);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update configuration' })
  update(
    @Param('id') id: string,
    @Body() dto: UpdateScanConfigDto,
    @CurrentUser() user: AuthUser,
  ) {
    return this.service.update(id, dto, user.id);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Soft delete configuration' })
  remove(@Param('id') id: string, @CurrentUser() user: AuthUser) {
    return this.service.remove(id, user.id);
  }
}
