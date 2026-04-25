import { Controller, Get, Param, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiQuery, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';

type AuthUser = { id: string; email: string; name: string };
import { ScanHistoryService } from './scan-history.service';
import { Criticality, ScanStatus } from '../common/enums';

@ApiTags('scan-history')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('scan-history')
export class ScanHistoryController {
  constructor(private readonly service: ScanHistoryService) {}

  @Get()
  @ApiOperation({ summary: 'Scan history with filters' })
  @ApiQuery({ name: 'from', required: false })
  @ApiQuery({ name: 'to', required: false })
  @ApiQuery({ name: 'criticality', enum: Criticality, required: false })
  @ApiQuery({ name: 'status', enum: ScanStatus, required: false })
  findAll(
    @CurrentUser() user: AuthUser,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('criticality') criticality?: Criticality,
    @Query('status') status?: ScanStatus,
  ) {
    return this.service.findAll(user.id, { from, to, criticality, status });
  }

  @Get('stats')
  @ApiOperation({ summary: 'Stats of last 10 scans for charts' })
  stats(@CurrentUser() user: AuthUser) {
    return this.service.stats(user.id);
  }

  @Get('compare/:id1/:id2')
  @ApiOperation({ summary: 'Compare two scans' })
  compare(@Param('id1') id1: string, @Param('id2') id2: string) {
    return this.service.compare(id1, id2);
  }
}
