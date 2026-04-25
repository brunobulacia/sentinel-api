import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { ScanHistoryService } from './scan-history.service';
import { Criticality, ScanStatus } from '../common/enums';

@ApiTags('scan-history')
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
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('criticality') criticality?: Criticality,
    @Query('status') status?: ScanStatus,
  ) {
    return this.service.findAll({ from, to, criticality, status });
  }

  @Get('stats')
  @ApiOperation({ summary: 'Stats of last 10 scans for charts' })
  stats() {
    return this.service.stats();
  }

  @Get('compare/:id1/:id2')
  @ApiOperation({ summary: 'Compare two scans' })
  compare(@Param('id1') id1: string, @Param('id2') id2: string) {
    return this.service.compare(id1, id2);
  }
}
