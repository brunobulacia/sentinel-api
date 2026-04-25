import { Module } from '@nestjs/common';
import { ScanHistoryService } from './scan-history.service';
import { ScanHistoryController } from './scan-history.controller';

@Module({
  controllers: [ScanHistoryController],
  providers: [ScanHistoryService],
})
export class ScanHistoryModule {}
