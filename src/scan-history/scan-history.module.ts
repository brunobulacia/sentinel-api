import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanExecution } from '../scan-execution/entities/scan-execution.entity';
import { Vulnerability } from '../vulnerability-classification/entities/vulnerability.entity';
import { ScanHistoryService } from './scan-history.service';
import { ScanHistoryController } from './scan-history.controller';

@Module({
  imports: [TypeOrmModule.forFeature([ScanExecution, Vulnerability])],
  controllers: [ScanHistoryController],
  providers: [ScanHistoryService],
})
export class ScanHistoryModule {}
