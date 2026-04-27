import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Report } from './entities/report.entity';
import { Vulnerability } from '../vulnerability-classification/entities/vulnerability.entity';
import { ScanExecution } from '../scan-execution/entities/scan-execution.entity';
import { ReportService } from './report.service';
import { ReportController } from './report.controller';

@Module({
  imports: [TypeOrmModule.forFeature([Report, Vulnerability, ScanExecution])],
  controllers: [ReportController],
  providers: [ReportService],
})
export class ReportModule {}
