import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanExecution } from './entities/scan-execution.entity';
import { Vulnerability } from '../vulnerability-classification/entities/vulnerability.entity';
import { ScanExecutionService } from './scan-execution.service';
import { ScanExecutionController } from './scan-execution.controller';
import { ScanConfigModule } from '../scan-config/scan-config.module';

@Module({
  imports: [TypeOrmModule.forFeature([ScanExecution, Vulnerability]), ScanConfigModule],
  controllers: [ScanExecutionController],
  providers: [ScanExecutionService],
  exports: [ScanExecutionService],
})
export class ScanExecutionModule {}
