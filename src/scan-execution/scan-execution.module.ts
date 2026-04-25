import { Module } from '@nestjs/common';
import { ScanExecutionService } from './scan-execution.service';
import { ScanExecutionController } from './scan-execution.controller';
import { ScanConfigModule } from '../scan-config/scan-config.module';

@Module({
  imports: [ScanConfigModule],
  controllers: [ScanExecutionController],
  providers: [ScanExecutionService],
  exports: [ScanExecutionService],
})
export class ScanExecutionModule {}
