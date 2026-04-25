import { Module } from '@nestjs/common';
import { ScanConfigService } from './scan-config.service';
import { ScanConfigController } from './scan-config.controller';

@Module({
  controllers: [ScanConfigController],
  providers: [ScanConfigService],
  exports: [ScanConfigService],
})
export class ScanConfigModule {}
