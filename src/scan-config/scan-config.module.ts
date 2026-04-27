import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanConfig } from './entities/scan-config.entity';
import { ScanConfigService } from './scan-config.service';
import { ScanConfigController } from './scan-config.controller';

@Module({
  imports: [TypeOrmModule.forFeature([ScanConfig])],
  controllers: [ScanConfigController],
  providers: [ScanConfigService],
  exports: [ScanConfigService],
})
export class ScanConfigModule {}
