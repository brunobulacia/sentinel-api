import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanConfig } from './scan-config/entities/scan-config.entity';
import { ScanExecution } from './scan-execution/entities/scan-execution.entity';
import { Vulnerability } from './vulnerability-classification/entities/vulnerability.entity';
import { Report } from './report/entities/report.entity';
import { ScanConfigModule } from './scan-config/scan-config.module';
import { ScanExecutionModule } from './scan-execution/scan-execution.module';
import { VulnerabilityClassificationModule } from './vulnerability-classification/vulnerability-classification.module';
import { ReportModule } from './report/report.module';
import { ScanHistoryModule } from './scan-history/scan-history.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST ?? 'localhost',
      port: parseInt(process.env.DB_PORT ?? '5432'),
      username: process.env.DB_USER ?? 'postgres',
      password: process.env.DB_PASS ?? 'postgres',
      database: process.env.DB_NAME ?? 'sentinel',
      entities: [ScanConfig, ScanExecution, Vulnerability, Report],
      synchronize: true,
    }),
    ScanConfigModule,
    ScanExecutionModule,
    VulnerabilityClassificationModule,
    ReportModule,
    ScanHistoryModule,
  ],
})
export class AppModule {}
