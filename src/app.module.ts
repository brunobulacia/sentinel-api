import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ScanConfigModule } from './scan-config/scan-config.module';
import { ScanExecutionModule } from './scan-execution/scan-execution.module';
import { VulnerabilityClassificationModule } from './vulnerability-classification/vulnerability-classification.module';
import { ReportModule } from './report/report.module';
import { ScanHistoryModule } from './scan-history/scan-history.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    PrismaModule,
    AuthModule,
    UsersModule,
    ScanConfigModule,
    ScanExecutionModule,
    VulnerabilityClassificationModule,
    ReportModule,
    ScanHistoryModule,
  ],
})
export class AppModule {}
