import { Module } from '@nestjs/common';
import { MlAnalysisController } from './ml-analysis.controller';
import { MlAnalysisService } from './ml-analysis.service';

@Module({
  controllers: [MlAnalysisController],
  providers: [MlAnalysisService],
})
export class MlAnalysisModule {}
