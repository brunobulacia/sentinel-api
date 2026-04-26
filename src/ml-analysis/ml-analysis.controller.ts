import { Controller, Get, Param, Post, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { IsString, IsNumber, IsBoolean, IsOptional, Min, Max } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { MlAnalysisService } from './ml-analysis.service';

type AuthUser = { id: string; email: string; name: string };

class PredictDto {
  @ApiProperty() @IsString() vuln_type: string;
  @ApiPropertyOptional() @IsNumber() @Min(0) @Max(10) @IsOptional() cvss_score?: number;
  @ApiPropertyOptional() @IsNumber() @IsOptional() url_depth?: number;
  @ApiPropertyOptional() @IsBoolean() @IsOptional() has_param?: boolean;
  @ApiPropertyOptional() @IsNumber() @IsOptional() response_time_ms?: number;
  @ApiPropertyOptional() @IsString() @IsOptional() method?: string;
}

@ApiTags('ml-analysis')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('ml-analysis')
export class MlAnalysisController {
  constructor(private readonly service: MlAnalysisService) {}

  @Get('model/info')
  @ApiOperation({ summary: 'Random Forest model metadata and accuracy' })
  modelInfo(): Promise<unknown> {
    return this.service.getModelInfo();
  }

  @Get(':executionId')
  @ApiOperation({ summary: 'ML-based severity prediction for all vulns in a scan' })
  analyze(@Param('executionId') executionId: string, @CurrentUser() user: AuthUser): Promise<unknown> {
    return this.service.analyzeExecution(executionId, user.id);
  }

  @Post('predict')
  @ApiOperation({ summary: 'Single vulnerability severity prediction' })
  predict(@Body() dto: PredictDto): Promise<unknown> {
    return this.service.predictSingle({
      vuln_type: dto.vuln_type,
      cvss_score: dto.cvss_score ?? 5.0,
      url_depth: dto.url_depth ?? 1,
      has_param: dto.has_param ?? false,
      response_time_ms: dto.response_time_ms ?? 200,
      method: dto.method ?? 'GET',
    });
  }
}
