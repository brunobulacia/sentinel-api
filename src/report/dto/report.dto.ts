import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsUUID, IsEnum, IsOptional } from 'class-validator';

export enum ReportFormat {
  PDF = 'PDF',
  HTML = 'HTML',
}

export class CreateReportDto {
  @ApiProperty()
  @IsUUID()
  scanExecutionId: string;

  @ApiPropertyOptional({ enum: ReportFormat, default: ReportFormat.HTML })
  @IsEnum(ReportFormat)
  @IsOptional()
  format?: ReportFormat;
}
