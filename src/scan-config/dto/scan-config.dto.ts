import { ApiProperty, ApiPropertyOptional, PartialType } from '@nestjs/swagger';
import {
  IsString,
  IsUrl,
  IsArray,
  IsEnum,
  IsOptional,
  IsDateString,
} from 'class-validator';
import { ScanDepth, VulnerabilityType } from '../../common/enums';

export class CreateScanConfigDto {
  @ApiProperty({ example: 'Production Scan' })
  @IsString()
  name: string;

  @ApiProperty({ example: 'https://example.com' })
  @IsUrl()
  targetUrl: string;

  @ApiPropertyOptional({ enum: VulnerabilityType, isArray: true })
  @IsArray()
  @IsEnum(VulnerabilityType, { each: true })
  @IsOptional()
  vulnerabilityTypes?: VulnerabilityType[];

  @ApiPropertyOptional({ enum: ScanDepth, default: ScanDepth.MEDIUM })
  @IsEnum(ScanDepth)
  @IsOptional()
  depth?: ScanDepth;

  @ApiPropertyOptional({ example: '2026-04-25T10:00:00Z' })
  @IsDateString()
  @IsOptional()
  scheduledAt?: string;
}

export class UpdateScanConfigDto extends PartialType(CreateScanConfigDto) {}
