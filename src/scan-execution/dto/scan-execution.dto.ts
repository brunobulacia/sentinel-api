import { ApiProperty } from '@nestjs/swagger';
import { IsUUID } from 'class-validator';

export class CreateScanExecutionDto {
  @ApiProperty({ description: 'ID of the scan configuration to execute' })
  @IsUUID()
  scanConfigId: string;
}
