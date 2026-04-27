import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  Res,
} from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import type { Response } from 'express';
import { ReportService } from './report.service';
import { CreateReportDto } from './dto/report.dto';

@ApiTags('reports')
@Controller('reports')
export class ReportController {
  constructor(private readonly service: ReportService) {}

  @Post()
  @ApiOperation({ summary: 'Generate report for an execution' })
  create(@Body() dto: CreateReportDto) {
    return this.service.create(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List all reports' })
  findAll() {
    return this.service.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get report detail' })
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }

  @Get(':id/download')
  @ApiOperation({ summary: 'Download HTML report' })
  async download(@Param('id') id: string, @Res() res: Response) {
    const report = await this.service.findOne(id);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="sentinel-report-${id}.html"`);
    res.send(report.content);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete report' })
  remove(@Param('id') id: string) {
    return this.service.remove(id);
  }
}
