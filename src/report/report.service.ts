import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Report } from './entities/report.entity';
import { Vulnerability } from '../vulnerability-classification/entities/vulnerability.entity';
import { ScanExecution } from '../scan-execution/entities/scan-execution.entity';
import { CreateReportDto } from './dto/report.dto';
import { Criticality } from '../common/enums';

@Injectable()
export class ReportService {
  constructor(
    @InjectRepository(Report)
    private readonly reportRepo: Repository<Report>,
    @InjectRepository(Vulnerability)
    private readonly vulnRepo: Repository<Vulnerability>,
    @InjectRepository(ScanExecution)
    private readonly executionRepo: Repository<ScanExecution>,
  ) {}

  async create(dto: CreateReportDto): Promise<Report> {
    const execution = await this.executionRepo.findOne({ where: { id: dto.scanExecutionId } });
    if (!execution) throw new NotFoundException(`Execution ${dto.scanExecutionId} not found`);

    const vulns = await this.vulnRepo.find({ where: { scanExecutionId: dto.scanExecutionId } });

    const high = vulns.filter((v) => v.criticality === Criticality.HIGH);
    const medium = vulns.filter((v) => v.criticality === Criticality.MEDIUM);
    const low = vulns.filter((v) => v.criticality === Criticality.LOW);

    const content = this.buildHtmlReport(execution, vulns, high, medium, low);

    const report = this.reportRepo.create({
      title: `Reporte de Seguridad - ${execution.scanConfig?.targetUrl ?? 'Sentinel'}`,
      format: dto.format ?? 'HTML',
      content,
      totalVulnerabilities: vulns.length,
      highCount: high.length,
      mediumCount: medium.length,
      lowCount: low.length,
      scanExecution: execution,
    });
    return this.reportRepo.save(report);
  }

  private buildHtmlReport(
    execution: ScanExecution,
    vulns: Vulnerability[],
    high: Vulnerability[],
    medium: Vulnerability[],
    low: Vulnerability[],
  ): string {
    const rows = vulns
      .map(
        (v) => `<tr>
        <td>${v.name}</td>
        <td>${v.type}</td>
        <td style="color:${v.criticality === Criticality.HIGH ? '#dc2626' : v.criticality === Criticality.MEDIUM ? '#d97706' : '#16a34a'}">${v.criticality}</td>
        <td>${v.cvssScore ?? '-'}</td>
        <td>${v.affectedUrl}</td>
        <td>${v.remediated ? '✅' : '❌'}</td>
      </tr>`,
      )
      .join('');

    return `<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Reporte Sentinel</title>
<style>body{font-family:sans-serif;padding:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:8px;text-align:left}th{background:#1e3a5f;color:#fff}.badge-high{background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px}.badge-medium{background:#d97706;color:#fff;padding:2px 8px;border-radius:4px}.badge-low{background:#16a34a;color:#fff;padding:2px 8px;border-radius:4px}</style>
</head>
<body>
<h1>🛡 Informe de Seguridad Web — Sentinel</h1>
<p><strong>URL Objetivo:</strong> ${execution.scanConfig?.targetUrl}</p>
<p><strong>Fecha:</strong> ${new Date().toLocaleString('es-BO')}</p>
<p><strong>Estado:</strong> ${execution.status}</p>
<h2>Resumen</h2>
<table><tr><th>Total</th><th>Alta</th><th>Media</th><th>Baja</th></tr>
<tr><td>${vulns.length}</td><td>${high.length}</td><td>${medium.length}</td><td>${low.length}</td></tr></table>
<h2>Vulnerabilidades Detectadas</h2>
<table><tr><th>Nombre</th><th>Tipo</th><th>Criticidad</th><th>CVSS</th><th>URL Afectada</th><th>Remediada</th></tr>
${rows}
</table>
<h2>Recomendaciones</h2>
${vulns.map((v) => `<h3>${v.name} (${v.criticality})</h3><p>${v.recommendation}</p>`).join('')}
</body></html>`;
  }

  findAll(): Promise<Report[]> {
    return this.reportRepo.find({ order: { generatedAt: 'DESC' } });
  }

  async findOne(id: string): Promise<Report> {
    const r = await this.reportRepo.findOne({ where: { id } });
    if (!r) throw new NotFoundException(`Report ${id} not found`);
    return r;
  }

  async remove(id: string): Promise<void> {
    await this.findOne(id);
    await this.reportRepo.delete(id);
  }
}
