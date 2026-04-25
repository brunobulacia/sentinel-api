import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateReportDto } from './dto/report.dto';
import { Criticality } from '../common/enums';
import { ScanExecution, Vulnerability } from '@prisma/client';

type ExecutionWithConfig = ScanExecution & { scanConfig: { targetUrl: string } | null };

@Injectable()
export class ReportService {
  constructor(private readonly prisma: PrismaService) {}

  async create(dto: CreateReportDto) {
    const execution = await this.prisma.scanExecution.findUnique({
      where: { id: dto.scanExecutionId },
      include: { scanConfig: true },
    });
    if (!execution) throw new NotFoundException(`Execution ${dto.scanExecutionId} not found`);

    const vulns = await this.prisma.vulnerability.findMany({
      where: { scanExecutionId: dto.scanExecutionId },
    });

    const high = vulns.filter((v) => v.criticality === Criticality.HIGH);
    const medium = vulns.filter((v) => v.criticality === Criticality.MEDIUM);
    const low = vulns.filter((v) => v.criticality === Criticality.LOW);

    const content = this.buildHtmlReport(execution, vulns, high, medium, low);

    return this.prisma.report.create({
      data: {
        title: `Reporte de Seguridad - ${execution.scanConfig?.targetUrl ?? 'Sentinel'}`,
        format: dto.format ?? 'HTML',
        content,
        totalVulnerabilities: vulns.length,
        highCount: high.length,
        mediumCount: medium.length,
        lowCount: low.length,
        scanExecutionId: dto.scanExecutionId,
      },
    });
  }

  private buildHtmlReport(
    execution: ExecutionWithConfig,
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

  findAll() {
    return this.prisma.report.findMany({
      orderBy: { generatedAt: 'desc' },
      include: { scanExecution: { include: { scanConfig: true } } },
    });
  }

  async findOne(id: string) {
    const r = await this.prisma.report.findUnique({
      where: { id },
      include: { scanExecution: { include: { scanConfig: true } } },
    });
    if (!r) throw new NotFoundException(`Report ${id} not found`);
    return r;
  }

  async remove(id: string): Promise<void> {
    await this.findOne(id);
    await this.prisma.report.delete({ where: { id } });
  }
}
