import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Criticality, ScanStatus } from '../common/enums';

@Injectable()
export class ScanHistoryService {
  constructor(private readonly prisma: PrismaService) {}

  findAll(userId: string, filters: { from?: string; to?: string; criticality?: Criticality; status?: ScanStatus }) {
    return this.prisma.scanExecution.findMany({
      where: {
        scanConfig: { userId },
        ...(filters.status && { status: filters.status }),
        ...(filters.from &&
          filters.to && {
            createdAt: {
              gte: new Date(filters.from),
              lte: new Date(filters.to),
            },
          }),
      },
      orderBy: { createdAt: 'desc' },
      include: { scanConfig: true },
    });
  }

  async stats(userId: string) {
    const all = await this.prisma.scanExecution.findMany({
      where: { scanConfig: { userId } },
      orderBy: { createdAt: 'desc' },
      take: 10,
      include: { scanConfig: true, vulnerabilities: true },
    });

    return all.map((ex) => ({
      id: ex.id,
      date: ex.createdAt,
      status: ex.status,
      targetUrl: ex.scanConfig?.targetUrl,
      total: ex.vulnerabilities.length,
      high: ex.vulnerabilities.filter((v) => v.criticality === Criticality.HIGH).length,
      medium: ex.vulnerabilities.filter((v) => v.criticality === Criticality.MEDIUM).length,
      low: ex.vulnerabilities.filter((v) => v.criticality === Criticality.LOW).length,
    }));
  }

  async compare(id1: string, id2: string) {
    const [vulns1, vulns2] = await Promise.all([
      this.prisma.vulnerability.findMany({ where: { scanExecutionId: id1 } }),
      this.prisma.vulnerability.findMany({ where: { scanExecutionId: id2 } }),
    ]);

    const names1 = new Set(vulns1.map((v) => v.name));
    const names2 = new Set(vulns2.map((v) => v.name));

    return {
      scan1: { id: id1, total: vulns1.length },
      scan2: { id: id2, total: vulns2.length },
      newInScan2: vulns2.filter((v) => !names1.has(v.name)).map((v) => v.name),
      resolvedInScan2: vulns1.filter((v) => !names2.has(v.name)).map((v) => v.name),
      persistent: vulns2.filter((v) => names1.has(v.name)).map((v) => v.name),
    };
  }
}
