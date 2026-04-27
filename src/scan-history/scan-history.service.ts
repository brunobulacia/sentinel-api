import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Between } from 'typeorm';
import { ScanExecution } from '../scan-execution/entities/scan-execution.entity';
import { Vulnerability } from '../vulnerability-classification/entities/vulnerability.entity';
import { Criticality, ScanStatus } from '../common/enums';

@Injectable()
export class ScanHistoryService {
  constructor(
    @InjectRepository(ScanExecution)
    private readonly executionRepo: Repository<ScanExecution>,
    @InjectRepository(Vulnerability)
    private readonly vulnRepo: Repository<Vulnerability>,
  ) {}

  async findAll(filters: { from?: string; to?: string; criticality?: Criticality; status?: ScanStatus }) {
    const where: Record<string, unknown> = {};
    if (filters.status) where.status = filters.status;
    if (filters.from && filters.to) {
      where.createdAt = Between(new Date(filters.from), new Date(filters.to));
    }
    return this.executionRepo.find({ where, order: { createdAt: 'DESC' } });
  }

  async stats() {
    const all = await this.executionRepo.find({ order: { createdAt: 'DESC' }, take: 10 });
    const stats = await Promise.all(
      all.map(async (ex) => {
        const vulns = await this.vulnRepo.find({ where: { scanExecutionId: ex.id } });
        return {
          id: ex.id,
          date: ex.createdAt,
          status: ex.status,
          targetUrl: ex.scanConfig?.targetUrl,
          total: vulns.length,
          high: vulns.filter((v) => v.criticality === Criticality.HIGH).length,
          medium: vulns.filter((v) => v.criticality === Criticality.MEDIUM).length,
          low: vulns.filter((v) => v.criticality === Criticality.LOW).length,
        };
      }),
    );
    return stats;
  }

  async compare(id1: string, id2: string) {
    const [vulns1, vulns2] = await Promise.all([
      this.vulnRepo.find({ where: { scanExecutionId: id1 } }),
      this.vulnRepo.find({ where: { scanExecutionId: id2 } }),
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
