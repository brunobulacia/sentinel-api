import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ScanConfigService } from '../scan-config/scan-config.service';
import { CreateScanExecutionDto } from './dto/scan-execution.dto';
import { ScanStatus } from '../common/enums';
import { ScannerEngine } from './scanner';

@Injectable()
export class ScanExecutionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly scanConfigService: ScanConfigService,
  ) {}

  async create(dto: CreateScanExecutionDto, userId: string) {
    const config = await this.scanConfigService.findOne(
      dto.scanConfigId,
      userId,
    );
    const execution = await this.prisma.scanExecution.create({
      data: {
        scanConfigId: dto.scanConfigId,
        status: ScanStatus.PENDING,
        progress: 0,
      },
    });
    this.runScan(execution.id, config.targetUrl, config.depth).catch(
      () => null,
    );
    return execution;
  }

  private async runScan(
    executionId: string,
    targetUrl: string,
    depth: string,
  ): Promise<void> {
    await this.prisma.scanExecution.update({
      where: { id: executionId },
      data: { status: ScanStatus.RUNNING, startedAt: new Date(), progress: 3 },
    });

    try {
      const engine = new ScannerEngine(targetUrl, depth);

      const vulnerabilities = await engine.scan(async (progress) => {
        await this.prisma.scanExecution.update({
          where: { id: executionId },
          data: { progress },
        });
      });

      if (vulnerabilities.length > 0) {
        await this.prisma.vulnerability.createMany({
          data: vulnerabilities.map((v) => ({
            ...v,
            scanExecutionId: executionId,
          })),
        });
      }

      await this.prisma.scanExecution.update({
        where: { id: executionId },
        data: {
          status: ScanStatus.COMPLETED,
          finishedAt: new Date(),
          progress: 100,
          totalVulnerabilities: vulnerabilities.length,
        },
      });
    } catch (err) {
      await this.prisma.scanExecution.update({
        where: { id: executionId },
        data: {
          status: ScanStatus.FAILED,
          finishedAt: new Date(),
          errorMessage: String(err),
        },
      });
    }
  }

  findAll(userId: string) {
    return this.prisma.scanExecution.findMany({
      where: { scanConfig: { userId } },
      orderBy: { createdAt: 'desc' },
      include: { scanConfig: true },
    });
  }

  async findOne(id: string, userId: string) {
    const ex = await this.prisma.scanExecution.findFirst({
      where: { id, scanConfig: { userId } },
      include: { scanConfig: true },
    });
    if (!ex) throw new NotFoundException(`ScanExecution ${id} not found`);
    return ex;
  }
}
