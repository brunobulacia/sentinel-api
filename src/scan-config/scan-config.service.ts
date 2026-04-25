import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateScanConfigDto, UpdateScanConfigDto } from './dto/scan-config.dto';

@Injectable()
export class ScanConfigService {
  constructor(private readonly prisma: PrismaService) {}

  create(dto: CreateScanConfigDto) {
    return this.prisma.scanConfig.create({
      data: {
        name: dto.name,
        targetUrl: dto.targetUrl,
        vulnerabilityTypes: dto.vulnerabilityTypes ?? [],
        depth: dto.depth,
        scheduledAt: dto.scheduledAt ? new Date(dto.scheduledAt) : null,
      },
    });
  }

  findAll() {
    return this.prisma.scanConfig.findMany({
      where: { isActive: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOne(id: string) {
    const config = await this.prisma.scanConfig.findFirst({
      where: { id, isActive: true },
    });
    if (!config) throw new NotFoundException(`ScanConfig ${id} not found`);
    return config;
  }

  async update(id: string, dto: UpdateScanConfigDto) {
    await this.findOne(id);
    return this.prisma.scanConfig.update({
      where: { id },
      data: {
        name: dto.name,
        targetUrl: dto.targetUrl,
        vulnerabilityTypes: dto.vulnerabilityTypes,
        depth: dto.depth,
        scheduledAt:
          dto.scheduledAt !== undefined
            ? dto.scheduledAt
              ? new Date(dto.scheduledAt)
              : null
            : undefined,
      },
    });
  }

  async remove(id: string): Promise<void> {
    await this.findOne(id);
    await this.prisma.scanConfig.update({
      where: { id },
      data: { isActive: false },
    });
  }
}
