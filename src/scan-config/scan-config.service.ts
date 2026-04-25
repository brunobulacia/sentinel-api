import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateScanConfigDto, UpdateScanConfigDto } from './dto/scan-config.dto';

@Injectable()
export class ScanConfigService {
  constructor(private readonly prisma: PrismaService) {}

  create(dto: CreateScanConfigDto, userId: string) {
    return this.prisma.scanConfig.create({
      data: {
        name: dto.name,
        targetUrl: dto.targetUrl,
        vulnerabilityTypes: dto.vulnerabilityTypes ?? [],
        depth: dto.depth,
        scheduledAt: dto.scheduledAt ? new Date(dto.scheduledAt) : null,
        userId,
      },
    });
  }

  findAll(userId: string) {
    return this.prisma.scanConfig.findMany({
      where: { isActive: true, userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOne(id: string, userId: string) {
    const config = await this.prisma.scanConfig.findFirst({
      where: { id, isActive: true, userId },
    });
    if (!config) throw new NotFoundException(`ScanConfig ${id} not found`);
    return config;
  }

  async update(id: string, dto: UpdateScanConfigDto, userId: string) {
    await this.findOne(id, userId);
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

  async remove(id: string, userId: string): Promise<void> {
    await this.findOne(id, userId);
    await this.prisma.scanConfig.update({
      where: { id },
      data: { isActive: false },
    });
  }
}
