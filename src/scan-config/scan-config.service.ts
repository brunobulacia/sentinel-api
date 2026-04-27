import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ScanConfig } from './entities/scan-config.entity';
import { CreateScanConfigDto, UpdateScanConfigDto } from './dto/scan-config.dto';

@Injectable()
export class ScanConfigService {
  constructor(
    @InjectRepository(ScanConfig)
    private readonly repo: Repository<ScanConfig>,
  ) {}

  create(dto: CreateScanConfigDto): Promise<ScanConfig> {
    const entity = this.repo.create(dto as Partial<ScanConfig>);
    return this.repo.save(entity);
  }

  findAll(): Promise<ScanConfig[]> {
    return this.repo.find({ where: { isActive: true }, order: { createdAt: 'DESC' } });
  }

  async findOne(id: string): Promise<ScanConfig> {
    const config = await this.repo.findOne({ where: { id, isActive: true } });
    if (!config) throw new NotFoundException(`ScanConfig ${id} not found`);
    return config;
  }

  async update(id: string, dto: UpdateScanConfigDto): Promise<ScanConfig> {
    const config = await this.findOne(id);
    Object.assign(config, dto);
    return this.repo.save(config);
  }

  async remove(id: string): Promise<void> {
    const config = await this.findOne(id);
    config.isActive = false;
    await this.repo.save(config);
  }
}
