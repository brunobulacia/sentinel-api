import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ScanDepth, VulnerabilityType } from '../../common/enums';

@Entity('scan_configs')
export class ScanConfig {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column()
  targetUrl: string;

  @Column({
    type: 'simple-array',
    nullable: true,
  })
  vulnerabilityTypes: VulnerabilityType[];

  @Column({ type: 'enum', enum: ScanDepth, default: ScanDepth.MEDIUM })
  depth: ScanDepth;

  @Column({ type: 'timestamp', nullable: true })
  scheduledAt: Date;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
