import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  CreateDateColumn,
  JoinColumn,
} from 'typeorm';
import { ScanConfig } from '../../scan-config/entities/scan-config.entity';
import { ScanStatus } from '../../common/enums';

@Entity('scan_executions')
export class ScanExecution {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => ScanConfig, { eager: true })
  @JoinColumn({ name: 'scanConfigId' })
  scanConfig: ScanConfig;

  @Column({ type: 'enum', enum: ScanStatus, default: ScanStatus.PENDING })
  status: ScanStatus;

  @Column({ type: 'timestamp', nullable: true })
  startedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  finishedAt: Date;

  @Column({ type: 'int', default: 0 })
  progress: number;

  @Column({ type: 'int', default: 0 })
  totalVulnerabilities: number;

  @Column({ type: 'text', nullable: true })
  errorMessage: string;

  @CreateDateColumn()
  createdAt: Date;
}
