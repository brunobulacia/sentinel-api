import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  CreateDateColumn,
  JoinColumn,
} from 'typeorm';
import { ScanExecution } from '../../scan-execution/entities/scan-execution.entity';

@Entity('reports')
export class Report {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column({ default: 'HTML' })
  format: string;

  @Column({ type: 'text' })
  content: string;

  @Column({ type: 'int', default: 0 })
  totalVulnerabilities: number;

  @Column({ type: 'int', default: 0 })
  highCount: number;

  @Column({ type: 'int', default: 0 })
  mediumCount: number;

  @Column({ type: 'int', default: 0 })
  lowCount: number;

  @ManyToOne(() => ScanExecution, { eager: true })
  @JoinColumn({ name: 'scanExecutionId' })
  scanExecution: ScanExecution;

  @CreateDateColumn()
  generatedAt: Date;
}
