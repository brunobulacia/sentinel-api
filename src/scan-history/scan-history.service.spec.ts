import { Test, TestingModule } from '@nestjs/testing';
import { ScanHistoryService } from './scan-history.service';
import { PrismaService } from '../prisma/prisma.service';
import { Criticality, ScanStatus } from '../common/enums';

const mockPrisma = {
  scanExecution: {
    findMany: jest.fn(),
  },
  vulnerability: {
    findMany: jest.fn(),
  },
};

function makeExecution(overrides: Record<string, unknown> = {}) {
  return {
    id: 'exec-1',
    status: ScanStatus.COMPLETED,
    createdAt: new Date('2026-01-01'),
    scanConfig: { targetUrl: 'http://example.com', userId: 'user-1' },
    vulnerabilities: [],
    ...overrides,
  };
}

describe('ScanHistoryService — Unit Tests', () => {
  let service: ScanHistoryService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ScanHistoryService,
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();

    service = module.get<ScanHistoryService>(ScanHistoryService);
    jest.clearAllMocks();
  });

  // ─── findAll() ─────────────────────────────────────────────────────────────

  describe('findAll()', () => {
    it('passes userId filter to prisma', async () => {
      mockPrisma.scanExecution.findMany.mockResolvedValue([]);
      await service.findAll('user-1', {});
      expect(mockPrisma.scanExecution.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ scanConfig: { userId: 'user-1' } }),
        }),
      );
    });

    it('adds status filter when provided', async () => {
      mockPrisma.scanExecution.findMany.mockResolvedValue([]);
      await service.findAll('user-1', { status: ScanStatus.COMPLETED });
      expect(mockPrisma.scanExecution.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ status: ScanStatus.COMPLETED }),
        }),
      );
    });

    it('adds date range filter when both from and to are provided', async () => {
      mockPrisma.scanExecution.findMany.mockResolvedValue([]);
      await service.findAll('user-1', { from: '2026-01-01', to: '2026-12-31' });
      const call = mockPrisma.scanExecution.findMany.mock.calls[0][0];
      expect(call.where.createdAt).toBeDefined();
      expect(call.where.createdAt.gte).toEqual(new Date('2026-01-01'));
      expect(call.where.createdAt.lte).toEqual(new Date('2026-12-31'));
    });

    it('does not add date filter when only from is provided', async () => {
      mockPrisma.scanExecution.findMany.mockResolvedValue([]);
      await service.findAll('user-1', { from: '2026-01-01' });
      const call = mockPrisma.scanExecution.findMany.mock.calls[0][0];
      expect(call.where.createdAt).toBeUndefined();
    });
  });

  // ─── stats() ───────────────────────────────────────────────────────────────

  describe('stats()', () => {
    it('returns empty array when no executions', async () => {
      mockPrisma.scanExecution.findMany.mockResolvedValue([]);
      const result = await service.stats('user-1');
      expect(result).toEqual([]);
    });

    it('correctly counts HIGH, MEDIUM, LOW vulnerabilities', async () => {
      const exec = makeExecution({
        vulnerabilities: [
          { criticality: Criticality.HIGH },
          { criticality: Criticality.HIGH },
          { criticality: Criticality.MEDIUM },
          { criticality: Criticality.LOW },
        ],
      });
      mockPrisma.scanExecution.findMany.mockResolvedValue([exec]);

      const result = await service.stats('user-1');
      expect(result[0].total).toBe(4);
      expect(result[0].high).toBe(2);
      expect(result[0].medium).toBe(1);
      expect(result[0].low).toBe(1);
    });

    it('returns total=0 and counts=0 for execution with no vulns', async () => {
      mockPrisma.scanExecution.findMany.mockResolvedValue([makeExecution()]);
      const result = await service.stats('user-1');
      expect(result[0]).toMatchObject({ total: 0, high: 0, medium: 0, low: 0 });
    });

    it('includes targetUrl and date in result', async () => {
      const exec = makeExecution();
      mockPrisma.scanExecution.findMany.mockResolvedValue([exec]);
      const result = await service.stats('user-1');
      expect(result[0].targetUrl).toBe('http://example.com');
      expect(result[0].date).toEqual(exec.createdAt);
    });
  });

  // ─── compare() ─────────────────────────────────────────────────────────────

  describe('compare()', () => {
    it('identifies new vulnerabilities in scan2 not present in scan1', async () => {
      mockPrisma.vulnerability.findMany
        .mockResolvedValueOnce([{ name: 'XSS in /search' }])
        .mockResolvedValueOnce([{ name: 'XSS in /search' }, { name: 'SQL Injection' }]);

      const result = await service.compare('exec-1', 'exec-2');
      expect(result.newInScan2).toContain('SQL Injection');
      expect(result.newInScan2).not.toContain('XSS in /search');
    });

    it('identifies resolved vulnerabilities (in scan1 but not in scan2)', async () => {
      mockPrisma.vulnerability.findMany
        .mockResolvedValueOnce([{ name: 'XSS in /search' }, { name: 'Old Vuln' }])
        .mockResolvedValueOnce([{ name: 'XSS in /search' }]);

      const result = await service.compare('exec-1', 'exec-2');
      expect(result.resolvedInScan2).toContain('Old Vuln');
      expect(result.resolvedInScan2).not.toContain('XSS in /search');
    });

    it('identifies persistent vulnerabilities (in both scans)', async () => {
      mockPrisma.vulnerability.findMany
        .mockResolvedValueOnce([{ name: 'Persistent Bug' }])
        .mockResolvedValueOnce([{ name: 'Persistent Bug' }]);

      const result = await service.compare('exec-1', 'exec-2');
      expect(result.persistent).toContain('Persistent Bug');
      expect(result.newInScan2).toHaveLength(0);
      expect(result.resolvedInScan2).toHaveLength(0);
    });

    it('includes scan totals in result', async () => {
      mockPrisma.vulnerability.findMany
        .mockResolvedValueOnce([{ name: 'A' }, { name: 'B' }])
        .mockResolvedValueOnce([{ name: 'C' }]);

      const result = await service.compare('exec-1', 'exec-2');
      expect(result.scan1.total).toBe(2);
      expect(result.scan2.total).toBe(1);
    });

    it('returns all empty when both scans have no vulnerabilities', async () => {
      mockPrisma.vulnerability.findMany.mockResolvedValue([]);
      const result = await service.compare('exec-1', 'exec-2');
      expect(result.newInScan2).toHaveLength(0);
      expect(result.resolvedInScan2).toHaveLength(0);
      expect(result.persistent).toHaveLength(0);
    });
  });
});
