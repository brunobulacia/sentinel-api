import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { MlAnalysisService } from './ml-analysis.service';
import { PrismaService } from '../prisma/prisma.service';
import { Criticality } from '../common/enums';

const mockPrisma = {
  scanExecution: { findFirst: jest.fn() },
};

function makeMlResponse(predictions: unknown[]) {
  return {
    ok: true,
    json: jest.fn().mockResolvedValue({ count: predictions.length, predictions }),
    text: jest.fn().mockResolvedValue(''),
  };
}

describe('MlAnalysisService — Unit Tests', () => {
  let service: MlAnalysisService;

  beforeEach(async () => {
    process.env.ML_SERVICE_URL = 'http://localhost:8000';

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MlAnalysisService,
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();

    service = module.get<MlAnalysisService>(MlAnalysisService);
    jest.clearAllMocks();
  });

  // ─── urlDepth() — white-box boundary tests ──────────────────────────────────

  describe('urlDepth() (via predictSingle to test private logic)', () => {
    // Access private method directly for white-box coverage
    function depth(url: string): number {
      return (service as unknown as { urlDepth: (u: string) => number }).urlDepth(url);
    }

    it('returns 0 for root URL with no path segments', () => {
      expect(depth('https://example.com')).toBe(0);
      expect(depth('https://example.com/')).toBe(0);
    });

    it('returns 1 for single-segment path', () => {
      expect(depth('https://example.com/page')).toBe(1);
    });

    it('returns correct depth for nested paths', () => {
      expect(depth('https://example.com/api/users/profile')).toBe(3);
    });

    it('returns 1 for malformed URL (fallback)', () => {
      expect(depth('not-a-url')).toBe(1);
    });

    it('ignores query string in depth calculation', () => {
      expect(depth('https://example.com/search?q=hello')).toBe(1);
    });
  });

  // ─── analyzeExecution() ────────────────────────────────────────────────────

  describe('analyzeExecution()', () => {
    it('throws NotFoundException when execution not found', async () => {
      mockPrisma.scanExecution.findFirst.mockResolvedValue(null);
      await expect(service.analyzeExecution('bad-id', 'user-1')).rejects.toThrow(NotFoundException);
    });

    it('returns empty predictions when execution has no vulnerabilities', async () => {
      mockPrisma.scanExecution.findFirst.mockResolvedValue({
        id: 'exec-1',
        scanConfig: { targetUrl: 'http://example.com', userId: 'user-1' },
        vulnerabilities: [],
      });

      const result = await service.analyzeExecution('exec-1', 'user-1');
      expect(result.predictions).toHaveLength(0);
      expect(result.summary).toEqual({ HIGH: 0, MEDIUM: 0, LOW: 0, avgConfidence: 0 });
    });

    it('enriches predictions with vulnerability metadata', async () => {
      const vuln = {
        id: 'vuln-1',
        name: 'XSS in /search',
        type: 'XSS',
        cvssScore: 7.5,
        affectedUrl: 'http://example.com/search?q=test',
        criticality: Criticality.HIGH,
      };

      mockPrisma.scanExecution.findFirst.mockResolvedValue({
        id: 'exec-1',
        scanConfig: { targetUrl: 'http://example.com', userId: 'user-1' },
        vulnerabilities: [vuln],
      });

      global.fetch = jest.fn().mockResolvedValue(
        makeMlResponse([{
          vuln_id: 'vuln-1',
          criticality: 'HIGH',
          confidence: 0.92,
          probabilities: { HIGH: 0.92, MEDIUM: 0.06, LOW: 0.02 },
        }]),
      ) as jest.Mock;

      const result = await service.analyzeExecution('exec-1', 'user-1');
      const pred = result.predictions[0];

      expect(pred.name).toBe('XSS in /search');
      expect(pred.type).toBe('XSS');
      expect(pred.cvssScore).toBe(7.5);
      expect(pred.affectedUrl).toBe('http://example.com/search?q=test');
      expect(pred.currentCriticality).toBe(Criticality.HIGH);
      expect(pred.mlCriticality).toBe('HIGH');
      expect(pred.agreement).toBe(true);
    });

    it('sets agreement=false when ML and scanner disagree', async () => {
      const vuln = {
        id: 'vuln-1',
        name: 'Open Redirect',
        type: 'OPEN_REDIRECT',
        cvssScore: 4.0,
        affectedUrl: 'http://example.com',
        criticality: Criticality.LOW,
      };

      mockPrisma.scanExecution.findFirst.mockResolvedValue({
        id: 'exec-1',
        scanConfig: { targetUrl: 'http://example.com', userId: 'user-1' },
        vulnerabilities: [vuln],
      });

      global.fetch = jest.fn().mockResolvedValue(
        makeMlResponse([{
          vuln_id: 'vuln-1',
          criticality: 'MEDIUM',
          confidence: 0.75,
          probabilities: { HIGH: 0.1, MEDIUM: 0.75, LOW: 0.15 },
        }]),
      ) as jest.Mock;

      const result = await service.analyzeExecution('exec-1', 'user-1');
      expect(result.predictions[0].agreement).toBe(false);
    });

    it('uses fallback name "Desconocida" when vuln_id not found in map', async () => {
      const vuln = {
        id: 'vuln-1',
        name: 'CSRF',
        type: 'CSRF',
        cvssScore: 5.4,
        affectedUrl: 'http://example.com',
        criticality: Criticality.MEDIUM,
      };

      mockPrisma.scanExecution.findFirst.mockResolvedValue({
        id: 'exec-1',
        scanConfig: { targetUrl: 'http://example.com', userId: 'user-1' },
        vulnerabilities: [vuln],
      });

      global.fetch = jest.fn().mockResolvedValue(
        makeMlResponse([{
          vuln_id: null,
          criticality: 'MEDIUM',
          confidence: 0.8,
          probabilities: { HIGH: 0.05, MEDIUM: 0.8, LOW: 0.15 },
        }]),
      ) as jest.Mock;

      const result = await service.analyzeExecution('exec-1', 'user-1');
      expect(result.predictions[0].name).toBe('Desconocida');
    });

    it('correctly builds summary counts and avgConfidence', async () => {
      const vulns = [
        { id: 'v1', name: 'A', type: 'XSS', cvssScore: 7.0, affectedUrl: 'http://a.com', criticality: 'HIGH' },
        { id: 'v2', name: 'B', type: 'CSRF', cvssScore: 5.0, affectedUrl: 'http://b.com', criticality: 'MEDIUM' },
      ];

      mockPrisma.scanExecution.findFirst.mockResolvedValue({
        id: 'exec-1',
        scanConfig: { targetUrl: 'http://example.com', userId: 'user-1' },
        vulnerabilities: vulns,
      });

      global.fetch = jest.fn().mockResolvedValue(
        makeMlResponse([
          { vuln_id: 'v1', criticality: 'HIGH', confidence: 0.9, probabilities: {} },
          { vuln_id: 'v2', criticality: 'MEDIUM', confidence: 0.7, probabilities: {} },
        ]),
      ) as jest.Mock;

      const result = await service.analyzeExecution('exec-1', 'user-1');
      expect(result.summary.HIGH).toBe(1);
      expect(result.summary.MEDIUM).toBe(1);
      expect(result.summary.LOW).toBe(0);
      expect(result.summary.avgConfidence).toBe(0.8);
    });

    it('throws when ML service responds with error status', async () => {
      const vuln = {
        id: 'v1', name: 'A', type: 'XSS', cvssScore: 7.0, affectedUrl: 'http://a.com', criticality: 'HIGH',
      };
      mockPrisma.scanExecution.findFirst.mockResolvedValue({
        id: 'exec-1',
        scanConfig: { targetUrl: 'http://example.com', userId: 'user-1' },
        vulnerabilities: [vuln],
      });

      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 422,
        text: jest.fn().mockResolvedValue('Validation error'),
      }) as jest.Mock;

      await expect(service.analyzeExecution('exec-1', 'user-1')).rejects.toThrow('ML service error 422');
    });
  });

  // ─── getModelInfo() ────────────────────────────────────────────────────────

  describe('getModelInfo()', () => {
    it('fetches model info from ML service', async () => {
      const mockInfo = { model: 'RandomForestClassifier', accuracy: 0.98 };
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue(mockInfo),
      }) as jest.Mock;

      const result = await service.getModelInfo();
      expect(result).toEqual(mockInfo);
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/model/info'));
    });

    it('throws when model info endpoint is unreachable', async () => {
      global.fetch = jest.fn().mockResolvedValue({ ok: false }) as jest.Mock;
      await expect(service.getModelInfo()).rejects.toThrow('ML service unreachable');
    });
  });
});
