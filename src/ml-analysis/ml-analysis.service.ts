import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

interface MlPrediction {
  vuln_id: string | null;
  criticality: string;
  confidence: number;
  probabilities: Record<string, number>;
}

interface MlBatchResult {
  count: number;
  predictions: MlPrediction[];
}

@Injectable()
export class MlAnalysisService {
  private readonly mlUrl: string;

  constructor(private readonly prisma: PrismaService) {
    this.mlUrl = process.env.ML_SERVICE_URL ?? 'http://localhost:8000';
  }

  async analyzeExecution(executionId: string, userId: string) {
    const execution = await this.prisma.scanExecution.findFirst({
      where: { id: executionId, scanConfig: { userId } },
      include: { scanConfig: true, vulnerabilities: true },
    });
    if (!execution) throw new NotFoundException(`Execution ${executionId} not found`);

    const payload = {
      vulnerabilities: execution.vulnerabilities.map((v) => ({
        vuln_id: v.id,
        vuln_type: v.type,
        cvss_score: v.cvssScore ?? 5.0,
        url_depth: Math.max(1, this.urlDepth(v.affectedUrl)),
        has_param: v.affectedUrl?.includes('?') ?? false,
        response_time_ms: 200,
        method: 'GET',
      })),
    };

    if (payload.vulnerabilities.length === 0) {
      return {
        executionId,
        targetUrl: execution.scanConfig.targetUrl,
        predictions: [],
        summary: { HIGH: 0, MEDIUM: 0, LOW: 0, avgConfidence: 0 },
      };
    }

    const res = await fetch(`${this.mlUrl}/predict/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`ML service error ${res.status}: ${text}`);
    }

    const data: MlBatchResult = await res.json();

    const countMap = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    let totalConf = 0;
    for (const p of data.predictions) {
      const key = p.criticality as keyof typeof countMap;
      if (key in countMap) countMap[key]++;
      totalConf += p.confidence;
    }

    return {
      executionId,
      targetUrl: execution.scanConfig.targetUrl,
      predictions: data.predictions,
      summary: {
        ...countMap,
        avgConfidence: data.predictions.length > 0
          ? Math.round((totalConf / data.predictions.length) * 100) / 100
          : 0,
      },
    };
  }

  async predictSingle(vuln: {
    vuln_type: string;
    cvss_score: number;
    url_depth: number;
    has_param: boolean;
    response_time_ms: number;
    method: string;
  }) {
    const res = await fetch(`${this.mlUrl}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(vuln),
    });
    if (!res.ok) throw new Error(`ML service error ${res.status}`);
    return res.json();
  }

  async getModelInfo() {
    const res = await fetch(`${this.mlUrl}/model/info`);
    if (!res.ok) throw new Error('ML service unreachable');
    return res.json();
  }

  private urlDepth(url: string): number {
    try {
      const path = new URL(url).pathname;
      return path.split('/').filter(Boolean).length;
    } catch {
      return 1;
    }
  }
}
