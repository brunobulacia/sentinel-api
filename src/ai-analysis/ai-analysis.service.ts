import { Injectable, NotFoundException } from '@nestjs/common';
import Anthropic from '@anthropic-ai/sdk';
import { PrismaService } from '../prisma/prisma.service';
import { Criticality } from '../common/enums';

const AI_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string' },
    riskLevel: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
    stackAnalysis: { type: 'string' },
    additionalVulnerabilities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          description: { type: 'string' },
          type: { type: 'string' },
          likelihood: { type: 'string', enum: ['HIGH', 'MEDIUM', 'LOW'] },
          reason: { type: 'string' },
          recommendation: { type: 'string' },
        },
        required: ['name', 'description', 'type', 'likelihood', 'reason', 'recommendation'],
        additionalProperties: false,
      },
    },
    remediationPriority: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          order: { type: 'number' },
          action: { type: 'string' },
          impact: { type: 'string' },
          effort: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH'] },
        },
        required: ['order', 'action', 'impact', 'effort'],
        additionalProperties: false,
      },
    },
    attackScenarios: { type: 'array', items: { type: 'string' } },
  },
  required: [
    'summary',
    'riskLevel',
    'stackAnalysis',
    'additionalVulnerabilities',
    'remediationPriority',
    'attackScenarios',
  ],
  additionalProperties: false,
};

@Injectable()
export class AiAnalysisService {
  private readonly client: Anthropic;

  constructor(private readonly prisma: PrismaService) {
    this.client = new Anthropic({
      apiKey: process.env.ANTHROPIC_API_KEY,
    });
  }

  async analyzeExecution(executionId: string, userId: string) {
    const execution = await this.prisma.scanExecution.findFirst({
      where: { id: executionId, scanConfig: { userId } },
      include: { scanConfig: true, vulnerabilities: true },
    });

    if (!execution) throw new NotFoundException(`Execution ${executionId} not found`);

    const high = execution.vulnerabilities.filter((v) => v.criticality === Criticality.HIGH);
    const medium = execution.vulnerabilities.filter((v) => v.criticality === Criticality.MEDIUM);
    const low = execution.vulnerabilities.filter((v) => v.criticality === Criticality.LOW);

    // Send only top 6 most critical vulns (sorted HIGH first) to minimize input tokens
    const topVulns = [...execution.vulnerabilities]
      .sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0))
      .slice(0, 6);

    const vulnList = topVulns
      .map((v) => `[${v.criticality}] ${v.name} (${v.type}, CVSS:${v.cvssScore ?? '?'})`)
      .join('\n');

    const prompt = `Analiza este escaneo de seguridad web. Responde en ESPAÑOL, muy conciso.

URL: ${execution.scanConfig.targetUrl}
Total: ${execution.vulnerabilities.length} vulns (${high.length}H/${medium.length}M/${low.length}L)
Top vulns:
${vulnList || 'Ninguna.'}

JSON requerido (strings cortos, max 2 frases cada uno):
- summary: resumen ejecutivo (max 3 oraciones)
- riskLevel: CRITICAL/HIGH/MEDIUM/LOW
- stackAnalysis: stack detectado y riesgo (max 2 oraciones)
- additionalVulnerabilities: 2 vulns probables no detectadas
- remediationPriority: 4 acciones priorizadas
- attackScenarios: 2 escenarios de ataque (1 frase c/u)`;

    const response = await this.client.messages.create({
      model: 'claude-haiku-4-5',
      max_tokens: 2048,
      output_config: {
        format: {
          type: 'json_schema',
          schema: AI_OUTPUT_SCHEMA,
        },
      },
      messages: [{ role: 'user', content: prompt }],
    });

    const textBlock = response.content.find((b) => b.type === 'text');
    if (!textBlock || textBlock.type !== 'text') {
      throw new Error('No text response from AI');
    }

    return {
      executionId,
      targetUrl: execution.scanConfig.targetUrl,
      scannedAt: execution.createdAt,
      vulnCounts: {
        total: execution.vulnerabilities.length,
        high: high.length,
        medium: medium.length,
        low: low.length,
      },
      analysis: JSON.parse(textBlock.text),
    };
  }
}
