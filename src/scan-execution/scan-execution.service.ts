import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ScanConfigService } from '../scan-config/scan-config.service';
import { CreateScanExecutionDto } from './dto/scan-execution.dto';
import { ScanStatus, Criticality, VulnerabilityType } from '../common/enums';

const MOCK_VULNS = [
  {
    name: 'SQL Injection en parámetro de búsqueda',
    description: 'El parámetro "q" no sanitiza la entrada del usuario, permitiendo inyección SQL.',
    type: VulnerabilityType.SQL_INJECTION,
    criticality: Criticality.HIGH,
    cvssScore: 9.1,
    recommendation:
      'Usar consultas parametrizadas o prepared statements. Nunca concatenar inputs del usuario en SQL.',
  },
  {
    name: 'Cross-Site Scripting (XSS) Reflejado',
    description: 'El campo de búsqueda refleja el input del usuario sin codificación HTML adecuada.',
    type: VulnerabilityType.XSS,
    criticality: Criticality.HIGH,
    cvssScore: 7.5,
    recommendation:
      'Implementar Content-Security-Policy y codificar todo output HTML. Usar librerías como DOMPurify.',
  },
  {
    name: 'Header X-Frame-Options ausente',
    description: 'El sitio no envía el header X-Frame-Options, habilitando ataques de Clickjacking.',
    type: VulnerabilityType.SECURITY_MISCONFIG,
    criticality: Criticality.MEDIUM,
    cvssScore: 5.4,
    recommendation: "Agregar header 'X-Frame-Options: DENY' o 'SAMEORIGIN' en las respuestas HTTP.",
  },
  {
    name: 'CSRF Token no implementado',
    description:
      'Los formularios POST no incluyen token CSRF, permitiendo ataques Cross-Site Request Forgery.',
    type: VulnerabilityType.CSRF,
    criticality: Criticality.MEDIUM,
    cvssScore: 6.1,
    recommendation:
      'Implementar tokens CSRF sincronizados en todos los formularios con métodos POST/PUT/DELETE.',
  },
  {
    name: 'Información sensible en headers HTTP',
    description: 'El servidor expone versión de software en headers Server y X-Powered-By.',
    type: VulnerabilityType.DATA_EXPOSURE,
    criticality: Criticality.LOW,
    cvssScore: 3.7,
    recommendation: 'Configurar el servidor para ocultar headers de versión (server_tokens off en nginx).',
  },
  {
    name: 'Strict-Transport-Security (HSTS) ausente',
    description: 'El sitio no implementa HSTS, permitiendo downgrade a HTTP.',
    type: VulnerabilityType.INSECURE_CONFIG,
    criticality: Criticality.MEDIUM,
    cvssScore: 5.9,
    recommendation: "Agregar header 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
  },
  {
    name: 'Content-Security-Policy no configurado',
    description:
      'Ausencia de CSP facilita la ejecución de scripts maliciosos en el contexto del sitio.',
    type: VulnerabilityType.SECURITY_MISCONFIG,
    criticality: Criticality.MEDIUM,
    cvssScore: 5.4,
    recommendation:
      'Definir una política CSP estricta usando directivas default-src, script-src y style-src.',
  },
  {
    name: 'Session sin flag Secure',
    description:
      'Las cookies de sesión no tienen el flag Secure, pudiendo ser transmitidas por HTTP.',
    type: VulnerabilityType.BROKEN_AUTH,
    criticality: Criticality.HIGH,
    cvssScore: 7.3,
    recommendation:
      'Configurar flags Secure, HttpOnly y SameSite=Strict en todas las cookies de sesión.',
  },
];

@Injectable()
export class ScanExecutionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly scanConfigService: ScanConfigService,
  ) {}

  async create(dto: CreateScanExecutionDto) {
    const config = await this.scanConfigService.findOne(dto.scanConfigId);
    const execution = await this.prisma.scanExecution.create({
      data: {
        scanConfigId: dto.scanConfigId,
        status: ScanStatus.PENDING,
        progress: 0,
      },
    });
    this.runScan(execution.id, config.targetUrl).catch(() => null);
    return execution;
  }

  private async runScan(executionId: string, targetUrl: string): Promise<void> {
    await this.prisma.scanExecution.update({
      where: { id: executionId },
      data: { status: ScanStatus.RUNNING, startedAt: new Date(), progress: 10 },
    });

    try {
      const totalSteps = MOCK_VULNS.length;
      const detectedVulns: Array<(typeof MOCK_VULNS)[number] & { affectedUrl: string; scanExecutionId: string }> = [];

      for (let i = 0; i < totalSteps; i++) {
        await this.sleep(1500);
        const progress = Math.round(((i + 1) / totalSteps) * 90) + 5;
        await this.prisma.scanExecution.update({
          where: { id: executionId },
          data: { progress },
        });

        if (Math.random() > 0.25) {
          detectedVulns.push({
            ...MOCK_VULNS[i],
            affectedUrl: `${targetUrl}/${this.randomPath()}`,
            scanExecutionId: executionId,
          });
        }
      }

      await this.prisma.vulnerability.createMany({ data: detectedVulns });

      await this.prisma.scanExecution.update({
        where: { id: executionId },
        data: {
          status: ScanStatus.COMPLETED,
          finishedAt: new Date(),
          progress: 100,
          totalVulnerabilities: detectedVulns.length,
        },
      });
    } catch (err) {
      await this.prisma.scanExecution.update({
        where: { id: executionId },
        data: { status: ScanStatus.FAILED, finishedAt: new Date(), errorMessage: String(err) },
      });
    }
  }

  private sleep(ms: number) {
    return new Promise((r) => setTimeout(r, ms));
  }

  private randomPath(): string {
    const paths = ['login', 'search', 'api/users', 'dashboard', 'reports', 'admin'];
    return paths[Math.floor(Math.random() * paths.length)];
  }

  findAll() {
    return this.prisma.scanExecution.findMany({
      orderBy: { createdAt: 'desc' },
      include: { scanConfig: true },
    });
  }

  async findOne(id: string) {
    const ex = await this.prisma.scanExecution.findUnique({
      where: { id },
      include: { scanConfig: true },
    });
    if (!ex) throw new NotFoundException(`ScanExecution ${id} not found`);
    return ex;
  }
}
