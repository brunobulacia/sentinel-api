import axios, { AxiosInstance, AxiosResponse } from 'axios';
import * as https from 'https';
import { VulnerabilityType, Criticality } from '../common/enums';

const INSECURE_AGENT = new https.Agent({ rejectUnauthorized: false });

export interface ScanResult {
  name: string;
  description: string;
  type: VulnerabilityType;
  criticality: Criticality;
  cvssScore: number;
  affectedUrl: string;
  recommendation: string;
}

// ─── SQL error signatures (error-based SQLi detection) ─────────────────────
const SQL_ERROR_PATTERNS = [
  'sql syntax', 'mysql_fetch', 'ora-0', 'microsoft sql server',
  'syntax error', 'pg_query', 'sqlite_', 'you have an error in your sql',
  'unclosed quotation mark', 'quoted string not properly terminated',
  'invalid query', 'mysql error', 'sql error', 'database error',
  'warning: mysql', 'supplied argument is not a valid mysql',
  'odbc driver', 'jet database engine', 'access database engine',
  'pdoexception', 'sqlexception', 'operationalerror',
];

// ─── Sensitive paths to probe ───────────────────────────────────────────────
const SENSITIVE_PATHS: { path: string; label: string; cvss: number; crit: Criticality }[] = [
  { path: '/.env',               label: 'Archivo .env expuesto',               cvss: 9.0, crit: Criticality.HIGH },
  { path: '/.env.local',         label: 'Archivo .env.local expuesto',          cvss: 8.6, crit: Criticality.HIGH },
  { path: '/.env.production',    label: 'Archivo .env.production expuesto',     cvss: 9.0, crit: Criticality.HIGH },
  { path: '/.git/config',        label: 'Repositorio Git expuesto (config)',     cvss: 8.6, crit: Criticality.HIGH },
  { path: '/.git/HEAD',          label: 'Repositorio Git expuesto (HEAD)',       cvss: 8.6, crit: Criticality.HIGH },
  { path: '/phpinfo.php',        label: 'phpinfo.php accesible',                 cvss: 7.5, crit: Criticality.HIGH },
  { path: '/web.config',         label: 'web.config expuesto',                  cvss: 8.2, crit: Criticality.HIGH },
  { path: '/config.php',         label: 'config.php expuesto',                  cvss: 8.6, crit: Criticality.HIGH },
  { path: '/config.yml',         label: 'config.yml expuesto',                  cvss: 7.5, crit: Criticality.HIGH },
  { path: '/backup.sql',         label: 'Backup SQL expuesto',                  cvss: 9.0, crit: Criticality.HIGH },
  { path: '/database.sql',       label: 'Base de datos SQL expuesta',           cvss: 9.0, crit: Criticality.HIGH },
  { path: '/dump.sql',           label: 'Dump SQL expuesto',                    cvss: 9.0, crit: Criticality.HIGH },
  { path: '/.htaccess',          label: '.htaccess accesible',                  cvss: 6.1, crit: Criticality.MEDIUM },
  { path: '/admin/',             label: 'Panel admin accesible',                cvss: 6.5, crit: Criticality.MEDIUM },
  { path: '/administrator/',     label: 'Panel administrador accesible',        cvss: 6.5, crit: Criticality.MEDIUM },
  { path: '/wp-admin/',          label: 'WordPress admin expuesto',             cvss: 6.5, crit: Criticality.MEDIUM },
  { path: '/wp-login.php',       label: 'WordPress login expuesto',             cvss: 5.4, crit: Criticality.MEDIUM },
  { path: '/api/',               label: 'API root accesible',                   cvss: 5.0, crit: Criticality.MEDIUM },
  { path: '/api/docs',           label: 'API Swagger/OpenAPI expuesto',         cvss: 5.4, crit: Criticality.MEDIUM },
  { path: '/swagger',            label: 'Swagger UI expuesto',                  cvss: 5.4, crit: Criticality.MEDIUM },
  { path: '/swagger-ui.html',    label: 'Swagger UI HTML expuesto',             cvss: 5.4, crit: Criticality.MEDIUM },
  { path: '/actuator',           label: 'Spring Actuator expuesto',             cvss: 8.0, crit: Criticality.HIGH },
  { path: '/actuator/env',       label: 'Spring Actuator /env expuesto',        cvss: 9.0, crit: Criticality.HIGH },
  { path: '/debug',              label: 'Ruta /debug expuesta',                 cvss: 7.0, crit: Criticality.HIGH },
  { path: '/console',            label: 'Consola debug expuesta',               cvss: 8.5, crit: Criticality.HIGH },
  { path: '/composer.json',      label: 'composer.json expuesto',               cvss: 3.7, crit: Criticality.LOW },
  { path: '/package.json',       label: 'package.json expuesto',                cvss: 3.7, crit: Criticality.LOW },
];

// ─── SSRF internal targets ──────────────────────────────────────────────────
const SSRF_TARGETS = [
  { url: 'http://127.0.0.1', label: 'localhost' },
  { url: 'http://localhost', label: 'localhost hostname' },
  { url: 'http://169.254.169.254/latest/meta-data/', label: 'AWS metadata endpoint' },
  { url: 'http://metadata.google.internal/computeMetadata/v1/', label: 'GCP metadata endpoint' },
  { url: 'http://192.168.0.1', label: 'gateway privado 192.168.0.1' },
  { url: 'http://10.0.0.1', label: 'red interna 10.0.0.1' },
];

// ─── Path traversal payloads ────────────────────────────────────────────────
const TRAVERSAL_PAYLOADS = [
  '../../../etc/passwd',
  '..%2F..%2F..%2Fetc%2Fpasswd',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..\\..\\..\\windows\\win.ini',
  '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
];
const TRAVERSAL_SIGNATURES = ['root:x:', '[boot loader]', '[extensions]', 'daemon:', 'nobody:', 'www-data:'];

// ─── SSTI payloads ──────────────────────────────────────────────────────────
const SSTI_PAYLOADS = [
  { probe: '{{7*7}}',      result: '49',   engine: 'Jinja2/Twig' },
  { probe: '${7*7}',       result: '49',   engine: 'FreeMarker/Velocity' },
  { probe: '<%= 7*7 %>',   result: '49',   engine: 'EJS/ERB' },
  { probe: '#{7*7}',       result: '49',   engine: 'Thymeleaf/SpEL' },
  { probe: '*{7*7}',       result: '49',   engine: 'Thymeleaf' },
  { probe: '{{7*\'7\'}}',  result: '7777777', engine: 'Jinja2' },
];

// ─── Command injection payloads (time-based) ────────────────────────────────
const CMD_PAYLOADS = [
  '; sleep 5',
  '| sleep 5',
  '`sleep 5`',
  '$(sleep 5)',
  '& timeout 5',
  '; ping -c 5 127.0.0.1',
];

// ─── XXE payloads ───────────────────────────────────────────────────────────
const XXE_PAYLOAD = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root><data>&xxe;</data></root>`;

const XXE_SIGNATURES = ['root:x:', 'daemon:', 'nobody:', '/bin/bash', '/bin/sh'];

// ─── NoSQL injection payloads ───────────────────────────────────────────────
const NOSQL_PARAMS_PAYLOADS = [
  { param: 'username', value: '{"$gt": ""}' },
  { param: 'email', value: '{"$ne": null}' },
  { param: 'id', value: '{"$gt": "000000000000"}' },
];

// ─── Common API patterns for IDOR ──────────────────────────────────────────
const IDOR_PATHS = [
  '/api/users',
  '/api/user',
  '/api/accounts',
  '/api/profile',
  '/api/orders',
  '/api/admin/users',
  '/users',
  '/user',
  '/account',
  '/profile',
];

// ─── Scanner Engine ─────────────────────────────────────────────────────────

export class ScannerEngine {
  private readonly http: AxiosInstance;
  private readonly baseUrl: string;
  private readonly baseOrigin: string;
  private readonly depth: string;
  private readonly vulnTypes: string[];

  constructor(targetUrl: string, depth: string, vulnTypes: string[] = []) {
    this.baseUrl = targetUrl.replace(/\/$/, '');
    this.baseOrigin = (() => {
      try { return new URL(this.baseUrl).origin; }
      catch { return this.baseUrl; }
    })();
    this.depth = depth;
    this.vulnTypes = vulnTypes;

    this.http = axios.create({
      timeout: 8000,
      maxRedirects: 0,
      validateStatus: () => true,
      httpsAgent: INSECURE_AGENT,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Sentinel-Scanner/3.0; Security Audit)',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'es-BO,es;q=0.9,en;q=0.8',
      },
    });
  }

  // Returns true if check should run (empty vulnTypes = run all)
  private allows(...types: string[]): boolean {
    if (this.vulnTypes.length === 0) return true;
    return types.some(t => this.vulnTypes.includes(t));
  }

  async scan(onProgress: (pct: number) => Promise<void>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Step 1: SSL check
    if (this.baseUrl.startsWith('https://')) {
      try {
        const strictClient = axios.create({
          timeout: 8000,
          maxRedirects: 0,
          validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Sentinel-Scanner/3.0)' },
        });
        await strictClient.get(this.baseUrl);
      } catch (err: unknown) {
        const code = (err as { code?: string })?.code ?? '';
        const msg = (err as Error)?.message ?? '';
        if (
          code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
          code === 'CERT_HAS_EXPIRED' ||
          code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
          code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          msg.includes('certificate') ||
          msg.includes('SSL')
        ) {
          const isSelfSigned = code.includes('SELF_SIGNED') || code.includes('DEPTH_ZERO');
          const isExpired = code === 'CERT_HAS_EXPIRED';
          results.push({
            name: isExpired ? 'Certificado SSL/TLS expirado' : isSelfSigned ? 'Certificado SSL/TLS autofirmado' : 'Certificado SSL/TLS inválido',
            description: isExpired
              ? 'El certificado SSL del sitio ha expirado. Los navegadores mostrarán una advertencia de seguridad.'
              : isSelfSigned
              ? 'El sitio usa un certificado autofirmado no emitido por una CA reconocida. Los navegadores bloquean estas conexiones.'
              : `El certificado SSL no pudo ser verificado (error: ${code}). La identidad del servidor no puede ser confirmada, exponiendo a los usuarios a ataques MITM.`,
            type: VulnerabilityType.INSECURE_CONFIG,
            criticality: Criticality.HIGH,
            cvssScore: 7.4,
            affectedUrl: this.baseUrl,
            recommendation: "Obtener un certificado SSL válido de una CA reconocida (Let's Encrypt es gratuito). Renovar antes del vencimiento.",
          });
        }
      }
    }

    // Step 2: fetch main page
    let mainRes: AxiosResponse | null = null;
    try { mainRes = await this.http.get(this.baseUrl); } catch { /* unreachable */ }

    // Step 3: spider — discover endpoints, forms, params from main page
    const discovered = mainRes ? this.spider(String(mainRes.data ?? '')) : { links: [], formParams: [], queryParams: new Set<string>() };

    // Step 4: build and run checks
    const checks = this.buildCheckList(discovered);
    const total = checks.length;

    for (let i = 0; i < total; i++) {
      try {
        const found = await checks[i](mainRes);
        results.push(...found);
      } catch { /* individual check failure never aborts */ }
      await onProgress(Math.round(((i + 1) / total) * 88) + 5);
    }

    return results;
  }

  // ─── Spider ───────────────────────────────────────────────────────────────

  private spider(html: string): { links: string[]; formParams: string[]; queryParams: Set<string> } {
    const links: string[] = [];
    const queryParams = new Set<string>();
    const formParams: string[] = [];

    // Extract href links within same origin
    const hrefRe = /href=["']([^"'#]*?)["']/gi;
    let m: RegExpExecArray | null;
    while ((m = hrefRe.exec(html)) !== null) {
      const href = m[1];
      try {
        const url = href.startsWith('http') ? href : `${this.baseOrigin}${href.startsWith('/') ? '' : '/'}${href}`;
        if (url.startsWith(this.baseOrigin)) {
          links.push(url);
          // Extract query param names
          const parsed = new URL(url);
          parsed.searchParams.forEach((_, k) => queryParams.add(k));
        }
      } catch { /* invalid URL */ }
    }

    // Extract form input names
    const inputRe = /<input[^>]*name=["']([^"']+)["'][^>]*>/gi;
    while ((m = inputRe.exec(html)) !== null) {
      formParams.push(m[1]);
    }

    // Extract action params from common JS fetch/axios patterns
    const apiRe = /["'`](\/api\/[^"'`?]+)/g;
    while ((m = apiRe.exec(html)) !== null) {
      const apiPath = m[1];
      try {
        links.push(`${this.baseOrigin}${apiPath}`);
      } catch { /* ignore */ }
    }

    return { links: [...new Set(links)].slice(0, 30), formParams, queryParams };
  }

  // ─── Check registry ────────────────────────────────────────────────────────

  private buildCheckList(
    discovered: { links: string[]; formParams: string[]; queryParams: Set<string> }
  ): ((r: AxiosResponse | null) => Promise<ScanResult[]>)[] {
    const allParams = [
      ...discovered.queryParams,
      ...discovered.formParams,
      'id', 'q', 'search', 'redirect', 'url', 'next', 'page', 'file', 'path', 'name', 'data',
    ];
    const uniqueParams = [...new Set(allParams)];

    const base: ((r: AxiosResponse | null) => Promise<ScanResult[]>)[] = [];

    if (this.allows('INSECURE_CONFIG', 'SECURITY_MISCONFIG'))
      base.push(r => this.checkHttpsAndHsts(r));

    if (this.allows('SECURITY_MISCONFIG', 'INSECURE_CONFIG', 'DATA_EXPOSURE'))
      base.push(r => this.checkSecurityHeaders(r));

    if (this.allows('DATA_EXPOSURE'))
      base.push(r => this.checkInformationDisclosure(r));

    if (this.allows('BROKEN_AUTH', 'CSRF'))
      base.push(r => this.checkCookieSecurity(r));

    if (this.allows('BROKEN_AUTH', 'SECURITY_MISCONFIG'))
      base.push(() => this.checkCorsConfig());

    if (this.allows('SECURITY_MISCONFIG'))
      base.push(() => this.checkHttpMethods());

    const medium: ((r: AxiosResponse | null) => Promise<ScanResult[]>)[] = [];

    if (this.allows('DATA_EXPOSURE', 'INSECURE_CONFIG'))
      medium.push(() => this.checkSensitivePaths());

    if (this.allows('DATA_EXPOSURE'))
      medium.push(() => this.checkRobotsTxt());

    if (this.allows('DATA_EXPOSURE'))
      medium.push(r => this.checkDirectoryListing(r));

    if (this.allows('CSRF'))
      medium.push(r => this.checkCsrfActive(r));

    if (this.allows('BROKEN_AUTH'))
      medium.push(() => this.checkIdor(discovered.links));

    const deep: ((r: AxiosResponse | null) => Promise<ScanResult[]>)[] = [];

    if (this.allows('SQL_INJECTION'))
      deep.push(() => this.checkSqlInjection(uniqueParams));

    if (this.allows('SQL_INJECTION'))
      deep.push(() => this.checkNoSqlInjection(uniqueParams));

    if (this.allows('XSS'))
      deep.push(() => this.checkXssReflection(uniqueParams));

    if (this.allows('SSRF'))
      deep.push(() => this.checkSsrf(uniqueParams));

    if (this.allows('SECURITY_MISCONFIG', 'OTHER'))
      deep.push(() => this.checkCommandInjection(uniqueParams));

    if (this.allows('DATA_EXPOSURE', 'OTHER'))
      deep.push(() => this.checkPathTraversal(uniqueParams));

    if (this.allows('SECURITY_MISCONFIG', 'XSS'))
      deep.push(() => this.checkSsti(uniqueParams));

    if (this.allows('DATA_EXPOSURE', 'OTHER'))
      deep.push(() => this.checkXxe());

    if (this.allows('SECURITY_MISCONFIG', 'INSECURE_CONFIG'))
      deep.push(r => this.checkOpenRedirect(uniqueParams));

    if (this.depth === 'low') return base;
    if (this.depth === 'medium') return [...base, ...medium];
    return [...base, ...medium, ...deep];
  }

  // ─── 1. HTTPS & HSTS ───────────────────────────────────────────────────────

  private async checkHttpsAndHsts(res: AxiosResponse | null): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const isHttps = this.baseUrl.startsWith('https://');

    if (!isHttps) {
      results.push({
        name: 'Sitio no usa HTTPS — Transmisión en texto plano',
        description: 'El sitio opera sobre HTTP sin cifrado TLS/SSL. Cualquier dato transmitido (credenciales, tokens, información personal) puede ser interceptado por ataques Man-in-the-Middle (MITM).',
        type: VulnerabilityType.INSECURE_CONFIG,
        criticality: Criticality.HIGH,
        cvssScore: 7.5,
        affectedUrl: this.baseUrl,
        recommendation: "Implementar TLS 1.2 o superior. Redirigir todo tráfico HTTP→HTTPS con código 301 permanente.",
      });
      return results;
    }

    try {
      const httpUrl = this.baseUrl.replace('https://', 'http://');
      const httpRes = await this.http.get(httpUrl, { timeout: 5000 });
      const loc = httpRes.headers['location'] ?? '';
      if (!(httpRes.status >= 300 && httpRes.status < 400 && loc.startsWith('https://'))) {
        results.push({
          name: 'HTTP no redirige a HTTPS',
          description: 'El servidor responde a peticiones HTTP sin redirigir a HTTPS, permitiendo conexiones no cifradas aunque el sitio tenga SSL configurado.',
          type: VulnerabilityType.INSECURE_CONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.9,
          affectedUrl: httpUrl,
          recommendation: 'Configurar redirección 301 permanente a HTTPS.',
        });
      }
    } catch { /* HTTP port may be blocked */ }

    if (res) {
      const hsts = res.headers['strict-transport-security'];
      if (!hsts) {
        results.push({
          name: 'HSTS (HTTP Strict-Transport-Security) ausente',
          description: 'Sin HSTS, los usuarios son vulnerables a ataques de downgrade SSL (SSLstrip). El navegador no fuerza HTTPS automáticamente.',
          type: VulnerabilityType.INSECURE_CONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.9,
          affectedUrl: this.baseUrl,
          recommendation: 'Agregar header: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`',
        });
      } else {
        const match = hsts.match(/max-age=(\d+)/i);
        if (match && parseInt(match[1]) < 2592000) {
          results.push({
            name: `HSTS max-age insuficiente: ${match[1]}s (< 30 días)`,
            description: `max-age=${match[1]}s es insuficiente. OWASP recomienda mínimo 63072000s (2 años).`,
            type: VulnerabilityType.INSECURE_CONFIG,
            criticality: Criticality.LOW,
            cvssScore: 3.1,
            affectedUrl: this.baseUrl,
            recommendation: 'Incrementar: `Strict-Transport-Security: max-age=63072000; includeSubDomains`',
          });
        }
      }
    }

    return results;
  }

  // ─── 2. Security Headers ──────────────────────────────────────────────────

  private async checkSecurityHeaders(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const h = res.headers;
    const results: ScanResult[] = [];
    const csp = String(h['content-security-policy'] ?? '');

    if (!h['x-frame-options'] && !csp.toLowerCase().includes('frame-ancestors')) {
      results.push({
        name: 'X-Frame-Options ausente — Riesgo de Clickjacking',
        description: 'Sin X-Frame-Options ni CSP frame-ancestors, el sitio puede ser incrustado en un iframe malicioso.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation: "Agregar `X-Frame-Options: DENY` o `Content-Security-Policy: frame-ancestors 'none'`",
      });
    }

    if (h['x-content-type-options'] !== 'nosniff') {
      results.push({
        name: 'X-Content-Type-Options: nosniff ausente',
        description: 'Sin este header el navegador puede hacer MIME sniffing y ejecutar archivos con tipo MIME incorrecto.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.LOW,
        cvssScore: 3.7,
        affectedUrl: this.baseUrl,
        recommendation: 'Agregar: `X-Content-Type-Options: nosniff`',
      });
    }

    if (!h['content-security-policy']) {
      results.push({
        name: 'Content-Security-Policy (CSP) no configurado',
        description: 'Sin CSP el navegador ejecutará cualquier script incluyendo los inyectados por XSS.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.MEDIUM,
        cvssScore: 6.1,
        affectedUrl: this.baseUrl,
        recommendation: "Implementar CSP: `default-src 'self'; script-src 'self'; frame-ancestors 'none'`",
      });
    } else {
      if (csp.includes("'unsafe-eval'")) {
        results.push({
          name: "CSP contiene 'unsafe-eval' — Debilita protección XSS",
          description: "'unsafe-eval' permite eval(), Function(), setTimeout(string). Anula protección XSS del CSP.",
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.4,
          affectedUrl: this.baseUrl,
          recommendation: "Eliminar 'unsafe-eval'. Refactorizar código para no usar eval().",
        });
      }
      if (csp.includes("'unsafe-inline'") && csp.includes('script-src')) {
        results.push({
          name: "CSP script-src contiene 'unsafe-inline'",
          description: "'unsafe-inline' permite scripts inline, neutralizando la protección XSS del CSP.",
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.LOW,
          cvssScore: 4.3,
          affectedUrl: this.baseUrl,
          recommendation: "Reemplazar 'unsafe-inline' con nonces criptográficos: `script-src 'self' 'nonce-{random}'`",
        });
      }
    }

    if (!h['referrer-policy']) {
      results.push({
        name: 'Referrer-Policy no configurado',
        description: 'Sin Referrer-Policy el navegador envía la URL completa como Referer, exponiendo rutas internas y tokens.',
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.1,
        affectedUrl: this.baseUrl,
        recommendation: 'Agregar: `Referrer-Policy: strict-origin-when-cross-origin`',
      });
    }

    if (!h['permissions-policy'] && !h['feature-policy']) {
      results.push({
        name: 'Permissions-Policy no configurado',
        description: 'Sin Permissions-Policy los scripts tienen acceso irrestricto a cámara, micrófono, geolocalización.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.LOW,
        cvssScore: 2.1,
        affectedUrl: this.baseUrl,
        recommendation: 'Agregar: `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`',
      });
    }

    if (h['access-control-allow-origin'] === '*') {
      results.push({
        name: 'CORS configurado con wildcard Access-Control-Allow-Origin: *',
        description: 'Cualquier sitio web puede hacer solicitudes CORS y leer las respuestas.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation: 'Restringir a dominios específicos: `Access-Control-Allow-Origin: https://app.tudominio.com`',
      });
    }

    return results;
  }

  // ─── 3. Information Disclosure ────────────────────────────────────────────

  private async checkInformationDisclosure(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const h = res.headers;
    const results: ScanResult[] = [];

    const server = String(h['server'] ?? '');
    if (server && /\d/.test(server)) {
      results.push({
        name: `Header Server expone versión: "${server}"`,
        description: `El header Server revela software y versión: "${server}". Permite buscar CVEs específicos.`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.7,
        affectedUrl: this.baseUrl,
        recommendation: 'Ocultar versión. Nginx: `server_tokens off`. Apache: `ServerTokens Prod`.',
      });
    }

    const xpb = h['x-powered-by'];
    if (xpb) {
      results.push({
        name: `Header X-Powered-By expone tecnología: "${xpb}"`,
        description: `Revela el framework/lenguaje: "${xpb}".`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.7,
        affectedUrl: this.baseUrl,
        recommendation: 'Express.js: `app.disable("x-powered-by")`. PHP: `expose_php = Off`.',
      });
    }

    const aspnetVer = h['x-aspnet-version'];
    if (aspnetVer) {
      results.push({
        name: `X-AspNet-Version expone .NET: "${aspnetVer}"`,
        description: `Revela versión exacta de ASP.NET: "${aspnetVer}". CVEs conocidos públicamente.`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation: 'Deshabilitar en web.config: `<httpRuntime enableVersionHeader="false" />`',
      });
    }

    const body = String(res.data ?? '');
    if (body.includes('wp-content') || body.includes('wp-includes')) {
      const wpVerMatch = body.match(/WordPress (\d+\.\d+[\.\d]*)/i);
      results.push({
        name: `CMS WordPress detectado${wpVerMatch ? ` v${wpVerMatch[1]}` : ''}`,
        description: `El sitio usa WordPress${wpVerMatch ? ` v${wpVerMatch[1]}` : ''}. Objetivo frecuente por plugins desactualizados.`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.1,
        affectedUrl: this.baseUrl,
        recommendation: 'Ocultar versión WordPress. Mantener plugins actualizados. Usar Wordfence.',
      });
    }

    // Stack trace in error responses
    if (res.status >= 400) {
      const lowerBody = body.toLowerCase();
      if (lowerBody.includes('stack trace') || lowerBody.includes('exception in') || lowerBody.includes('at line') || lowerBody.includes('traceback')) {
        results.push({
          name: 'Stack trace expuesto en respuesta HTTP de error',
          description: 'Las páginas de error revelan stack traces con rutas de archivos, versiones y estructura interna.',
          type: VulnerabilityType.DATA_EXPOSURE,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.4,
          affectedUrl: this.baseUrl,
          recommendation: 'Páginas de error genéricas en producción. Deshabilitar modo debug.',
        });
      }
    }

    return results;
  }

  // ─── 4. Cookie Security ───────────────────────────────────────────────────

  private async checkCookieSecurity(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const results: ScanResult[] = [];
    const rawCookies = res.headers['set-cookie'];
    if (!rawCookies) return [];

    const cookies = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
    const processed = new Set<string>();

    for (const cookie of cookies) {
      const lower = cookie.toLowerCase();
      const cookieName = cookie.split('=')[0].trim();
      const reportKey = cookieName;

      if (!processed.has(`httponly-${reportKey}`) && !lower.includes('httponly')) {
        processed.add(`httponly-${reportKey}`);
        results.push({
          name: `Cookie sin HttpOnly: "${cookieName}"`,
          description: `La cookie "${cookieName}" es accesible via JavaScript. En caso de XSS, un atacante puede robar tokens de sesión.`,
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: Criticality.MEDIUM,
          cvssScore: 6.1,
          affectedUrl: this.baseUrl,
          recommendation: `Agregar flag HttpOnly: Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict`,
        });
      }

      if (!processed.has(`secure-${reportKey}`) && !lower.includes('secure')) {
        processed.add(`secure-${reportKey}`);
        results.push({
          name: `Cookie sin flag Secure: "${cookieName}"`,
          description: `La cookie "${cookieName}" puede transmitirse por HTTP no cifrado.`,
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.9,
          affectedUrl: this.baseUrl,
          recommendation: `Agregar flag Secure: Set-Cookie: ${cookieName}=...; Secure; HttpOnly; SameSite=Strict`,
        });
      }

      if (!processed.has(`samesite-${reportKey}`)) {
        if (!lower.includes('samesite')) {
          processed.add(`samesite-${reportKey}`);
          results.push({
            name: `Cookie sin SameSite: "${cookieName}" — Riesgo CSRF`,
            description: `La cookie "${cookieName}" se envía en solicitudes cross-site, vulnerable a CSRF.`,
            type: VulnerabilityType.CSRF,
            criticality: Criticality.MEDIUM,
            cvssScore: 5.4,
            affectedUrl: this.baseUrl,
            recommendation: `Agregar: Set-Cookie: ${cookieName}=...; SameSite=Strict; Secure; HttpOnly`,
          });
        } else if (lower.includes('samesite=none') && !lower.includes('secure')) {
          processed.add(`samesite-${reportKey}`);
          results.push({
            name: `Cookie SameSite=None sin Secure: "${cookieName}"`,
            description: 'SameSite=None requiere Secure obligatoriamente. Sin Secure la cookie viaja en texto plano.',
            type: VulnerabilityType.BROKEN_AUTH,
            criticality: Criticality.HIGH,
            cvssScore: 7.1,
            affectedUrl: this.baseUrl,
            recommendation: `Combinar: Set-Cookie: ${cookieName}=...; SameSite=None; Secure; HttpOnly`,
          });
        }
      }
    }

    return results;
  }

  // ─── 5. CORS Misconfiguration ─────────────────────────────────────────────

  private async checkCorsConfig(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
      const res = await this.http.get(this.baseUrl, {
        headers: { Origin: 'https://evil-sentinel-test.com' },
        timeout: 6000,
      });
      const allowOrigin = res.headers['access-control-allow-origin'];
      const allowCredentials = res.headers['access-control-allow-credentials'];

      if (allowOrigin === 'https://evil-sentinel-test.com') {
        const withCreds = allowCredentials === 'true';
        results.push({
          name: `CORS refleja origen arbitrario${withCreds ? ' + credenciales (Crítico)' : ''}`,
          description: withCreds
            ? 'El servidor refleja cualquier Origin Y permite credenciales. Un atacante puede leer respuestas autenticadas desde cualquier dominio.'
            : 'El servidor refleja el header Origin sin validación. Expone datos del API a cualquier dominio.',
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: withCreds ? Criticality.HIGH : Criticality.MEDIUM,
          cvssScore: withCreds ? 9.0 : 7.4,
          affectedUrl: this.baseUrl,
          recommendation: 'Whitelist de orígenes explícita. Nunca reflejar request.headers.origin directamente.',
        });
      }

      if (allowCredentials === 'true' && allowOrigin === '*') {
        results.push({
          name: 'CORS: Allow-Credentials: true + wildcard origin',
          description: 'Combinación prohibida por el estándar CORS. Indica mala configuración grave.',
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: Criticality.MEDIUM,
          cvssScore: 6.5,
          affectedUrl: this.baseUrl,
          recommendation: 'Nunca combinar credentials:true con origin:*. Especificar el origen exacto.',
        });
      }
    } catch { /* network error */ }
    return results;
  }

  // ─── 6. HTTP Methods ──────────────────────────────────────────────────────

  private async checkHttpMethods(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      const res = await this.http.request({ method: 'TRACE', url: this.baseUrl, timeout: 5000 });
      if (res.status === 200) {
        results.push({
          name: 'Método HTTP TRACE habilitado — Cross-Site Tracing (XST)',
          description: 'TRACE devuelve la solicitud completa incluyendo headers de autenticación. Permite XST (XSS + TRACE para leer cookies HttpOnly).',
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.8,
          affectedUrl: this.baseUrl,
          recommendation: 'Deshabilitar TRACE. Nginx: `if ($request_method = TRACE) { return 405; }`. Apache: `TraceEnable Off`.',
        });
      }
    } catch { /* method not supported */ }

    try {
      const res = await this.http.request({ method: 'OPTIONS', url: this.baseUrl, timeout: 5000 });
      const allowed = (res.headers['allow'] ?? res.headers['access-control-allow-methods'] ?? '').toUpperCase();
      if (allowed && (allowed.includes('PUT') || allowed.includes('DELETE') || allowed.includes('PATCH'))) {
        results.push({
          name: `Métodos HTTP riesgosos expuestos: ${allowed}`,
          description: `El servidor declara soporte para ${allowed}. PUT permite subir archivos, DELETE eliminarlos en servidores mal configurados.`,
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.4,
          affectedUrl: this.baseUrl,
          recommendation: 'Restringir métodos a los necesarios por endpoint. Asegurar autenticación en PUT/DELETE.',
        });
      }
    } catch { /* OPTIONS blocked */ }

    return results;
  }

  // ─── 7. Sensitive Path Probing ────────────────────────────────────────────

  private async checkSensitivePaths(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const BATCH = 5;

    for (let i = 0; i < SENSITIVE_PATHS.length; i += BATCH) {
      const batch = SENSITIVE_PATHS.slice(i, i + BATCH);
      const settled = await Promise.allSettled(
        batch.map(async (item) => {
          const url = `${this.baseUrl}${item.path}`;
          const res = await this.http.get(url, { timeout: 5000 });
          const body = String(res.data ?? '');
          if (res.status !== 200 || body.length < 20) return null;
          return {
            name: item.label,
            description: `La ruta ${item.path} devuelve HTTP ${res.status} con ${body.length} bytes. Accesible públicamente.`,
            type: VulnerabilityType.DATA_EXPOSURE,
            criticality: item.crit,
            cvssScore: item.cvss,
            affectedUrl: url,
            recommendation: `Bloquear acceso a ${item.path}. Mover archivo fuera del webroot o denegar con reglas del servidor.`,
          } as ScanResult;
        }),
      );
      for (const r of settled) {
        if (r.status === 'fulfilled' && r.value) results.push(r.value);
      }
    }

    return results;
  }

  // ─── 8. robots.txt ───────────────────────────────────────────────────────

  private async checkRobotsTxt(): Promise<ScanResult[]> {
    try {
      const url = `${this.baseUrl}/robots.txt`;
      const res = await this.http.get(url, { timeout: 5000 });
      if (res.status !== 200) return [];
      const text = String(res.data ?? '');
      const disallows = (text.match(/^Disallow:\s*(.+)/gim) ?? [])
        .map(l => l.replace(/^Disallow:\s*/i, '').trim())
        .filter(p => p.length > 1 && p !== '/');
      if (disallows.length > 0) {
        return [{
          name: `robots.txt expone ${disallows.length} ruta(s) restringida(s)`,
          description: `robots.txt lista rutas como mapa para atacantes: ${disallows.slice(0, 6).join(', ')}`,
          type: VulnerabilityType.DATA_EXPOSURE,
          criticality: Criticality.LOW,
          cvssScore: 3.1,
          affectedUrl: url,
          recommendation: 'No usar robots.txt para "ocultar" rutas. La protección real viene de auth/authz.',
        }];
      }
    } catch { /* not found */ }
    return [];
  }

  // ─── 9. Directory Listing ─────────────────────────────────────────────────

  private async checkDirectoryListing(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const body = String(res.data ?? '').toLowerCase();
    if (body.includes('index of /') || body.includes('directory listing for') || (body.includes('<title>') && /index of/i.test(body))) {
      return [{
        name: 'Directory Listing habilitado en webroot',
        description: 'El servidor muestra listado completo de archivos. Atacante puede descubrir backups, configs y código fuente.',
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation: 'Deshabilitar Directory Listing. Apache: `Options -Indexes`. Nginx: eliminar `autoindex on`.',
      }];
    }
    return [];
  }

  // ─── 10. CSRF — Active Form Check ─────────────────────────────────────────

  private async checkCsrfActive(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const results: ScanResult[] = [];
    const html = String(res.data ?? '');

    // Detect forms with POST method
    const formMatches = html.matchAll(/<form[^>]*method=["']post["'][^>]*>/gi);
    let formCount = 0;
    for (const _ of formMatches) formCount++;

    if (formCount > 0) {
      // Check if any CSRF token input exists
      const hasCsrfToken =
        /name=["'](_token|csrf|csrf_token|_csrf|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["']/i.test(html);

      if (!hasCsrfToken) {
        // Try submitting a POST to a form action without any CSRF token
        const formActionMatch = html.match(/<form[^>]*method=["']post["'][^>]*action=["']([^"']+)["'][^>]*>/i);
        const actionUrl = formActionMatch
          ? (formActionMatch[1].startsWith('http') ? formActionMatch[1] : `${this.baseOrigin}${formActionMatch[1]}`)
          : this.baseUrl;

        try {
          const csrfRes = await this.http.post(actionUrl, {}, {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              Origin: 'https://evil-sentinel-csrf-test.com',
              Referer: 'https://evil-sentinel-csrf-test.com',
            },
            timeout: 5000,
          });

          // If server accepted (2xx or 3xx redirect) a cross-origin POST without CSRF token
          if (csrfRes.status < 400) {
            results.push({
              name: `CSRF: Formulario POST sin protección CSRF detectado (${formCount} form(s))`,
              description: `El sitio tiene ${formCount} formulario(s) POST sin token CSRF. Una solicitud POST desde origen externo (evil-sentinel-csrf-test.com) fue aceptada con status ${csrfRes.status}. Un atacante puede hacer que un usuario autenticado ejecute acciones no deseadas.`,
              type: VulnerabilityType.CSRF,
              criticality: Criticality.HIGH,
              cvssScore: 8.0,
              affectedUrl: actionUrl,
              recommendation: 'Implementar tokens CSRF síncronos en todos los formularios. Para APIs REST: validar el header Origin/Referer y usar SameSite=Strict en cookies de sesión.',
            });
          }
        } catch { /* form submission failed */ }
      }
    }

    // Check JSON APIs for CSRF (no SameSite + no Origin validation)
    try {
      const apiRes = await this.http.post(`${this.baseUrl}/api/test-csrf-probe-sentinel`, {}, {
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://evil-sentinel-csrf-test.com',
        },
        timeout: 4000,
      });
      // 404 is fine (endpoint doesn't exist), 403 is fine (CSRF protected), 405 is fine
      // If we get 200/201/400(validation) without explicit CSRF denial, flag it
      if (apiRes.status === 200 || apiRes.status === 201) {
        results.push({
          name: 'API REST: Solicitud cross-origin POST aceptada sin validación CSRF',
          description: 'El API aceptó una solicitud POST desde un Origin externo sin rechazarla. Si las cookies de sesión no tienen SameSite=Strict, el API es vulnerable a CSRF.',
          type: VulnerabilityType.CSRF,
          criticality: Criticality.MEDIUM,
          cvssScore: 6.5,
          affectedUrl: `${this.baseUrl}/api`,
          recommendation: 'Validar el header Origin en endpoints que modifican estado. Combinar con SameSite=Strict en cookies.',
        });
      }
    } catch { /* ignore */ }

    return results;
  }

  // ─── 11. IDOR — Insecure Direct Object Reference ─────────────────────────

  private async checkIdor(discoveredLinks: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Combine IDOR paths with discovered links that match common patterns
    const apiPaths = [
      ...IDOR_PATHS,
      ...discoveredLinks
        .filter(l => /\/api\//i.test(l))
        .map(l => { try { return new URL(l).pathname; } catch { return ''; } })
        .filter(Boolean),
    ];

    const tested = new Set<string>();

    for (const basePath of apiPaths.slice(0, 12)) {
      if (tested.has(basePath)) continue;
      tested.add(basePath);

      // Try accessing resource without auth (should get 401/403 if protected)
      try {
        const url = `${this.baseOrigin}${basePath}`;
        const resNoAuth = await this.http.get(url, { timeout: 5000 });

        if (resNoAuth.status === 200) {
          const body = String(resNoAuth.data ?? '');
          // Check if the response looks like user data (arrays of objects, emails, names)
          const looksLikeUserData = /["'](email|username|password|name|phone|address|role)["']/i.test(body);

          if (looksLikeUserData || (typeof resNoAuth.data === 'object' && Array.isArray(resNoAuth.data) && (resNoAuth.data as unknown[]).length > 0)) {
            results.push({
              name: `IDOR / Control de Acceso Roto: ${basePath} accesible sin autenticación`,
              description: `El endpoint ${basePath} devuelve datos (${body.length} bytes) sin requerir autenticación. Se detectaron posibles campos sensibles en la respuesta.`,
              type: VulnerabilityType.BROKEN_AUTH,
              criticality: Criticality.HIGH,
              cvssScore: 8.1,
              affectedUrl: url,
              recommendation: 'Implementar autenticación JWT/session en TODOS los endpoints de API. Verificar que cada recurso solo sea accesible por su dueño (row-level security). Nunca confiar en el ID del cliente.',
            });
          }
        }
      } catch { /* ignore */ }

      // Try numeric ID enumeration
      for (const id of ['1', '2', '3', '100']) {
        try {
          const url = `${this.baseOrigin}${basePath}/${id}`;
          const resId = await this.http.get(url, { timeout: 4000 });
          if (resId.status === 200) {
            const body = String(resId.data ?? '');
            const looksLikeObject = typeof resId.data === 'object' && resId.data !== null && !Array.isArray(resId.data);
            const hasId = /["'](id|userId|user_id)["']/i.test(body);
            if (looksLikeObject || hasId) {
              results.push({
                name: `IDOR: Acceso a objeto por ID secuencial sin auth: ${basePath}/${id}`,
                description: `El endpoint ${basePath}/${id} devuelve un objeto con datos sin requerir autenticación. Un atacante puede enumerar IDs (1, 2, 3...) para acceder a registros de otros usuarios.`,
                type: VulnerabilityType.BROKEN_AUTH,
                criticality: Criticality.HIGH,
                cvssScore: 8.5,
                affectedUrl: url,
                recommendation: 'Requerir autenticación. Verificar que el recurso pertenece al usuario autenticado antes de devolverlo. Preferir UUIDs sobre IDs secuenciales.',
              });
              break;
            }
          }
        } catch { /* ignore */ }
      }
    }

    return results;
  }

  // ─── 12. SQL Injection ────────────────────────────────────────────────────

  private async checkSqlInjection(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const testParams = params.slice(0, 8);

    for (const param of testParams) {
      try {
        const errorUrl = `${this.baseUrl}?${param}=${encodeURIComponent("1'")}`;
        const res = await this.http.get(errorUrl, { timeout: 7000 });
        const body = String(res.data ?? '').toLowerCase();
        const hasSqlError = SQL_ERROR_PATTERNS.some(p => body.includes(p));

        if (hasSqlError) {
          results.push({
            name: `SQL Injection Error-Based — parámetro "${param}"`,
            description: `El parámetro "${param}" devuelve un error SQL explícito al inyectar una comilla simple. Confirma SQLi error-based: posible extracción directa de datos.`,
            type: VulnerabilityType.SQL_INJECTION,
            criticality: Criticality.HIGH,
            cvssScore: 9.1,
            affectedUrl: errorUrl,
            recommendation: 'URGENTE: Usar prepared statements en TODAS las queries. Nunca concatenar input en SQL. Revocar privilegios innecesarios de la BD.',
          });
          return results;
        }

        // Boolean-based: compare normal vs injected response
        const normalRes = await this.http.get(`${this.baseUrl}?${param}=1`, { timeout: 5000 });
        const trueRes = await this.http.get(`${this.baseUrl}?${param}=${encodeURIComponent("1 OR 1=1--")}`, { timeout: 5000 });
        const falseRes = await this.http.get(`${this.baseUrl}?${param}=${encodeURIComponent("1 AND 1=2--")}`, { timeout: 5000 });

        const normalLen = String(normalRes.data ?? '').length;
        const trueLen = String(trueRes.data ?? '').length;
        const falseLen = String(falseRes.data ?? '').length;

        if (Math.abs(trueLen - falseLen) > 300 && trueLen !== normalLen) {
          results.push({
            name: `SQL Injection Boolean-Based — parámetro "${param}"`,
            description: `El parámetro "${param}" produce respuestas significativamente diferentes con condiciones TRUE (${trueLen} bytes) vs FALSE (${falseLen} bytes). Indica SQLi boolean-based.`,
            type: VulnerabilityType.SQL_INJECTION,
            criticality: Criticality.HIGH,
            cvssScore: 8.1,
            affectedUrl: `${this.baseUrl}?${param}=...`,
            recommendation: 'Usar prepared statements y ORM parametrizado. Validar y sanitizar todas las entradas.',
          });
          return results;
        }

        // Time-based: check for delays
        const startTime = Date.now();
        await this.http.get(`${this.baseUrl}?${param}=${encodeURIComponent("1; WAITFOR DELAY '0:0:5'--")}`, { timeout: 10000 });
        const elapsed = Date.now() - startTime;
        if (elapsed > 4500) {
          results.push({
            name: `SQL Injection Time-Based — parámetro "${param}" (MSSQL)`,
            description: `El parámetro "${param}" causó un delay de ${elapsed}ms al inyectar WAITFOR DELAY. Confirma SQLi time-based en Microsoft SQL Server.`,
            type: VulnerabilityType.SQL_INJECTION,
            criticality: Criticality.HIGH,
            cvssScore: 9.0,
            affectedUrl: `${this.baseUrl}?${param}=...`,
            recommendation: 'Usar prepared statements. Nunca concatenar input en SQL.',
          });
          return results;
        }
      } catch { /* ignore timeout/network errors */ }
    }

    return results;
  }

  // ─── 13. NoSQL Injection ──────────────────────────────────────────────────

  private async checkNoSqlInjection(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Query param style: ?username[$gt]=
    for (const param of params.slice(0, 5)) {
      try {
        const url = `${this.baseUrl}?${param}[$gt]=&${param}[$ne]=null`;
        const res = await this.http.get(url, { timeout: 6000 });
        const normalRes = await this.http.get(`${this.baseUrl}?${param}=sentinel_nosqli_probe`, { timeout: 5000 });

        if (res.status === 200 && normalRes.status !== 200) {
          results.push({
            name: `NoSQL Injection — parámetro "${param}" acepta operadores MongoDB`,
            description: `El parámetro "${param}" acepta operadores NoSQL ($gt, $ne) sin sanitización. Con ?${param}[$gt]= se obtiene HTTP 200 mientras que valores normales retornan ${normalRes.status}. Permite bypass de autenticación y lectura de datos arbitrarios.`,
            type: VulnerabilityType.SQL_INJECTION,
            criticality: Criticality.HIGH,
            cvssScore: 8.8,
            affectedUrl: url,
            recommendation: 'Validar que los parámetros sean strings/números simples. Rechazar objetos JSON en query params. Usar ODM con validación de esquema (Mongoose schema validation).',
          });
          return results;
        }
      } catch { /* ignore */ }
    }

    // JSON body NoSQL injection
    for (const payload of NOSQL_PARAMS_PAYLOADS) {
      try {
        const res = await this.http.post(`${this.baseUrl}/api/login`, payload, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 6000,
        });
        if (res.status === 200 && String(res.data ?? '').toLowerCase().includes('token')) {
          results.push({
            name: `NoSQL Injection — Bypass de autenticación via operador MongoDB`,
            description: `El endpoint /api/login aceptó un operador MongoDB (${JSON.stringify(payload)}) como credencial y retornó un token. Un atacante puede autenticarse sin conocer la contraseña.`,
            type: VulnerabilityType.SQL_INJECTION,
            criticality: Criticality.HIGH,
            cvssScore: 9.8,
            affectedUrl: `${this.baseUrl}/api/login`,
            recommendation: 'Validar y castear tipos de entrada. Rechazar objetos donde se esperan strings. Usar librerías de validación (Joi, class-validator) con transformación de tipos.',
          });
          return results;
        }
      } catch { /* ignore */ }
    }

    return results;
  }

  // ─── 14. XSS Reflection ──────────────────────────────────────────────────

  private async checkXssReflection(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const probe = '<sentinel-xss-probe-2026>';
    const scriptProbe = '<script>sentinel_xss_test</script>';

    for (const param of params.slice(0, 10)) {
      try {
        const url = `${this.baseUrl}?${param}=${encodeURIComponent(probe)}`;
        const res = await this.http.get(url, { timeout: 6000 });
        const body = String(res.data ?? '');

        if (body.includes(probe)) {
          // Check if it's inside a script context (more severe)
          const inScript = /<script[^>]*>[\s\S]*sentinel-xss-probe/i.test(body);
          results.push({
            name: `XSS Reflejado — parámetro "${param}" sin codificación HTML`,
            description: `El parámetro "${param}" refleja el valor directamente en el HTML${inScript ? ' dentro de un contexto <script>' : ''}. Un atacante puede inyectar <script> para ejecutar código arbitrario en el navegador de la víctima (robo de cookies, keylogger, redireccionamiento).`,
            type: VulnerabilityType.XSS,
            criticality: inScript ? Criticality.HIGH : Criticality.HIGH,
            cvssScore: inScript ? 8.8 : 7.5,
            affectedUrl: url,
            recommendation: 'Codificar TODO output HTML usando entidades antes de renderizar. En frameworks modernos (React/Angular/Vue) usar los mecanismos de escape incluidos. Implementar CSP para mitigar el impacto.',
          });
          break;
        }

        // Test script tag reflection
        const url2 = `${this.baseUrl}?${param}=${encodeURIComponent(scriptProbe)}`;
        const res2 = await this.http.get(url2, { timeout: 5000 });
        const body2 = String(res2.data ?? '');
        if (body2.includes(scriptProbe)) {
          results.push({
            name: `XSS Reflejado — Script tag no filtrado en "${param}"`,
            description: `El parámetro "${param}" refleja tags <script> sin filtrar. XSS confirmado.`,
            type: VulnerabilityType.XSS,
            criticality: Criticality.HIGH,
            cvssScore: 8.8,
            affectedUrl: url2,
            recommendation: 'Sanitizar y codificar toda entrada de usuario antes de incluirla en HTML.',
          });
          break;
        }
      } catch { /* ignore */ }
    }

    return results;
  }

  // ─── 15. SSRF — Server-Side Request Forgery ───────────────────────────────

  private async checkSsrf(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const urlParams = params.filter(p => /url|link|src|href|path|host|endpoint|redirect|proxy|fetch|load|remote/i.test(p));
    const testParams = urlParams.length > 0 ? urlParams : ['url', 'redirect', 'path', 'src', 'href', 'host'];

    for (const target of SSRF_TARGETS.slice(0, 3)) {
      for (const param of testParams.slice(0, 4)) {
        try {
          const url = `${this.baseUrl}?${param}=${encodeURIComponent(target.url)}`;
          const startTime = Date.now();
          const res = await this.http.get(url, { timeout: 8000 });
          const elapsed = Date.now() - startTime;
          const body = String(res.data ?? '').toLowerCase();

          // Signatures of internal service responses
          const hasInternalContent =
            body.includes('ami-id') ||               // AWS metadata
            body.includes('instance-id') ||
            body.includes('computemetadata') ||        // GCP metadata
            body.includes('root:x:') ||               // /etc/passwd
            body.includes('"hostname"') ||
            (res.status === 200 && elapsed < 500 && body.length > 50 && !body.includes('not found'));

          if (hasInternalContent) {
            results.push({
              name: `SSRF Confirmado — parámetro "${param}" realiza solicitudes internas a ${target.label}`,
              description: `El parámetro "${param}" acepta URLs y realiza solicitudes hacia ${target.url} (${target.label}). La respuesta contiene contenido interno. Un atacante puede escanear la red interna, acceder a metadatos de cloud (AWS/GCP/Azure), o pivotar hacia servicios internos no expuestos.`,
              type: VulnerabilityType.SSRF,
              criticality: Criticality.HIGH,
              cvssScore: 9.0,
              affectedUrl: url,
              recommendation: 'URGENTE: Validar URLs contra whitelist de dominios permitidos. Bloquear IPs privadas (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x) a nivel de firewall y aplicación. Usar DNS rebinding protection.',
            });
            return results;
          }
        } catch { /* connection refused = good (means server blocked it) */ }
      }
    }

    // Check for potential SSRF via URL params accepting internal patterns (heuristic)
    for (const param of testParams.slice(0, 3)) {
      try {
        const url = `${this.baseUrl}?${param}=http://127.0.0.1:8080`;
        const res = await this.http.get(url, { timeout: 6000 });
        if (res.status === 200 && String(res.data ?? '').length > 100) {
          results.push({
            name: `Posible SSRF — parámetro "${param}" acepta URLs externas`,
            description: `El parámetro "${param}" acepta URLs (incluyendo http://127.0.0.1) y devuelve respuesta con contenido. Verificar manualmente si realiza la solicitud interna.`,
            type: VulnerabilityType.SSRF,
            criticality: Criticality.MEDIUM,
            cvssScore: 7.2,
            affectedUrl: url,
            recommendation: 'Validar y restringir URLs que la aplicación puede seguir. Usar allowlist de dominios.',
          });
          break;
        }
      } catch { /* ignore */ }
    }

    return results;
  }

  // ─── 16. Command Injection (Time-based) ──────────────────────────────────

  private async checkCommandInjection(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    for (const param of params.slice(0, 6)) {
      for (const payload of CMD_PAYLOADS.slice(0, 3)) {
        try {
          const url = `${this.baseUrl}?${param}=${encodeURIComponent('test' + payload)}`;
          const startTime = Date.now();
          await this.http.get(url, { timeout: 10000 });
          const elapsed = Date.now() - startTime;

          if (elapsed > 4500) {
            results.push({
              name: `Command Injection Time-Based — parámetro "${param}"`,
              description: `El parámetro "${param}" causó un delay de ${elapsed}ms al inyectar "${payload}". Esto indica que el input se pasa sin sanitización a una llamada de sistema (exec, shell_exec, system, etc.). Un atacante puede ejecutar comandos arbitrarios en el servidor.`,
              type: VulnerabilityType.SECURITY_MISCONFIG,
              criticality: Criticality.HIGH,
              cvssScore: 9.8,
              affectedUrl: url,
              recommendation: 'URGENTE: Nunca pasar input del usuario a funciones de sistema (exec, shell_exec, subprocess). Si es absolutamente necesario, usar whitelist estricta de valores permitidos y escapar con las funciones apropiadas del lenguaje.',
            });
            return results;
          }
        } catch { /* ignore */ }
      }
    }

    return results;
  }

  // ─── 17. Path Traversal / LFI ────────────────────────────────────────────

  private async checkPathTraversal(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const fileParams = params.filter(p => /file|path|page|doc|template|view|include|load|download|src|dir/i.test(p));
    const testParams = fileParams.length > 0 ? fileParams : ['file', 'path', 'page', 'template', 'include', 'doc'];

    for (const param of testParams.slice(0, 5)) {
      for (const payload of TRAVERSAL_PAYLOADS.slice(0, 4)) {
        try {
          const url = `${this.baseUrl}?${param}=${encodeURIComponent(payload)}`;
          const res = await this.http.get(url, { timeout: 6000 });
          const body = String(res.data ?? '');

          const hasTraversalContent = TRAVERSAL_SIGNATURES.some(sig => body.includes(sig));

          if (hasTraversalContent) {
            const isLinux = body.includes('root:x:') || body.includes('daemon:');
            results.push({
              name: `Path Traversal / LFI — parámetro "${param}" lee archivos del sistema`,
              description: `El parámetro "${param}" con payload "${payload}" devuelve contenido de ${isLinux ? '/etc/passwd' : 'archivos del sistema Windows'}. Un atacante puede leer cualquier archivo al que tenga acceso el proceso del servidor (credenciales, claves privadas, código fuente).`,
              type: VulnerabilityType.DATA_EXPOSURE,
              criticality: Criticality.HIGH,
              cvssScore: 9.3,
              affectedUrl: url,
              recommendation: 'URGENTE: Nunca usar input del usuario para construir rutas de archivo. Usar rutas absolutas hardcodeadas o un mapa de archivos permitidos (whitelist). Implementar chroot o sandbox para el proceso del servidor.',
            });
            return results;
          }
        } catch { /* ignore */ }
      }
    }

    return results;
  }

  // ─── 18. SSTI — Server-Side Template Injection ───────────────────────────

  private async checkSsti(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    for (const param of params.slice(0, 8)) {
      for (const { probe, result, engine } of SSTI_PAYLOADS) {
        try {
          const url = `${this.baseUrl}?${param}=${encodeURIComponent(probe)}`;
          const res = await this.http.get(url, { timeout: 6000 });
          const body = String(res.data ?? '');

          if (body.includes(result)) {
            results.push({
              name: `SSTI (Server-Side Template Injection) — parámetro "${param}" — Motor: ${engine}`,
              description: `El parámetro "${param}" evaluó la expresión de template "${probe}" y retornó "${result}". Esto confirma SSTI con motor ${engine}. Un atacante puede ejecutar código arbitrario en el servidor, leer variables de entorno (incluyendo secretos), y potencialmente escalar a RCE completo.`,
              type: VulnerabilityType.SECURITY_MISCONFIG,
              criticality: Criticality.HIGH,
              cvssScore: 9.8,
              affectedUrl: url,
              recommendation: 'URGENTE: Nunca renderizar input del usuario como template. Separar datos de templates. Usar sandboxed template engines o deshabilitar ejecución de código en templates.',
            });
            return results;
          }
        } catch { /* ignore */ }
      }
    }

    return results;
  }

  // ─── 19. XXE — XML External Entity ──────────────────────────────────────

  private async checkXxe(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Look for XML endpoints
    const xmlEndpoints = [
      `${this.baseUrl}/api`,
      `${this.baseUrl}/api/upload`,
      `${this.baseUrl}/api/import`,
      `${this.baseUrl}/upload`,
      `${this.baseUrl}/import`,
      `${this.baseUrl}/xml`,
      `${this.baseUrl}/parse`,
    ];

    for (const endpoint of xmlEndpoints.slice(0, 5)) {
      try {
        const res = await this.http.post(endpoint, XXE_PAYLOAD, {
          headers: {
            'Content-Type': 'application/xml',
            Accept: 'application/xml,text/xml,*/*',
          },
          timeout: 7000,
        });

        const body = String(res.data ?? '');
        const hasXxeContent = XXE_SIGNATURES.some(sig => body.includes(sig));

        if (hasXxeContent) {
          results.push({
            name: `XXE (XML External Entity) Confirmado — ${endpoint}`,
            description: `El endpoint ${endpoint} procesó una entidad XML externa que leyó /etc/passwd del servidor. La respuesta contiene contenido de archivos del sistema. Un atacante puede leer archivos arbitrarios, realizar SSRF interno, y en algunos parsers lograr RCE.`,
            type: VulnerabilityType.DATA_EXPOSURE,
            criticality: Criticality.HIGH,
            cvssScore: 9.1,
            affectedUrl: endpoint,
            recommendation: 'URGENTE: Deshabilitar procesamiento de entidades externas en el parser XML. PHP: libxml_disable_entity_loader(true). Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). Python: defusedxml library.',
          });
          return results;
        }

        // Check if endpoint parses XML at all (look for XML errors)
        if ((res.status === 400 || res.status === 422) && (body.includes('xml') || body.includes('XML') || body.includes('entity'))) {
          results.push({
            name: `Endpoint XML detectado — Verificar XXE manualmente: ${endpoint}`,
            description: `El endpoint ${endpoint} parece procesar XML (retornó error ${res.status} con mención de XML). No se confirmó XXE automáticamente pero merece revisión manual con herramientas como Burp Suite.`,
            type: VulnerabilityType.DATA_EXPOSURE,
            criticality: Criticality.MEDIUM,
            cvssScore: 5.0,
            affectedUrl: endpoint,
            recommendation: 'Revisar manualmente con Burp Suite. Asegurar que el parser XML tenga entidades externas deshabilitadas.',
          });
        }
      } catch { /* ignore */ }
    }

    return results;
  }

  // ─── 20. Open Redirect ────────────────────────────────────────────────────

  private async checkOpenRedirect(params: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const externalUrl = 'https://evil-sentinel-redirect-test.com';
    const redirectParams = params.filter(p => /redirect|url|next|return|goto|target|dest|destination|back/i.test(p));
    const testParams = redirectParams.length > 0 ? redirectParams : ['redirect', 'url', 'next', 'return', 'goto'];

    for (const param of testParams.slice(0, 5)) {
      try {
        const testUrl = `${this.baseUrl}?${param}=${encodeURIComponent(externalUrl)}`;
        const res = await this.http.get(testUrl, { timeout: 5000, maxRedirects: 0 });

        if (res.status >= 300 && res.status < 400) {
          const location = res.headers['location'] ?? '';
          if (location.includes('evil-sentinel-redirect-test.com')) {
            results.push({
              name: `Open Redirect — parámetro "${param}"`,
              description: `El parámetro "${param}" acepta URLs externas sin validación y redirige al usuario hacia ${externalUrl}. Un atacante puede crear links legítimos de tu dominio que llevan a sitios de phishing.`,
              type: VulnerabilityType.SECURITY_MISCONFIG,
              criticality: Criticality.MEDIUM,
              cvssScore: 6.1,
              affectedUrl: testUrl,
              recommendation: 'Validar URLs contra whitelist de dominios. Usar solo rutas relativas para redirects internos.',
            });
            break;
          }
        }
      } catch { /* ignore */ }
    }

    return results;
  }
}
