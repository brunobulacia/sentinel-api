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
  { path: '/composer.json',      label: 'composer.json expuesto',               cvss: 3.7, crit: Criticality.LOW },
  { path: '/package.json',       label: 'package.json expuesto',                cvss: 3.7, crit: Criticality.LOW },
];

// ─── Scanner Engine ─────────────────────────────────────────────────────────

export class ScannerEngine {
  private readonly http: AxiosInstance;
  private readonly baseUrl: string;
  private readonly depth: string;

  constructor(targetUrl: string, depth: string) {
    this.baseUrl = targetUrl.replace(/\/$/, '');
    this.depth = depth;

    this.http = axios.create({
      timeout: 8000,
      maxRedirects: 0,
      validateStatus: () => true,
      httpsAgent: INSECURE_AGENT, // Scanner must reach sites with self-signed or misconfigured certs
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Sentinel-Scanner/2.0; Security Audit)',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'es-BO,es;q=0.9,en;q=0.8',
      },
    });
  }

  async scan(onProgress: (pct: number) => Promise<void>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Step 1: detect SSL issues by trying with strict verification first
    if (this.baseUrl.startsWith('https://')) {
      try {
        const strictClient = axios.create({
          timeout: 8000,
          maxRedirects: 0,
          validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Sentinel-Scanner/2.0)' },
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
            name: isExpired
              ? 'Certificado SSL/TLS expirado'
              : isSelfSigned
              ? 'Certificado SSL/TLS autofirmado (self-signed)'
              : 'Certificado SSL/TLS inválido o no verificable',
            description: isExpired
              ? 'El certificado SSL del sitio ha expirado. Los navegadores mostrarán una advertencia de seguridad y las conexiones no son de confianza. Esto puede causar que usuarios abandonen el sitio.'
              : isSelfSigned
              ? 'El sitio usa un certificado autofirmado que no fue emitido por una Autoridad Certificadora (CA) reconocida. Los navegadores bloquean estas conexiones por defecto mostrando error crítico de seguridad.'
              : `El certificado SSL no pudo ser verificado (error: ${code}). La identidad del servidor no puede ser confirmada, exponiendo a los usuarios a ataques MITM.`,
            type: VulnerabilityType.INSECURE_CONFIG,
            criticality: Criticality.HIGH,
            cvssScore: 7.4,
            affectedUrl: this.baseUrl,
            recommendation:
              "Obtener un certificado SSL válido de una CA reconocida. Let's Encrypt provee certificados gratuitos. Renovar antes del vencimiento. Verificar la cadena completa de certificados.",
          });
        }
      }
    }

    // Step 2: fetch main page with insecure agent (bypass SSL issues to continue scanning)
    let mainRes: AxiosResponse | null = null;
    try {
      mainRes = await this.http.get(this.baseUrl);
    } catch {
      /* site completely unreachable */
    }

    // Step 3: run all checks
    const checks = this.buildCheckList();
    const total = checks.length;

    for (let i = 0; i < total; i++) {
      try {
        const found = await checks[i](mainRes);
        results.push(...found);
      } catch {
        /* individual check failure never aborts the scan */
      }
      await onProgress(Math.round(((i + 1) / total) * 88) + 5);
    }

    return results;
  }

  // ─── Check registry ────────────────────────────────────────────────────────

  private buildCheckList(): ((r: AxiosResponse | null) => Promise<ScanResult[]>)[] {
    const base = [
      (r: AxiosResponse | null) => this.checkHttpsAndHsts(r),
      (r: AxiosResponse | null) => this.checkSecurityHeaders(r),
      (r: AxiosResponse | null) => this.checkInformationDisclosure(r),
      (r: AxiosResponse | null) => this.checkCookieSecurity(r),
      (r: AxiosResponse | null) => this.checkCorsConfig(),
      (r: AxiosResponse | null) => this.checkHttpMethods(),
    ];

    const medium = [
      () => this.checkSensitivePaths(),
      (r: AxiosResponse | null) => this.checkRobotsTxt(),
      (r: AxiosResponse | null) => this.checkDirectoryListing(r),
    ];

    const deep = [
      () => this.checkSqlInjection(),
      () => this.checkXssReflection(),
      () => this.checkOpenRedirect(),
    ];

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
        description:
          'El sitio opera sobre HTTP sin cifrado TLS/SSL. Cualquier dato transmitido (credenciales, tokens, información personal) puede ser interceptado por ataques Man-in-the-Middle (MITM).',
        type: VulnerabilityType.INSECURE_CONFIG,
        criticality: Criticality.HIGH,
        cvssScore: 7.5,
        affectedUrl: this.baseUrl,
        recommendation:
          "Implementar TLS 1.2 o superior con certificado de CA confiable (Let's Encrypt). Redirigir todo tráfico HTTP→HTTPS con código 301 permanente.",
      });
      return results; // No point checking HSTS for HTTP site
    }

    // Check if HTTP version redirects to HTTPS
    try {
      const httpUrl = this.baseUrl.replace('https://', 'http://');
      const httpRes = await this.http.get(httpUrl, { timeout: 5000 });
      const loc = httpRes.headers['location'] ?? '';
      const redirectsToHttps = httpRes.status >= 300 && httpRes.status < 400 && loc.startsWith('https://');

      if (!redirectsToHttps) {
        results.push({
          name: 'HTTP no redirige a HTTPS',
          description:
            'El servidor responde a peticiones HTTP sin redirigir a HTTPS, permitiendo conexiones no cifradas aunque el sitio tenga SSL configurado.',
          type: VulnerabilityType.INSECURE_CONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.9,
          affectedUrl: httpUrl,
          recommendation:
            'Configurar redirección 301 permanente. Nginx: `return 301 https://$host$request_uri;`. Apache: `RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]`',
        });
      }
    } catch { /* HTTP port may be blocked */ }

    // HSTS header
    if (res) {
      const hsts = res.headers['strict-transport-security'];
      if (!hsts) {
        results.push({
          name: 'HSTS (HTTP Strict-Transport-Security) ausente',
          description:
            'Sin HSTS, los usuarios que visiten el sitio por primera vez via HTTP son vulnerables a ataques de downgrade SSL (SSLstrip). El navegador no fuerza HTTPS automáticamente.',
          type: VulnerabilityType.INSECURE_CONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.9,
          affectedUrl: this.baseUrl,
          recommendation:
            'Agregar header: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (2 años mínimo recomendado por OWASP).',
        });
      } else {
        const match = hsts.match(/max-age=(\d+)/i);
        if (match && parseInt(match[1]) < 2592000) {
          results.push({
            name: 'HSTS max-age insuficiente (< 30 días)',
            description: `El HSTS tiene max-age=${match[1]} segundos (${Math.round(parseInt(match[1]) / 86400)} días). OWASP recomienda mínimo 2 años (63072000 segundos) para protección efectiva.`,
            type: VulnerabilityType.INSECURE_CONFIG,
            criticality: Criticality.LOW,
            cvssScore: 3.1,
            affectedUrl: this.baseUrl,
            recommendation:
              'Incrementar: `Strict-Transport-Security: max-age=63072000; includeSubDomains`',
          });
        }
      }
    }

    return results;
  }

  // ─── 2. Security Headers (OWASP Secure Headers Project) ───────────────────

  private async checkSecurityHeaders(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const h = res.headers;
    const results: ScanResult[] = [];

    // X-Frame-Options (Clickjacking)
    const xfo = h['x-frame-options'];
    const csp = String(h['content-security-policy'] ?? '');
    const hasFrameAncestors = csp.toLowerCase().includes('frame-ancestors');

    if (!xfo && !hasFrameAncestors) {
      results.push({
        name: 'X-Frame-Options ausente — Riesgo de Clickjacking',
        description:
          'Sin X-Frame-Options ni CSP frame-ancestors, el sitio puede ser incrustado en un iframe malicioso. Un atacante puede superponer elementos transparentes para que el usuario haga clic en acciones no deseadas.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation:
          "Agregar `X-Frame-Options: DENY` o usar CSP moderno: `Content-Security-Policy: frame-ancestors 'none'`",
      });
    }

    // X-Content-Type-Options (MIME sniffing)
    if (h['x-content-type-options'] !== 'nosniff') {
      results.push({
        name: 'X-Content-Type-Options: nosniff ausente',
        description:
          'Sin este header, el navegador puede interpretar archivos con un MIME type diferente al declarado (MIME sniffing). Un atacante puede subir un archivo HTML disfrazado de imagen y ejecutarlo como script.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.LOW,
        cvssScore: 3.7,
        affectedUrl: this.baseUrl,
        recommendation: "Agregar header: `X-Content-Type-Options: nosniff`",
      });
    }

    // Content-Security-Policy
    if (!h['content-security-policy']) {
      results.push({
        name: 'Content-Security-Policy (CSP) no configurado',
        description:
          'Sin CSP, el navegador ejecutará cualquier script incluyendo los inyectados por XSS. CSP es la defensa en profundidad más efectiva contra inyección de scripts.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.MEDIUM,
        cvssScore: 6.1,
        affectedUrl: this.baseUrl,
        recommendation:
          "Implementar CSP: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'`",
      });
    } else {
      // Check for unsafe-eval in CSP
      if (csp.includes("'unsafe-eval'")) {
        results.push({
          name: "CSP contiene 'unsafe-eval' — Debilita protección XSS",
          description:
            "La directiva 'unsafe-eval' en el CSP permite el uso de eval(), Function(), setTimeout(string), etc. Esto anula gran parte de la protección contra XSS que ofrece el CSP.",
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.4,
          affectedUrl: this.baseUrl,
          recommendation: "Eliminar 'unsafe-eval' del CSP. Refactorizar el código para no usar eval() o similares.",
        });
      }
      // Check for unsafe-inline in script-src
      if (csp.includes("'unsafe-inline'") && csp.includes('script-src')) {
        results.push({
          name: "CSP script-src contiene 'unsafe-inline'",
          description:
            "La directiva 'unsafe-inline' permite la ejecución de scripts inline, neutralizando la protección XSS del CSP. Un atacante puede inyectar scripts directamente en el HTML.",
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.LOW,
          cvssScore: 4.3,
          affectedUrl: this.baseUrl,
          recommendation:
            "Reemplazar 'unsafe-inline' con nonces o hashes criptográficos para scripts específicos: `script-src 'self' 'nonce-{random}'`",
        });
      }
    }

    // Referrer-Policy
    if (!h['referrer-policy']) {
      results.push({
        name: 'Referrer-Policy no configurado',
        description:
          'Sin Referrer-Policy, el navegador envía la URL completa como Referer al navegar a otros sitios, pudiendo exponer rutas internas, tokens de sesión o parámetros sensibles en la URL.',
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.1,
        affectedUrl: this.baseUrl,
        recommendation: "Agregar: `Referrer-Policy: strict-origin-when-cross-origin`",
      });
    }

    // Permissions-Policy
    if (!h['permissions-policy'] && !h['feature-policy']) {
      results.push({
        name: 'Permissions-Policy no configurado',
        description:
          'Sin Permissions-Policy, los scripts del sitio (incluyendo los de terceros) tienen acceso irrestricto a cámara, micrófono, geolocalización y otras APIs sensibles del navegador.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.LOW,
        cvssScore: 2.1,
        affectedUrl: this.baseUrl,
        recommendation:
          'Agregar: `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`',
      });
    }

    // CORS wildcard
    const corsOrigin = h['access-control-allow-origin'];
    if (corsOrigin === '*') {
      results.push({
        name: 'CORS configurado con wildcard Access-Control-Allow-Origin: *',
        description:
          'Cualquier sitio web puede hacer solicitudes CORS a este servidor y leer las respuestas. Si se combinara con credenciales, daría acceso completo a datos del usuario.',
        type: VulnerabilityType.SECURITY_MISCONFIG,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation:
          'Restringir el origen CORS a dominios específicos de confianza: `Access-Control-Allow-Origin: https://app.tudominio.com`',
      });
    }

    return results;
  }

  // ─── 3. Information Disclosure ─────────────────────────────────────────────

  private async checkInformationDisclosure(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const h = res.headers;
    const results: ScanResult[] = [];

    // Server header with version number
    const server = String(h['server'] ?? '');
    if (server && /\d/.test(server)) {
      results.push({
        name: `Header Server expone versión: "${server}"`,
        description:
          `El header Server revela el software y versión del servidor web: "${server}". Con esta información, un atacante puede buscar CVEs específicos para esa versión exacta.`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.7,
        affectedUrl: this.baseUrl,
        recommendation:
          'Ocultar versión del servidor. Nginx: `server_tokens off`. Apache: `ServerTokens Prod` + `ServerSignature Off`. IIS: eliminar via web.config.',
      });
    }

    // X-Powered-By
    const xpb = h['x-powered-by'];
    if (xpb) {
      results.push({
        name: `Header X-Powered-By expone tecnología: "${xpb}"`,
        description:
          `El header X-Powered-By revela el framework o lenguaje: "${xpb}". Esta información ayuda a atacantes a identificar vulnerabilidades conocidas en el stack tecnológico.`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.7,
        affectedUrl: this.baseUrl,
        recommendation:
          'Eliminar el header. Express.js: `app.disable("x-powered-by")`. PHP: `expose_php = Off` en php.ini. ASP.NET: httpRuntime removeAdditionalResponseHeaders.',
      });
    }

    // ASP.NET version disclosure
    const aspnetVer = h['x-aspnet-version'];
    if (aspnetVer) {
      results.push({
        name: `X-AspNet-Version expone .NET: "${aspnetVer}"`,
        description:
          `El header revela la versión exacta de ASP.NET: "${aspnetVer}". Las versiones antiguas de .NET tienen CVEs críticos conocidos públicamente.`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation:
          'Deshabilitar en web.config: `<httpRuntime enableVersionHeader="false" />` y eliminar módulo ServerHeader.',
      });
    }

    // WordPress / CMS fingerprinting
    const body = String(res.data ?? '');
    if (body.includes('wp-content') || body.includes('wp-includes')) {
      const wpVerMatch = body.match(/WordPress (\d+\.\d+[\.\d]*)/i);
      results.push({
        name: `CMS WordPress detectado${wpVerMatch ? ` v${wpVerMatch[1]}` : ''}`,
        description:
          `El sitio usa WordPress${wpVerMatch ? ` versión ${wpVerMatch[1]}` : ''}. Los sistemas de gestión de contenido son objetivos frecuentes por sus plugins y temas desactualizados.`,
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.LOW,
        cvssScore: 3.1,
        affectedUrl: this.baseUrl,
        recommendation:
          'Ocultar la versión de WordPress. Usar plugins de seguridad (Wordfence). Mantener WordPress, plugins y temas actualizados.',
      });
    }

    // Error page information disclosure in 4xx/5xx responses
    if (res.status >= 400) {
      const lowerBody = body.toLowerCase();
      const leaksStack = lowerBody.includes('stack trace') ||
        lowerBody.includes('exception in') ||
        lowerBody.includes('at line') ||
        lowerBody.includes('traceback');
      if (leaksStack) {
        results.push({
          name: 'Stack trace / error detallado en respuesta HTTP',
          description:
            'Las páginas de error revelan stack traces con información interna: rutas de archivos, versiones de librerías, estructura de código. Esto facilita enormemente los ataques dirigidos.',
          type: VulnerabilityType.DATA_EXPOSURE,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.4,
          affectedUrl: this.baseUrl,
          recommendation:
            'Configurar páginas de error personalizadas genéricas. Deshabilitar modo debug en producción. Registrar errores en logs internos, nunca mostrar al usuario.',
        });
      }
    }

    return results;
  }

  // ─── 4. Cookie Security ────────────────────────────────────────────────────

  private async checkCookieSecurity(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const results: ScanResult[] = [];

    const rawCookies = res.headers['set-cookie'];
    if (!rawCookies) return [];

    const cookies = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
    const processed = new Set<string>(); // Avoid duplicate reports

    for (const cookie of cookies) {
      const lower = cookie.toLowerCase();
      const cookieName = cookie.split('=')[0].trim();
      const key = `${cookieName}`;

      // Only report each cookie name once
      const isSession = /sess|auth|token|user|id|login|jwt/i.test(cookieName);
      const reportKey = isSession ? cookieName : 'generic';
      if (processed.has(`httponly-${reportKey}`)) continue;

      if (!lower.includes('httponly')) {
        processed.add(`httponly-${reportKey}`);
        results.push({
          name: `Cookie sin HttpOnly: "${cookieName}"`,
          description:
            `La cookie "${cookieName}" es accesible via JavaScript (document.cookie). En caso de XSS, un atacante puede robar el valor completo de la cookie, incluyendo tokens de sesión.`,
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: Criticality.MEDIUM,
          cvssScore: 6.1,
          affectedUrl: this.baseUrl,
          recommendation:
            `Agregar flag HttpOnly: \`Set-Cookie: ${cookieName}=...; HttpOnly; Secure; SameSite=Strict\``,
        });
      }

      if (!lower.includes('secure')) {
        results.push({
          name: `Cookie sin flag Secure: "${cookieName}"`,
          description:
            `La cookie "${cookieName}" no tiene el flag Secure, pudiendo transmitirse por HTTP no cifrado. Si el usuario accede por HTTP, la cookie es interceptable.`,
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.9,
          affectedUrl: this.baseUrl,
          recommendation:
            `Agregar flag Secure: \`Set-Cookie: ${cookieName}=...; Secure; HttpOnly; SameSite=Strict\``,
        });
      }

      if (!lower.includes('samesite')) {
        results.push({
          name: `Cookie sin SameSite: "${cookieName}" — Riesgo CSRF`,
          description:
            `La cookie "${cookieName}" se enviará en solicitudes cross-site, haciéndola vulnerable a ataques CSRF. Un sitio malicioso puede hacer solicitudes autenticadas en nombre del usuario.`,
          type: VulnerabilityType.CSRF,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.4,
          affectedUrl: this.baseUrl,
          recommendation:
            `Agregar SameSite: \`Set-Cookie: ${cookieName}=...; SameSite=Strict; Secure; HttpOnly\``,
        });
      } else if (lower.includes('samesite=none') && !lower.includes('secure')) {
        results.push({
          name: `Cookie SameSite=None sin Secure: "${cookieName}"`,
          description:
            'SameSite=None requiere el flag Secure obligatoriamente. Sin Secure, la cookie se transmite en texto plano en contextos cross-site, violando el estándar RFC 6265bis.',
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: Criticality.HIGH,
          cvssScore: 7.1,
          affectedUrl: this.baseUrl,
          recommendation:
            `Siempre combinar SameSite=None con Secure: \`Set-Cookie: ${cookieName}=...; SameSite=None; Secure; HttpOnly\``,
        });
      }
    }

    return results;
  }

  // ─── 5. CORS Misconfiguration ──────────────────────────────────────────────

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
          name: `CORS refleja origen arbitrario${withCreds ? ' con credenciales (Crítico)' : ''}`,
          description: withCreds
            ? 'El servidor refleja cualquier Origin Y permite credenciales (cookies/tokens). Un atacante puede leer respuestas autenticadas desde cualquier dominio malicioso — equivalente a CSRF completo.'
            : 'El servidor refleja el header Origin de la solicitud sin validación. Un atacante puede hacer solicitudes cross-origin y leer las respuestas, exponiendo datos del API.',
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: withCreds ? Criticality.HIGH : Criticality.MEDIUM,
          cvssScore: withCreds ? 9.0 : 7.4,
          affectedUrl: this.baseUrl,
          recommendation:
            'Implementar whitelist de orígenes. Validar Origin contra lista explícita antes de incluirlo en la respuesta. Nunca usar `request.headers.origin` directamente como valor de `Access-Control-Allow-Origin`.',
        });
      }

      if (allowCredentials === 'true' && allowOrigin === '*') {
        results.push({
          name: 'CORS: Access-Control-Allow-Credentials: true + wildcard origin',
          description:
            'Esta combinación está prohibida por el estándar CORS. Aunque los navegadores modernos la bloquean, indica una mala configuración que puede afectar a clientes HTTP no-navegador.',
          type: VulnerabilityType.BROKEN_AUTH,
          criticality: Criticality.MEDIUM,
          cvssScore: 6.5,
          affectedUrl: this.baseUrl,
          recommendation:
            'Nunca combinar `Allow-Credentials: true` con `Allow-Origin: *`. Especificar el origen exacto: `Access-Control-Allow-Origin: https://app.tudominio.com`',
        });
      }
    } catch { /* Network error is fine */ }
    return results;
  }

  // ─── 6. HTTP Methods (OWASP WSTG-CONF-06) ─────────────────────────────────

  private async checkHttpMethods(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // TRACE → Cross-Site Tracing (XST)
    try {
      const res = await this.http.request({ method: 'TRACE', url: this.baseUrl, timeout: 5000 });
      if (res.status === 200) {
        results.push({
          name: 'Método HTTP TRACE habilitado — Cross-Site Tracing (XST)',
          description:
            'TRACE devuelve la solicitud completa incluyendo headers de autenticación. En navegadores antiguos, esto permite a scripts JavaScript leer cookies HttpOnly via XST, combinando TRACE + XSS.',
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.8,
          affectedUrl: this.baseUrl,
          recommendation:
            'Deshabilitar TRACE. Nginx: `if ($request_method = TRACE) { return 405; }`. Apache: `TraceEnable Off`. IIS: via applicationHost.config.',
        });
      }
    } catch { /* Method not supported */ }

    // OPTIONS → enumerate allowed methods
    try {
      const res = await this.http.request({ method: 'OPTIONS', url: this.baseUrl, timeout: 5000 });
      const allowed = (res.headers['allow'] ?? res.headers['access-control-allow-methods'] ?? '').toUpperCase();
      if (allowed && (allowed.includes('PUT') || allowed.includes('DELETE') || allowed.includes('PATCH'))) {
        results.push({
          name: `Métodos HTTP riesgosos declarados: ${allowed}`,
          description:
            `El servidor declara soporte para ${allowed} via el header Allow/Access-Control-Allow-Methods. PUT permite subir archivos, DELETE eliminarlos. En servidores mal configurados esto puede ser explotado.`,
          type: VulnerabilityType.SECURITY_MISCONFIG,
          criticality: Criticality.MEDIUM,
          cvssScore: 5.4,
          affectedUrl: this.baseUrl,
          recommendation:
            'Restringir métodos permitidos solo a los necesarios en cada endpoint. Verificar que PUT/DELETE solo estén disponibles en rutas autenticadas de APIs REST.',
        });
      }
    } catch { /* OPTIONS blocked */ }

    return results;
  }

  // ─── 7. Sensitive Path Probing ─────────────────────────────────────────────

  private async checkSensitivePaths(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const BATCH = 5;

    for (let i = 0; i < SENSITIVE_PATHS.length; i += BATCH) {
      const batch = SENSITIVE_PATHS.slice(i, i + BATCH);
      const settled = await Promise.allSettled(
        batch.map(async (item) => {
          const url = `${this.baseUrl}${item.path}`;
          const res = await this.http.get(url, { timeout: 5000 });
          // 200 with non-trivial content = exposed
          const body = String(res.data ?? '');
          const exposed = res.status === 200 && body.length > 20;
          if (!exposed) return null;
          return {
            name: item.label,
            description: `La ruta ${item.path} devuelve HTTP ${res.status} con contenido (${body.length} bytes). Este archivo/directorio es accesible públicamente y puede contener credenciales, configuraciones o código fuente.`,
            type: VulnerabilityType.DATA_EXPOSURE,
            criticality: item.crit,
            cvssScore: item.cvss,
            affectedUrl: url,
            recommendation: `Bloquear acceso a ${item.path}. Mover el archivo fuera del webroot o denegar acceso vía reglas del servidor. Auditar si el contenido fue previamente expuesto (revisar logs).`,
          } as ScanResult;
        }),
      );
      for (const r of settled) {
        if (r.status === 'fulfilled' && r.value) results.push(r.value);
      }
    }

    return results;
  }

  // ─── 8. robots.txt Analysis ────────────────────────────────────────────────

  private async checkRobotsTxt(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    try {
      const url = `${this.baseUrl}/robots.txt`;
      const res = await this.http.get(url, { timeout: 5000 });
      if (res.status !== 200) return [];

      const text = String(res.data ?? '');
      const disallows = (text.match(/^Disallow:\s*(.+)/gim) ?? [])
        .map((l) => l.replace(/^Disallow:\s*/i, '').trim())
        .filter((p) => p.length > 1 && p !== '/');

      if (disallows.length > 0) {
        results.push({
          name: `robots.txt expone ${disallows.length} ruta(s) restringida(s)`,
          description:
            `El archivo robots.txt lista rutas que deben ser "ignoradas" por crawlers: ${disallows.slice(0, 6).join(', ')}. Paradójicamente, esto actúa como un mapa para atacantes que lo primero que revisan es robots.txt.`,
          type: VulnerabilityType.DATA_EXPOSURE,
          criticality: Criticality.LOW,
          cvssScore: 3.1,
          affectedUrl: url,
          recommendation:
            'No usar robots.txt para "ocultar" rutas sensibles. La protección real viene de autenticación y autorización. Considerar un robots.txt minimalista: `User-agent: * Disallow: /`',
        });
      }
    } catch { /* robots.txt not found */ }
    return results;
  }

  // ─── 9. Directory Listing ──────────────────────────────────────────────────

  private async checkDirectoryListing(res: AxiosResponse | null): Promise<ScanResult[]> {
    if (!res) return [];
    const body = String(res.data ?? '').toLowerCase();
    if (
      body.includes('index of /') ||
      body.includes('directory listing for') ||
      (body.includes('<title>') && /index of/i.test(body))
    ) {
      return [{
        name: 'Directory Listing habilitado en webroot',
        description:
          'El servidor muestra el listado completo de archivos del directorio raíz. Un atacante puede navegar por toda la estructura de archivos, descubrir archivos de respaldo, configuraciones y código fuente.',
        type: VulnerabilityType.DATA_EXPOSURE,
        criticality: Criticality.MEDIUM,
        cvssScore: 5.4,
        affectedUrl: this.baseUrl,
        recommendation:
          'Deshabilitar Directory Listing. Apache: `Options -Indexes` en .htaccess. Nginx: eliminar `autoindex on`. Asegurar que exista un index.html en todos los directorios.',
      }];
    }
    return [];
  }

  // ─── 10. SQL Injection (Error-based + Response-diff) ──────────────────────

  private async checkSqlInjection(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const probes = [
      { url: `${this.baseUrl}?id=1'`, param: 'id' },
      { url: `${this.baseUrl}?search=test'--`, param: 'search' },
      { url: `${this.baseUrl}?q=1 OR 1=1--`, param: 'q' },
      { url: `${this.baseUrl}?page=1'`, param: 'page' },
    ];

    for (const probe of probes) {
      try {
        const res = await this.http.get(probe.url, { timeout: 7000 });
        const body = String(res.data ?? '').toLowerCase();
        const hasSqlError = SQL_ERROR_PATTERNS.some((p) => body.includes(p));

        if (hasSqlError) {
          results.push({
            name: `SQL Injection detectado — Error SQL en parámetro "${probe.param}"`,
            description:
              `El parámetro "${probe.param}" no sanitiza la entrada y devuelve un error SQL en la respuesta HTTP. Esto confirma inyección SQL error-based, permitiendo extracción directa de datos de la BD.`,
            type: VulnerabilityType.SQL_INJECTION,
            criticality: Criticality.HIGH,
            cvssScore: 9.1,
            affectedUrl: probe.url,
            recommendation:
              'URGENTE: Usar prepared statements / consultas parametrizadas en TODAS las queries. Nunca concatenar input del usuario en SQL. Implementar validación de entrada. Revocar privilegios innecesarios de la BD.',
          });
          break;
        }

        // Boolean-based detection: compare normal vs malicious response size
        const normalRes = await this.http.get(`${this.baseUrl}?${probe.param}=1`, { timeout: 5000 });
        const normalSize = String(normalRes.data ?? '').length;
        const probeSize = body.length;
        const diff = Math.abs(normalSize - probeSize);

        if (diff > 500 && probeSize > 100) {
          results.push({
            name: `Posible SQL Injection — Respuesta anómala en "${probe.param}"`,
            description:
              `El parámetro "${probe.param}" produce respuestas significativamente diferentes (${diff} bytes) al inyectar SQL. Esto sugiere una posible vulnerabilidad de inyección SQL boolean-based.`,
            type: VulnerabilityType.SQL_INJECTION,
            criticality: Criticality.HIGH,
            cvssScore: 8.1,
            affectedUrl: probe.url,
            recommendation:
              'Investigar y verificar manualmente. Implementar consultas parametrizadas y validación de entrada en todos los parámetros de la aplicación.',
          });
          break;
        }
      } catch { /* Timeout or network error */ }
    }

    return results;
  }

  // ─── 11. XSS Reflection Test ──────────────────────────────────────────────

  private async checkXssReflection(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const probe = '<sentinel-xss-probe-2026>';
    const params = ['q', 'search', 's', 'query', 'term', 'keyword'];

    for (const param of params) {
      try {
        const url = `${this.baseUrl}?${param}=${encodeURIComponent(probe)}`;
        const res = await this.http.get(url, { timeout: 6000 });
        const body = String(res.data ?? '');

        if (body.includes(probe)) {
          results.push({
            name: `XSS Reflejado — Input no codificado en parámetro "${param}"`,
            description:
              `El parámetro "${param}" refleja el valor directamente en el HTML sin codificación de entidades. Un atacante puede inyectar <script> para ejecutar código arbitrario en el navegador de la víctima.`,
            type: VulnerabilityType.XSS,
            criticality: Criticality.HIGH,
            cvssScore: 7.5,
            affectedUrl: url,
            recommendation:
              'Codificar TODO output HTML usando entidades HTML antes de renderizarlo. Implementar CSP para mitigar. En frameworks modernos usar los mecanismos de escape incluidos (React JSX, Angular templates, Thymeleaf, etc.)',
          });
          break;
        }
      } catch { /* Ignore */ }
    }

    return results;
  }

  // ─── 12. Open Redirect ─────────────────────────────────────────────────────

  private async checkOpenRedirect(): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const externalUrl = 'https://evil-sentinel-redirect-test.com';
    const params = ['redirect', 'url', 'next', 'return', 'goto', 'target'];

    for (const param of params.slice(0, 4)) {
      try {
        const testUrl = `${this.baseUrl}?${param}=${encodeURIComponent(externalUrl)}`;
        const res = await this.http.get(testUrl, { timeout: 5000, maxRedirects: 0 });

        if (res.status >= 300 && res.status < 400) {
          const location = res.headers['location'] ?? '';
          if (location.includes('evil-sentinel-redirect-test.com')) {
            results.push({
              name: `Open Redirect — Parámetro "${param}" redirige a dominio externo`,
              description:
                `El parámetro "${param}" acepta URLs externas sin validación y redirige al usuario. Un atacante puede crear links legítimos de tu dominio que llevan a sitios de phishing: ${testUrl}`,
              type: VulnerabilityType.SECURITY_MISCONFIG,
              criticality: Criticality.MEDIUM,
              cvssScore: 6.1,
              affectedUrl: testUrl,
              recommendation:
                'Validar URLs de redirección contra whitelist de dominios permitidos. Usar solo rutas relativas para redirects internos. Rechazar cualquier URL con dominio diferente al propio.',
            });
            break;
          }
        }
      } catch { /* Ignore */ }
    }

    return results;
  }
}
