import { ScannerEngine } from './scanner';
import { Criticality, VulnerabilityType } from '../common/enums';

// ─── Helpers to access private methods ──────────────────────────────────────

function callPrivate<T>(instance: unknown, method: string, ...args: unknown[]): T {
  return (instance as Record<string, (...a: unknown[]) => T>)[method](...args);
}

// ─── ScannerEngine — White-Box Unit Tests ────────────────────────────────────

describe('ScannerEngine — allows()', () => {
  it('returns true for any type when vulnTypes is empty (run all)', () => {
    const engine = new ScannerEngine('http://example.com', 'low', []);
    expect(callPrivate(engine, 'allows', 'SQL_INJECTION')).toBe(true);
    expect(callPrivate(engine, 'allows', 'XSS', 'CSRF')).toBe(true);
  });

  it('returns true when at least one type matches the filter list', () => {
    const engine = new ScannerEngine('http://example.com', 'low', ['XSS', 'CSRF']);
    expect(callPrivate(engine, 'allows', 'XSS')).toBe(true);
    expect(callPrivate(engine, 'allows', 'SQL_INJECTION', 'XSS')).toBe(true);
  });

  it('returns false when none of the given types is in the filter list', () => {
    const engine = new ScannerEngine('http://example.com', 'low', ['XSS']);
    expect(callPrivate(engine, 'allows', 'SQL_INJECTION')).toBe(false);
    expect(callPrivate(engine, 'allows', 'CSRF', 'SSRF')).toBe(false);
  });
});

// ─── spider() — link, form, and query param extraction ───────────────────────

describe('ScannerEngine — spider()', () => {
  const engine = new ScannerEngine('http://example.com', 'deep', []);

  it('extracts same-origin href links', () => {
    const html = `<a href="http://example.com/page1">p1</a>
                  <a href="/page2">p2</a>
                  <a href="http://other.com/page3">p3</a>`;
    const result = callPrivate<ReturnType<(typeof engine)['spider' & string]>>(engine, 'spider', html);
    expect(result.links).toContain('http://example.com/page1');
    expect(result.links).toContain('http://example.com/page2');
    expect(result.links).not.toContain('http://other.com/page3');
  });

  it('extracts query param names from hrefs', () => {
    const html = `<a href="http://example.com/search?q=hello&page=1">search</a>`;
    const result = callPrivate<{ links: string[]; formParams: string[]; queryParams: Set<string> }>(engine, 'spider', html);
    expect(result.queryParams.has('q')).toBe(true);
    expect(result.queryParams.has('page')).toBe(true);
  });

  it('extracts form input names', () => {
    const html = `<input type="text" name="username" />
                  <input type="password" name="password" />`;
    const result = callPrivate<{ links: string[]; formParams: string[]; queryParams: Set<string> }>(engine, 'spider', html);
    expect(result.formParams).toContain('username');
    expect(result.formParams).toContain('password');
  });

  it('extracts API paths from JS fetch patterns', () => {
    const html = `fetch('/api/users', { method: 'GET' })`;
    const result = callPrivate<{ links: string[]; formParams: string[]; queryParams: Set<string> }>(engine, 'spider', html);
    expect(result.links).toContain('http://example.com/api/users');
  });

  it('deduplicates links and respects 30-link limit', () => {
    const links = Array.from({ length: 50 }, (_, i) => `<a href="http://example.com/p${i}">x</a>`).join('');
    const result = callPrivate<{ links: string[] }>(engine, 'spider', links);
    expect(result.links.length).toBeLessThanOrEqual(30);
    const uniqueLinks = new Set(result.links);
    expect(uniqueLinks.size).toBe(result.links.length);
  });

  it('returns empty collections for empty HTML', () => {
    const result = callPrivate<{ links: string[]; formParams: string[]; queryParams: Set<string> }>(engine, 'spider', '');
    expect(result.links).toHaveLength(0);
    expect(result.formParams).toHaveLength(0);
    expect(result.queryParams.size).toBe(0);
  });
});

// ─── buildCheckList() — depth levels ─────────────────────────────────────────

describe('ScannerEngine — buildCheckList() depth', () => {
  const discovered = { links: [], formParams: [], queryParams: new Set<string>() };

  it('low depth returns only base checks (6 checks)', () => {
    const engine = new ScannerEngine('http://example.com', 'low', []);
    const checks = callPrivate<unknown[]>(engine, 'buildCheckList', discovered);
    expect(checks.length).toBe(6);
  });

  it('medium depth returns base + medium checks (11 checks)', () => {
    const engine = new ScannerEngine('http://example.com', 'medium', []);
    const checks = callPrivate<unknown[]>(engine, 'buildCheckList', discovered);
    expect(checks.length).toBe(11);
  });

  it('deep depth returns base + medium + deep checks (more than 11)', () => {
    const engine = new ScannerEngine('http://example.com', 'deep', []);
    const checks = callPrivate<unknown[]>(engine, 'buildCheckList', discovered);
    expect(checks.length).toBeGreaterThan(11);
  });

  it('filters checks when vulnTypes restricts scope', () => {
    const engineAll = new ScannerEngine('http://example.com', 'deep', []);
    const engineXss = new ScannerEngine('http://example.com', 'deep', ['XSS']);
    const allChecks = callPrivate<unknown[]>(engineAll, 'buildCheckList', discovered);
    const xssChecks = callPrivate<unknown[]>(engineXss, 'buildCheckList', discovered);
    expect(xssChecks.length).toBeLessThan(allChecks.length);
  });
});

// ─── checkDirectoryListing() ──────────────────────────────────────────────────

describe('ScannerEngine — checkDirectoryListing()', () => {
  const engine = new ScannerEngine('http://example.com', 'deep', []);

  it('detects "Index of /" in response body', async () => {
    const res = { data: '<html><body>Index of /var/www</body></html>', headers: {}, status: 200 } as unknown;
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkDirectoryListing', res);
    expect(results).toHaveLength(1);
    expect((results[0] as { name: string }).name).toContain('Directory Listing');
  });

  it('detects "directory listing for" pattern', async () => {
    const res = { data: 'Directory listing for /uploads/', headers: {}, status: 200 } as unknown;
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkDirectoryListing', res);
    expect(results).toHaveLength(1);
  });

  it('returns empty when no directory listing indicators present', async () => {
    const res = { data: '<html><body>Welcome</body></html>', headers: {}, status: 200 } as unknown;
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkDirectoryListing', res);
    expect(results).toHaveLength(0);
  });

  it('returns empty when res is null', async () => {
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkDirectoryListing', null);
    expect(results).toHaveLength(0);
  });
});

// ─── checkSecurityHeaders() ──────────────────────────────────────────────────

describe('ScannerEngine — checkSecurityHeaders()', () => {
  const engine = new ScannerEngine('http://example.com', 'deep', []);

  it('reports missing X-Frame-Options when no CSP frame-ancestors', async () => {
    const res = { data: '', headers: {}, status: 200 } as unknown;
    const results = await callPrivate<Promise<{ name: string; type: string }[]>>(engine, 'checkSecurityHeaders', res);
    const names = results.map(r => r.name);
    expect(names.some(n => n.includes('X-Frame-Options'))).toBe(true);
  });

  it('skips X-Frame-Options finding when CSP has frame-ancestors', async () => {
    const res = {
      data: '',
      headers: { 'content-security-policy': "frame-ancestors 'none'" },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkSecurityHeaders', res);
    expect(results.every(r => !r.name.includes('X-Frame-Options'))).toBe(true);
  });

  it('reports CSP with unsafe-eval', async () => {
    const res = {
      data: '',
      headers: {
        'content-security-policy': "default-src 'self'; script-src 'unsafe-eval'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
      },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkSecurityHeaders', res);
    expect(results.some(r => r.name.includes('unsafe-eval'))).toBe(true);
  });

  it('reports wildcard CORS in Access-Control-Allow-Origin', async () => {
    const res = {
      data: '',
      headers: { 'access-control-allow-origin': '*' },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkSecurityHeaders', res);
    expect(results.some(r => r.name.includes('CORS') && r.name.includes('*'))).toBe(true);
  });

  it('returns empty when all security headers are present and safe', async () => {
    const res = {
      data: '',
      headers: {
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'self'",
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
        'strict-transport-security': 'max-age=63072000',
      },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkSecurityHeaders', res);
    expect(results).toHaveLength(0);
  });

  it('returns empty when res is null', async () => {
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkSecurityHeaders', null);
    expect(results).toHaveLength(0);
  });
});

// ─── checkCookieSecurity() ────────────────────────────────────────────────────

describe('ScannerEngine — checkCookieSecurity()', () => {
  const engine = new ScannerEngine('http://example.com', 'deep', []);

  it('reports missing HttpOnly flag', async () => {
    const res = {
      data: '',
      headers: { 'set-cookie': ['sessionId=abc123; Secure; SameSite=Strict'] },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkCookieSecurity', res);
    expect(results.some(r => r.name.includes('HttpOnly'))).toBe(true);
  });

  it('reports missing Secure flag', async () => {
    const res = {
      data: '',
      headers: { 'set-cookie': ['sessionId=abc123; HttpOnly; SameSite=Strict'] },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkCookieSecurity', res);
    expect(results.some(r => r.name.includes('Secure'))).toBe(true);
  });

  it('reports missing SameSite flag', async () => {
    const res = {
      data: '',
      headers: { 'set-cookie': ['sessionId=abc123; HttpOnly; Secure'] },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkCookieSecurity', res);
    expect(results.some(r => r.name.includes('SameSite'))).toBe(true);
  });

  it('reports HIGH criticality for SameSite=None without Secure', async () => {
    const res = {
      data: '',
      headers: { 'set-cookie': ['session=x; SameSite=None'] },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ criticality: string }[]>>(engine, 'checkCookieSecurity', res);
    expect(results.some(r => r.criticality === Criticality.HIGH)).toBe(true);
  });

  it('returns empty when no set-cookie header', async () => {
    const res = { data: '', headers: {}, status: 200 } as unknown;
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkCookieSecurity', res);
    expect(results).toHaveLength(0);
  });

  it('returns empty when cookie has all flags set properly', async () => {
    const res = {
      data: '',
      headers: { 'set-cookie': ['session=x; HttpOnly; Secure; SameSite=Strict'] },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkCookieSecurity', res);
    expect(results).toHaveLength(0);
  });

  it('deduplicates findings for same cookie', async () => {
    const res = {
      data: '',
      headers: { 'set-cookie': ['sid=x', 'sid=x'] },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkCookieSecurity', res);
    const httpOnlyFindings = results.filter(r => r.name.includes('HttpOnly')).length;
    expect(httpOnlyFindings).toBe(1);
  });
});

// ─── checkInformationDisclosure() — version detection ─────────────────────────

describe('ScannerEngine — checkInformationDisclosure()', () => {
  const engine = new ScannerEngine('http://example.com', 'deep', []);

  it('flags Server header that includes a version number', async () => {
    const res = { data: '', headers: { server: 'nginx/1.18.0' }, status: 200 } as unknown;
    const results = await callPrivate<Promise<{ name: string; type: string }[]>>(engine, 'checkInformationDisclosure', res);
    expect(results.some(r => r.name.includes('Server') && r.name.includes('nginx/1.18.0'))).toBe(true);
    expect(results.some(r => r.type === VulnerabilityType.DATA_EXPOSURE)).toBe(true);
  });

  it('does not flag Server header without version number', async () => {
    const res = { data: '', headers: { server: 'nginx' }, status: 200 } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkInformationDisclosure', res);
    expect(results.every(r => !r.name.includes('Server expone versión'))).toBe(true);
  });

  it('flags X-Powered-By header', async () => {
    const res = { data: '', headers: { 'x-powered-by': 'PHP/7.4.3' }, status: 200 } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkInformationDisclosure', res);
    expect(results.some(r => r.name.includes('X-Powered-By'))).toBe(true);
  });

  it('detects WordPress in body', async () => {
    const res = { data: '<link href="/wp-content/themes/x/style.css">', headers: {}, status: 200 } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkInformationDisclosure', res);
    expect(results.some(r => r.name.includes('WordPress'))).toBe(true);
  });

  it('detects stack trace in error response', async () => {
    const res = {
      data: 'Internal Server Error\nstack trace: at app.js line 42',
      headers: {},
      status: 500,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkInformationDisclosure', res);
    expect(results.some(r => r.name.includes('Stack trace'))).toBe(true);
  });

  it('returns empty when res is null', async () => {
    const results = await callPrivate<Promise<unknown[]>>(engine, 'checkInformationDisclosure', null);
    expect(results).toHaveLength(0);
  });
});

// ─── checkHttpsAndHsts() — HSTS boundary cases ───────────────────────────────

describe('ScannerEngine — checkHttpsAndHsts() HSTS logic', () => {
  it('flags missing HSTS header on HTTPS site', async () => {
    const engine = new ScannerEngine('https://example.com', 'low', []);
    const res = { data: '', headers: {}, status: 200 } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkHttpsAndHsts', res);
    expect(results.some(r => r.name.includes('HSTS'))).toBe(true);
  });

  it('flags HSTS max-age below 30 days (< 2592000)', async () => {
    const engine = new ScannerEngine('https://example.com', 'low', []);
    const res = {
      data: '',
      headers: { 'strict-transport-security': 'max-age=86400' },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkHttpsAndHsts', res);
    expect(results.some(r => r.name.includes('max-age insuficiente'))).toBe(true);
  });

  it('does not flag HSTS when max-age >= 2592000', async () => {
    const engine = new ScannerEngine('https://example.com', 'low', []);
    const res = {
      data: '',
      headers: { 'strict-transport-security': 'max-age=63072000; includeSubDomains' },
      status: 200,
    } as unknown;
    const results = await callPrivate<Promise<{ name: string }[]>>(engine, 'checkHttpsAndHsts', res);
    expect(results.every(r => !r.name.includes('max-age'))).toBe(true);
  });

  it('flags plain HTTP site as HIGH criticality', async () => {
    const engine = new ScannerEngine('http://example.com', 'low', []);
    const results = await callPrivate<Promise<{ criticality: string; name: string }[]>>(engine, 'checkHttpsAndHsts', null);
    expect(results.some(r => r.name.includes('HTTPS') && r.criticality === Criticality.HIGH)).toBe(true);
  });
});
