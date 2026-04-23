export enum Criticality {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

export enum ScanStatus {
  PENDING = 'PENDING',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

export enum VulnerabilityType {
  SQL_INJECTION = 'SQL_INJECTION',
  XSS = 'XSS',
  CSRF = 'CSRF',
  INSECURE_CONFIG = 'INSECURE_CONFIG',
  DATA_EXPOSURE = 'DATA_EXPOSURE',
  BROKEN_AUTH = 'BROKEN_AUTH',
  SECURITY_MISCONFIG = 'SECURITY_MISCONFIG',
  SSRF = 'SSRF',
  OTHER = 'OTHER',
}

export enum ScanDepth {
  LOW = 'low',
  MEDIUM = 'medium',
  DEEP = 'deep',
}
