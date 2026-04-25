-- CreateEnum
CREATE TYPE "VulnerabilityType" AS ENUM ('SQL_INJECTION', 'XSS', 'CSRF', 'INSECURE_CONFIG', 'DATA_EXPOSURE', 'BROKEN_AUTH', 'SECURITY_MISCONFIG', 'SSRF', 'OTHER');

-- CreateEnum
CREATE TYPE "ScanDepth" AS ENUM ('low', 'medium', 'deep');

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "Criticality" AS ENUM ('HIGH', 'MEDIUM', 'LOW');

-- CreateTable
CREATE TABLE "scan_configs" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "targetUrl" TEXT NOT NULL,
    "vulnerabilityTypes" "VulnerabilityType"[],
    "depth" "ScanDepth" NOT NULL DEFAULT 'medium',
    "scheduledAt" TIMESTAMP(3),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scan_configs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_executions" (
    "id" TEXT NOT NULL,
    "scanConfigId" TEXT NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'PENDING',
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "progress" INTEGER NOT NULL DEFAULT 0,
    "totalVulnerabilities" INTEGER NOT NULL DEFAULT 0,
    "errorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_executions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerabilities" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "type" "VulnerabilityType" NOT NULL,
    "criticality" "Criticality" NOT NULL,
    "cvssScore" DOUBLE PRECISION,
    "affectedUrl" TEXT NOT NULL,
    "recommendation" TEXT NOT NULL,
    "remediated" BOOLEAN NOT NULL DEFAULT false,
    "remediatedAt" TIMESTAMP(3),
    "scanExecutionId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vulnerabilities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reports" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "format" TEXT NOT NULL DEFAULT 'HTML',
    "content" TEXT NOT NULL,
    "totalVulnerabilities" INTEGER NOT NULL DEFAULT 0,
    "highCount" INTEGER NOT NULL DEFAULT 0,
    "mediumCount" INTEGER NOT NULL DEFAULT 0,
    "lowCount" INTEGER NOT NULL DEFAULT 0,
    "scanExecutionId" TEXT NOT NULL,
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "reports_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "scan_executions" ADD CONSTRAINT "scan_executions_scanConfigId_fkey" FOREIGN KEY ("scanConfigId") REFERENCES "scan_configs"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vulnerabilities" ADD CONSTRAINT "vulnerabilities_scanExecutionId_fkey" FOREIGN KEY ("scanExecutionId") REFERENCES "scan_executions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_scanExecutionId_fkey" FOREIGN KEY ("scanExecutionId") REFERENCES "scan_executions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
