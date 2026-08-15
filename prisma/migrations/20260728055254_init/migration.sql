-- CreateEnum
CREATE TYPE "Platform" AS ENUM ('ANDROID', 'IOS');

-- CreateEnum
CREATE TYPE "SessionStatus" AS ENUM ('ACTIVE', 'COMPLETE', 'INCOMPLETE', 'ABORTED');

-- CreateEnum
CREATE TYPE "Verdict" AS ENUM ('CLEAN', 'SUSPICIOUS', 'FLAGGED', 'INVALID');

-- CreateEnum
CREATE TYPE "IntegrityVerdict" AS ENUM ('MEETS_STRONG', 'MEETS_DEVICE', 'MEETS_BASIC', 'DEGRADED', 'FAILED', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "AttestationType" AS ENUM ('PLAY_INTEGRITY', 'APP_ATTEST', 'NONE');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- CreateEnum
CREATE TYPE "FlagType" AS ENUM ('ROOT', 'HOOKING_FRAMEWORK', 'BLACKLIST_PACKAGE', 'APK_SIGNATURE_MISMATCH', 'INTEGRITY_FAILED', 'EMULATOR', 'OVERLAY', 'ACCESSIBILITY', 'INTEGRITY_BASIC', 'INTEGRITY_DEGRADED', 'SNAPSHOT_GAP', 'SIGNATURE_INVALID', 'NONCE_REUSE');

-- CreateTable
CREATE TABLE "Device" (
    "id" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "publicKeyFp" TEXT NOT NULL,
    "platform" "Platform" NOT NULL,
    "keyAlgo" TEXT NOT NULL DEFAULT 'ES256',
    "attestationType" "AttestationType" NOT NULL DEFAULT 'NONE',
    "attestationData" JSONB,
    "label" TEXT,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Device_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "status" "SessionStatus" NOT NULL DEFAULT 'ACTIVE',
    "verdict" "Verdict",
    "currentNonce" TEXT NOT NULL,
    "expectedIntervalSec" INTEGER NOT NULL DEFAULT 45,
    "jitterSec" INTEGER NOT NULL DEFAULT 15,
    "blacklistVersion" INTEGER NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Snapshot" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "seq" INTEGER NOT NULL,
    "clientTimestamp" TIMESTAMP(3) NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signals" JSONB NOT NULL,
    "signedPayload" BYTEA NOT NULL,
    "signatureValid" BOOLEAN NOT NULL,
    "nonceUsed" TEXT NOT NULL,
    "integrityVerdict" "IntegrityVerdict" NOT NULL DEFAULT 'UNKNOWN',

    CONSTRAINT "Snapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Flag" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "snapshotId" TEXT,
    "type" "FlagType" NOT NULL,
    "severity" "Severity" NOT NULL,
    "details" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Flag_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlacklistEntry" (
    "id" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "severity" "Severity" NOT NULL DEFAULT 'HIGH',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlacklistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlacklistState" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "version" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "BlacklistState_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Device_publicKeyFp_key" ON "Device"("publicKeyFp");

-- CreateIndex
CREATE INDEX "Device_platform_idx" ON "Device"("platform");

-- CreateIndex
CREATE INDEX "Session_status_lastSeenAt_idx" ON "Session"("status", "lastSeenAt");

-- CreateIndex
CREATE INDEX "Session_deviceId_idx" ON "Session"("deviceId");

-- CreateIndex
CREATE UNIQUE INDEX "Snapshot_sessionId_seq_key" ON "Snapshot"("sessionId", "seq");

-- CreateIndex
CREATE UNIQUE INDEX "Snapshot_sessionId_nonceUsed_key" ON "Snapshot"("sessionId", "nonceUsed");

-- CreateIndex
CREATE INDEX "Flag_sessionId_idx" ON "Flag"("sessionId");

-- CreateIndex
CREATE UNIQUE INDEX "BlacklistEntry_packageName_key" ON "BlacklistEntry"("packageName");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Snapshot" ADD CONSTRAINT "Snapshot_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Flag" ADD CONSTRAINT "Flag_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Flag" ADD CONSTRAINT "Flag_snapshotId_fkey" FOREIGN KEY ("snapshotId") REFERENCES "Snapshot"("id") ON DELETE SET NULL ON UPDATE CASCADE;
