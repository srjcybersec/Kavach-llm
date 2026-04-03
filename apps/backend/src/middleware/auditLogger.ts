import crypto from "crypto";
import { prisma } from "../prismaClient.js";
import type { ThreatClassificationResult } from "./threatClassifier.js";
import type { PolicyAction } from "./policyEngine.js";
import type { ScanInputResult } from "./inputScanner.js";
import type { OutputFilterResult } from "./outputFilter.js";

export function sha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export type AuditLogCreateParams = {
  sessionId: string;
  userId: string;
  apiKeyId: string;
  inputText: string;
  responseText: string;
  threat: ThreatClassificationResult;
  action: PolicyAction;
  latencyMs: number;
  scan?: ScanInputResult;
  outputFilter?: OutputFilterResult;
  arbitration?: { primaryCategory: string; secondaryCategory: string; agree: boolean };
  piiTypes?: string[];
  piiValues?: string[]; // plaintext PII values are only used for hashing, never stored
};

function severityFromConfidence(confidence: number): string {
  if (confidence >= 0.85) return "HIGH";
  if (confidence >= 0.7) return "MEDIUM";
  return "LOW";
}

export async function createAuditLogEntry(params: AuditLogCreateParams): Promise<{ auditLogId: string }> {
  const inputHash = sha256(params.inputText);
  const responseHash = sha256(params.responseText);

  const piiValues = params.piiValues ?? [];
  const piiValueHashes = piiValues.map((v) => sha256(v));

  const piiFields = {
    types: params.piiTypes ?? params.scan?.piiFound ?? [],
    valuesHash: piiValueHashes
  };

  const scanBreakdown = params.scan
    ? {
        flags: params.scan.flags,
        riskScore: params.scan.riskScore,
        piiFound: params.scan.piiFound
      }
    : null;

  const scanBreakdownWithExtras =
    scanBreakdown === null
      ? {
          outputFilter: params.outputFilter ?? null,
          arbitration: params.arbitration ?? null
        }
      : {
          ...scanBreakdown,
          outputFilter: params.outputFilter ?? null,
          arbitration: params.arbitration ?? null
        };

  // `AuditLog.sessionId` is a required FK to `Session`.
  // The proxy pipeline derives `sessionId` from headers (often `user:<userId>`) and
  // the current context tracker updates Redis but does not create the SQL Session row.
  // Upserting here prevents FK constraint violations and makes auditing reliable.
  await prisma.session.upsert({
    where: { id: params.sessionId },
    update: { lastActiveAt: new Date() },
    create: {
      id: params.sessionId,
      userId: params.userId
    }
  });

  const auditLog = await prisma.auditLog.create({
    data: {
      sessionId: params.sessionId,
      apiKeyId: params.apiKeyId,
      userId: params.userId,
      inputHash,
      threatCategory: params.threat.category,
      confidence: params.threat.confidence,
      action: params.action,
      responseHash,
      latencyMs: params.latencyMs,
      piiFields,
      scanBreakdown: scanBreakdownWithExtras
    }
  });

  await prisma.threatEvent.create({
    data: {
      auditLogId: auditLog.id,
      category: params.threat.category,
      severity: severityFromConfidence(params.threat.confidence),
      description: params.threat.subCategories.slice(0, 5).join(", "),
      resolved: false
    }
  });

  return { auditLogId: auditLog.id };
}

