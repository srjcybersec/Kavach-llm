import crypto from "crypto";
import { Router } from "express";
import { z } from "zod";
import { prisma } from "../prismaClient.js";
import { requireAuth } from "../middleware/auth.js";
import { scanInput } from "../middleware/inputScanner.js";
import { classifyThreat } from "../middleware/threatClassifier.js";
import {
  builtInPresetRules,
  evaluatePolicyRules,
  type PolicyAction,
  type PolicyRule
} from "../middleware/policyEngine.js";
import { trackContext, type ContextTrackerResult } from "../middleware/contextTracker.js";
import { applyOutputFilter } from "../middleware/outputFilter.js";
import { createAuditLogEntry } from "../middleware/auditLogger.js";
import { generateLLMResponse } from "../services/llmService.js";
import { env } from "../config.js";
import { publishThreatEvent } from "../socket/threatFeed.js";
import { arbitrateSafety } from "../services/arbitrationService.js";
import { detectPersonaDrift } from "../services/personaDriftService.js";

export const proxyRouter = Router();

const chatBodySchema = z.object({
  message: z.string().min(1).max(20000),
  history: z.array(z.string()).optional(),
  bypassKavach: z.boolean().optional()
});

function sha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function clampTextForRedaction(text: string): string {
  return text.length > 25000 ? text.slice(0, 25000) : text;
}

type DbPolicyRuleRow = {
  id: string;
  action: string;
  priority: number;
  enabled: boolean;
  preset: string | null;
  condition: unknown;
};

function baselinePolicyRules(): PolicyRule[] {
  switch (env.POLICY_BASELINE_PRESET) {
    case "none":
      return [];
    case "StrictEnterprisePolicy":
      return builtInPresetRules("StrictEnterprisePolicy");
    default:
      return builtInPresetRules("DefaultSafePolicy");
  }
}

function mergeWithBaseline(dbRules: PolicyRule[]): PolicyRule[] {
  return [...baselinePolicyRules(), ...dbRules];
}

function redactPIIFromInput(text: string): { redactedText: string; piiTypes: string[] } {
  // Minimal PII redaction for request-side mitigation.
  // Step 5 output filter performs deeper response-side checks.
  const piiTypes: string[] = [];
  let out = text;

  const emailRe = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  if (emailRe.test(out)) {
    piiTypes.push("EMAIL");
    out = out.replace(emailRe, "[REDACTED_EMAIL]");
  }

  const aadhaarRe = /\b\d{4}\s?\d{4}\s?\d{4}\b/g;
  if (aadhaarRe.test(out)) {
    piiTypes.push("AADHAAR");
    out = out.replace(aadhaarRe, "[REDACTED_AADHAAR]");
  }

  const ssnRe = /\b\d{3}-\d{2}-\d{4}\b/g;
  if (ssnRe.test(out)) {
    piiTypes.push("SSN");
    out = out.replace(ssnRe, "[REDACTED_SSN]");
  }

  const phoneRe = /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g;
  if (phoneRe.test(out)) {
    piiTypes.push("PHONE");
    out = out.replace(phoneRe, "[REDACTED_PHONE]");
  }

  // Credit-card regex is intentionally broad; outputFilter performs Luhn validation.
  const ccRe = /\b(?:\d[ -]*?){13,19}\b/g;
  if (ccRe.test(out)) {
    piiTypes.push("CREDIT_CARD");
    out = out.replace(ccRe, "[REDACTED_CREDIT_CARD]");
  }

  return { redactedText: out, piiTypes: Array.from(new Set(piiTypes)) };
}

async function getOrCreateDefaultApiKey(params: { userId: string }) {
  const existing = await prisma.apiKey.findFirst({
    where: { userId: params.userId, status: "ACTIVE" },
    orderBy: { createdAt: "desc" }
  });
  if (existing) return existing;

  // Create a local-only placeholder key to satisfy auditLog foreign key constraints.
  const apiKeyPlain = crypto.randomBytes(24).toString("hex");
  const keyHash = sha256(apiKeyPlain);

  return prisma.apiKey.create({
    data: {
      userId: params.userId,
      keyHash,
      label: "Default (auto-created)",
      reputationScore: 0,
      status: "ACTIVE",
      lastUsed: null
    }
  });
}

function reputationDelta(params: { riskScore: number; action: PolicyAction | "ALLOW"; personaDrift: boolean }): number {
  const base = Math.round(params.riskScore / 10);
  const actionPenalty =
    params.action === "BLOCK" || params.action === "QUARANTINE"
      ? 6
      : params.action === "RATE_LIMIT"
        ? 4
        : params.action === "REDACT_PII" || params.action === "WARN_USER"
          ? 2
          : -1;
  const driftPenalty = params.personaDrift ? 5 : 0;
  return base + actionPenalty + driftPenalty;
}

async function updateApiKeyReputation(params: { apiKeyId: string; delta: number }): Promise<void> {
  const key = await prisma.apiKey.findUnique({ where: { id: params.apiKeyId } });
  if (!key || key.status === "REVOKED") return;

  const nextScore = Math.max(0, Math.min(100, key.reputationScore + params.delta));
  const nextStatus = nextScore >= 80 ? "SUSPENDED" : "ACTIVE";

  await prisma.apiKey.update({
    where: { id: params.apiKeyId },
    data: { reputationScore: nextScore, status: nextStatus, lastUsed: new Date() }
  });
}

proxyRouter.post("/chat", requireAuth, async (req, res) => {
  try {
    const body = chatBodySchema.parse(req.body);
    const userId = req.user!.userId;
    const sessionId =
      typeof req.headers["x-session-id"] === "string" ? req.headers["x-session-id"] : `user:${req.user!.userId}`;

    const start = Date.now();

    if (body.bypassKavach) {
      const scanStart = Date.now();

      // Even in bypass mode, we still return scan/threat/context for UX comparability.
      const scan = scanInput({
        text: clampTextForRedaction(body.message),
        previousMessages: body.history ?? [],
        nowMs: Date.now()
      });
      const threat = classifyThreat({ text: body.message, scan });
      const arbitration = await arbitrateSafety({ scanRiskScore: scan.riskScore, threat });

      let context: ContextTrackerResult;
      try {
        context = await trackContext({ sessionId, currentText: body.message, scan });
      } catch {
        context = { sessionRiskScore: scan.riskScore, escalationDetected: false };
      }

      const scanLatencyMs = Date.now() - scanStart;

      const apiKey = await getOrCreateDefaultApiKey({ userId });

      try {
        const snippet = redactPIIFromInput(body.message).redactedText.slice(0, 140);
        await publishThreatEvent({
          time: new Date().toISOString(),
          category: threat.category,
          riskScore: scan.riskScore,
          actionTaken: "ALLOW",
          redactedInputSnippet: snippet
        });
      } catch {
        // ignore
      }

      const llm = await generateLLMResponse({ userMessage: body.message, sessionId });
      const llmLatencyMs = llm.latencyMs;
      const persona: Awaited<ReturnType<typeof detectPersonaDrift>> = await detectPersonaDrift({ sessionId, llmResponseText: llm.responseText }).catch(() => ({
        driftDetected: false,
        previousPersona: undefined,
        currentPersona: { style: "unknown" as const, claimsCapabilities: false, selfIdentity: "unknown" }
      }));

      const output = applyOutputFilter({
        responseText: llm.responseText,
        sessionId,
        scan,
        honeypotCanaryPhrase: llm.honeypotCanaryPhrase
      });
      if (persona.driftDetected) output.result.warningFlags.push("PERSONA_DRIFT");

      await createAuditLogEntry({
        sessionId,
        userId,
        apiKeyId: apiKey.id,
        inputText: body.message,
        responseText: output.clientResponseText,
        threat,
        action: "ALLOW",
        latencyMs: Date.now() - start,
        scan,
        outputFilter: output.result,
        arbitration: arbitration ?? undefined
      });

      await updateApiKeyReputation({
        apiKeyId: apiKey.id,
        delta: reputationDelta({ riskScore: scan.riskScore, action: "ALLOW", personaDrift: persona.driftDetected })
      });

      if (persona.driftDetected) {
        try {
          await publishThreatEvent({
            time: new Date().toISOString(),
            category: "PERSONA_DRIFT",
            riskScore: scan.riskScore,
            actionTaken: "WARN_USER",
            redactedInputSnippet: `Persona drift detected: ${persona.reason ?? "identity/style changed"}`
          });
        } catch {
          // ignore
        }
      }

      res.status(200).json({
        success: true,
        data: {
          actionTaken: "ALLOW",
          bypassed: true,
          threat,
          scan,
          contextTracker: context,
          outputFilter: output.result,
          response: output.clientResponseText,
          outputFingerprint: output.outputFingerprint,
          scanLatencyMs,
          llmLatencyMs
        }
      });
      return;
    }

    // STEP 1: Input scanner
    const scanStart = Date.now();
    const scan = scanInput({
      text: clampTextForRedaction(body.message),
      previousMessages: body.history ?? [],
      nowMs: Date.now()
    });

    // STEP 2: Threat classifier
    const threat = classifyThreat({ text: body.message, scan });

    // F4: Multi-model arbitration (shadow validation stub)
    const arbitration = await arbitrateSafety({ scanRiskScore: scan.riskScore, threat });

    // STEP 3: Policy engine
    const dbRules = await prisma.policyRule.findMany({
      where: { userId, enabled: true },
      orderBy: { priority: "desc" }
    });

    const dbPolicyRules = dbRules as unknown as DbPolicyRuleRow[];

    const policyRules: PolicyRule[] = mergeWithBaseline(
      dbPolicyRules.map((r) => ({
        id: r.id,
        action: r.action as PolicyAction,
        priority: r.priority,
        enabled: r.enabled,
        preset: r.preset,
        condition: r.condition as unknown as PolicyRule["condition"]
      }))
    );

    const policyDecision = evaluatePolicyRules({
      rules: policyRules,
      threat,
      text: body.message,
      fallbackAction: "ALLOW"
    });

    // STEP 4: Context tracker
    let context: ContextTrackerResult;
    try {
      context = await trackContext({ sessionId, currentText: body.message, scan });
    } catch {
      context = { sessionRiskScore: scan.riskScore, escalationDetected: false };
    }

    const scanLatencyMs = Date.now() - scanStart;

    // Apply policy action before reaching the LLM.
    const policyAction = policyDecision.action;

    const apiKey = await getOrCreateDefaultApiKey({ userId });

    // Emit threat feed event (best-effort; failures must not break the API).
    try {
      const snippet = redactPIIFromInput(body.message).redactedText.slice(0, 140);
      await publishThreatEvent({
        time: new Date().toISOString(),
        category: threat.category,
        riskScore: scan.riskScore,
        actionTaken: policyAction,
        redactedInputSnippet: snippet
      });
    } catch {
      // ignore
    }

    if (policyAction === "BLOCK" || policyAction === "QUARANTINE" || policyAction === "RATE_LIMIT") {
      const responseText = "";
      await createAuditLogEntry({
        sessionId,
        userId,
        apiKeyId: apiKey.id,
        inputText: body.message,
        responseText,
        threat,
        action: policyAction,
        latencyMs: Date.now() - start,
        scan,
        arbitration: arbitration ?? undefined
      });

      await updateApiKeyReputation({
        apiKeyId: apiKey.id,
        delta: reputationDelta({ riskScore: scan.riskScore, action: policyAction, personaDrift: false })
      });

      const statusCode = policyAction === "RATE_LIMIT" ? 429 : 403;
      res.status(statusCode).json({
        success: true,
        data: {
          actionTaken: policyAction,
          threat,
          scan,
          contextTracker: context,
          scanLatencyMs,
          llmLatencyMs: 0
        }
      });
      return;
    }

    const inputForLLM =
      policyAction === "REDACT_PII"
        ? redactPIIFromInput(body.message).redactedText
        : body.message;

    // STEP 5: LLM call (service)
    const llm = await generateLLMResponse({ userMessage: inputForLLM, systemPrompt: env.LLM_SYSTEM_PROMPT, sessionId });
    const llmLatencyMs = llm.latencyMs;
    const persona: Awaited<ReturnType<typeof detectPersonaDrift>> = await detectPersonaDrift({ sessionId, llmResponseText: llm.responseText }).catch(() => ({
      driftDetected: false,
      previousPersona: undefined,
      currentPersona: { style: "unknown" as const, claimsCapabilities: false, selfIdentity: "unknown" }
    }));

    // STEP 5 (post-LLM): Output filter
    const output = applyOutputFilter({
      responseText: llm.responseText,
      sessionId,
      scan,
      honeypotCanaryPhrase: llm.honeypotCanaryPhrase
    });
    if (persona.driftDetected) output.result.warningFlags.push("PERSONA_DRIFT");

    // STEP 6: Audit logger (immutable log)
    await createAuditLogEntry({
      sessionId,
      userId,
      apiKeyId: apiKey.id,
      inputText: body.message,
      responseText: output.clientResponseText,
      threat,
      action: policyAction,
      latencyMs: Date.now() - start,
      scan,
      outputFilter: output.result,
      arbitration: arbitration ?? undefined
    });

    await updateApiKeyReputation({
      apiKeyId: apiKey.id,
      delta: reputationDelta({ riskScore: scan.riskScore, action: policyDecision.action, personaDrift: false })
    });

    await updateApiKeyReputation({
      apiKeyId: apiKey.id,
      delta: reputationDelta({ riskScore: scan.riskScore, action: policyAction, personaDrift: persona.driftDetected })
    });

    if (persona.driftDetected) {
      try {
        await publishThreatEvent({
          time: new Date().toISOString(),
          category: "PERSONA_DRIFT",
          riskScore: scan.riskScore,
          actionTaken: "WARN_USER",
          redactedInputSnippet: `Persona drift detected: ${persona.reason ?? "identity/style changed"}`
        });
      } catch {
        // ignore
      }
    }

    res.status(200).json({
      success: true,
      data: {
        actionTaken: policyAction,
        threat,
        scan,
        contextTracker: context,
        outputFilter: output.result,
        response: output.clientResponseText,
        outputFingerprint: output.outputFingerprint,
        scanLatencyMs,
        llmLatencyMs
      }
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Proxy chat failed";
    res.status(400).json({ success: false, error: message });
  }
});

proxyRouter.post("/scan", requireAuth, async (req, res) => {
  try {
    const body = chatBodySchema.parse(req.body);
    const userId = req.user!.userId;
    const sessionId =
      typeof req.headers["x-session-id"] === "string" ? req.headers["x-session-id"] : `user:${req.user!.userId}`;

    const start = Date.now();
    const scanStart = Date.now();

    const scan = scanInput({
      text: clampTextForRedaction(body.message),
      previousMessages: body.history ?? [],
      nowMs: Date.now()
    });

    const threat = classifyThreat({ text: body.message, scan });

    const arbitration = await arbitrateSafety({ scanRiskScore: scan.riskScore, threat });

    const dbRules = await prisma.policyRule.findMany({
      where: { userId, enabled: true },
      orderBy: { priority: "desc" }
    });

    const dbPolicyRules = dbRules as unknown as DbPolicyRuleRow[];
    const policyRules: PolicyRule[] = mergeWithBaseline(
      dbPolicyRules.map((r) => ({
        id: r.id,
        action: r.action as PolicyAction,
        priority: r.priority,
        enabled: r.enabled,
        preset: r.preset,
        condition: r.condition as unknown as PolicyRule["condition"]
      }))
    );

    const policyDecision = evaluatePolicyRules({
      rules: policyRules,
      threat,
      text: body.message,
      fallbackAction: "ALLOW"
    });

    let context: ContextTrackerResult;
    try {
      context = await trackContext({ sessionId, currentText: body.message, scan });
    } catch {
      context = { sessionRiskScore: scan.riskScore, escalationDetected: false };
    }

    const scanLatencyMs = Date.now() - scanStart;

    const apiKey = await getOrCreateDefaultApiKey({ userId });

    try {
      const snippet = redactPIIFromInput(body.message).redactedText.slice(0, 140);
      await publishThreatEvent({
        time: new Date().toISOString(),
        category: threat.category,
        riskScore: scan.riskScore,
        actionTaken: policyDecision.action,
        redactedInputSnippet: snippet
      });
    } catch {
      // ignore
    }

    await createAuditLogEntry({
      sessionId,
      userId,
      apiKeyId: apiKey.id,
      inputText: body.message,
      responseText: "",
      threat,
      action: policyDecision.action,
      latencyMs: Date.now() - start,
      scan,
      arbitration: arbitration ?? undefined
    });

    res.status(200).json({
      success: true,
      data: {
        actionTaken: policyDecision.action,
        threat,
        scan,
        contextTracker: context,
        scanLatencyMs,
        llmLatencyMs: 0
      }
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Proxy scan failed";
    res.status(400).json({ success: false, error: message });
  }
});

