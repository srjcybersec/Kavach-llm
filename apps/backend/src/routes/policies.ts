import { Router } from "express";
import { z } from "zod";
import { prisma } from "../prismaClient.js";
import { requireAuth } from "../middleware/auth.js";
import {
  builtInPresetRules,
  complianceFrameworkRules,
  type ComplianceFrameworkMode,
  type PolicyAction,
  type PolicyCondition
} from "../middleware/policyEngine.js";

/** Replaced when user picks a compliance chip; product preset cards use separate names. */
const COMPLIANCE_PRESET_TAGS = ["GDPR", "HIPAA", "PCI-DSS", "GENERAL"] as const;
const PRODUCT_PRESET_TAGS = ["DefaultSafePolicy", "StrictEnterprisePolicy", "DeveloperPolicy"] as const;

export const policiesRouter = Router();

const policyActionSchema = z.union([
  z.literal("ALLOW"),
  z.literal("BLOCK"),
  z.literal("REDACT_PII"),
  z.literal("WARN_USER"),
  z.literal("RATE_LIMIT"),
  z.literal("QUARANTINE")
]);

const threatCategorySchema = z.union([
  z.literal("SAFE"),
  z.literal("SUSPICIOUS"),
  z.literal("PROMPT_INJECTION"),
  z.literal("JAILBREAK"),
  z.literal("PHISHING"),
  z.literal("SOCIAL_ENGINEERING"),
  z.literal("DATA_EXFILTRATION"),
  z.literal("NSFW"),
  z.literal("HATE_SPEECH"),
  z.literal("MALWARE_REQUEST")
]);

const confidenceExprSchema = z
  .string()
  .regex(/^(>=|<=|>|<)\s*(0(?:\.\d+)?|1(?:\.0+)?)$/i, "Expected operator like >0.7 or >=0.65");

/** Higher than merged baseline rules (~≤200) so custom DB rules win over env baseline. */
const USER_RULE_DEFAULT_PRIORITY = 10_000;
/** Stored preset rows sit above baseline but below hand-authored rules (10_000+). */
const PRESET_DB_PRIORITY_OFFSET = 9000;

const ruleIfSchema = z.object({
  category: threatCategorySchema.optional(),
  confidence: confidenceExprSchema.optional(),
  allowPhrases: z.array(z.string()).optional(),
  denyPhrases: z.array(z.string()).optional(),
  allowDomains: z.array(z.string()).optional(),
  denyDomains: z.array(z.string()).optional()
});

const policyDslSchema = z.object({
  if: ruleIfSchema,
  then: policyActionSchema
});

const createRuleSchema = policyDslSchema.extend({
  priority: z.number().int().min(-10_000).max(100_000).optional().default(USER_RULE_DEFAULT_PRIORITY),
  enabled: z.boolean().optional().default(true),
  preset: z.string().optional()
});

const updateRuleSchema = createRuleSchema.partial().extend({
  priority: z.number().int().min(-10_000).max(100_000).optional(),
  enabled: z.boolean().optional()
});

function normalizeStoredCondition(raw: unknown): PolicyCondition {
  if (!raw || typeof raw !== "object") return {};
  const o = raw as Record<string, unknown>;
  const out: PolicyCondition = {};
  if (typeof o.category === "string") out.category = o.category as PolicyCondition["category"];
  if (o.confidence && typeof o.confidence === "object" && o.confidence !== null) {
    const c = o.confidence as Record<string, unknown>;
    const op = c.op;
    const value = c.value;
    if (
      (op === ">" || op === ">=" || op === "<" || op === "<=") &&
      typeof value === "number" &&
      !Number.isNaN(value)
    ) {
      out.confidence = { op, value };
    }
  }
  if (Array.isArray(o.allowPhrases)) out.allowPhrases = o.allowPhrases.filter((x): x is string => typeof x === "string");
  if (Array.isArray(o.denyPhrases)) out.denyPhrases = o.denyPhrases.filter((x): x is string => typeof x === "string");
  if (Array.isArray(o.allowDomains)) out.allowDomains = o.allowDomains.filter((x): x is string => typeof x === "string");
  if (Array.isArray(o.denyDomains)) out.denyDomains = o.denyDomains.filter((x): x is string => typeof x === "string");
  return out;
}

policiesRouter.get("/", requireAuth, async (req, res) => {
  try {
    const rules = await prisma.policyRule.findMany({
      where: { userId: req.user!.userId },
      orderBy: { priority: "desc" }
    });

    const data = rules.map((r) => ({
      ...r,
      condition: normalizeStoredCondition(r.condition)
    }));

    res.status(200).json({ success: true, data });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to fetch policy rules" });
  }
});

function parseConfidenceExpression(expr: string): PolicyCondition["confidence"] | undefined {
  const m = /^(>=|<=|>|<)\s*(0(?:\.\d+)?|1(?:\.0+)?)$/i.exec(expr.trim());
  if (!m) return undefined;
  const op = m[1] as ">" | ">=" | "<" | "<=";
  const value = Number(m[2]);
  if (Number.isNaN(value)) return undefined;
  return { op: op as ">" | ">=" | "<" | "<=", value };
}

function toCondition(body: z.infer<typeof ruleIfSchema>): PolicyCondition {
  const confidence = typeof body.confidence === "string" ? parseConfidenceExpression(body.confidence) : undefined;
  return {
    category: body.category,
    confidence,
    allowPhrases: body.allowPhrases,
    denyPhrases: body.denyPhrases,
    allowDomains: body.allowDomains,
    denyDomains: body.denyDomains
  };
}

policiesRouter.post("/", requireAuth, async (req, res) => {
  try {
    const body = createRuleSchema.parse(req.body);
    const condition = toCondition(body.if);

    const created = await prisma.policyRule.create({
      data: {
        userId: req.user!.userId,
        condition,
        action: body.then,
        priority: body.priority ?? USER_RULE_DEFAULT_PRIORITY,
        enabled: body.enabled,
        preset: body.preset ?? null
      }
    });

    res.status(201).json({ success: true, data: { ...created, condition: normalizeStoredCondition(created.condition) } });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid policy rule payload" });
      return;
    }
    res.status(500).json({ success: false, error: "Failed to create policy rule" });
  }
});

policiesRouter.patch("/:id", requireAuth, async (req, res) => {
  try {
    const raw = req.params.id;
    const id = (Array.isArray(raw) ? raw[0] : raw) ?? "";
    if (!id) {
      res.status(400).json({ success: false, error: "Missing rule id" });
      return;
    }
    const body = updateRuleSchema.parse(req.body);

    const existing = await prisma.policyRule.findFirst({
      where: { id, userId: req.user!.userId }
    });
    if (!existing) {
      res.status(404).json({ success: false, error: "Policy rule not found" });
      return;
    }

    const conditionUpdate =
      body.if !== undefined ? toCondition(body.if) : existing.condition as unknown as PolicyCondition;

    const updated = await prisma.policyRule.update({
      where: { id },
      data: {
        condition: conditionUpdate,
        action: body.then ?? existing.action,
        priority: body.priority ?? existing.priority,
        enabled: body.enabled ?? existing.enabled,
        preset: body.preset ?? existing.preset
      }
    });

    res.status(200).json({ success: true, data: { ...updated, condition: normalizeStoredCondition(updated.condition) } });
  } catch (err: unknown) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ success: false, error: "Invalid policy rule payload" });
      return;
    }
    res.status(500).json({ success: false, error: "Failed to update policy rule" });
  }
});

policiesRouter.delete("/preset/:name", requireAuth, async (req, res) => {
  try {
    const nameRaw = String(req.params.name ?? "");
    const name =
      nameRaw === "DefaultSafePolicy" || nameRaw === "StrictEnterprisePolicy" || nameRaw === "DeveloperPolicy"
        ? nameRaw
        : null;

    if (!name) {
      res.status(404).json({ success: false, error: "Unknown preset" });
      return;
    }

    const result = await prisma.policyRule.deleteMany({
      where: { userId: req.user!.userId, preset: name }
    });

    res.status(200).json({ success: true, data: { preset: name, removed: result.count } });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to remove preset rules" });
  }
});

policiesRouter.delete("/:id", requireAuth, async (req, res) => {
  try {
    const raw = req.params.id;
    const id = (Array.isArray(raw) ? raw[0] : raw) ?? "";
    if (!id) {
      res.status(400).json({ success: false, error: "Missing rule id" });
      return;
    }
    const result = await prisma.policyRule.deleteMany({
      where: { id, userId: req.user!.userId }
    });
    if (result.count === 0) {
      res.status(404).json({ success: false, error: "Policy rule not found" });
      return;
    }
    res.status(200).json({ success: true, data: { deleted: true } });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to delete policy rule" });
  }
});

policiesRouter.post("/preset/:name", requireAuth, async (req, res) => {
  try {
    const nameRaw = String(req.params.name ?? "");
    const name =
      nameRaw === "DefaultSafePolicy" || nameRaw === "StrictEnterprisePolicy" || nameRaw === "DeveloperPolicy"
        ? nameRaw
        : null;

    if (!name) {
      res.status(404).json({ success: false, error: "Unknown preset" });
      return;
    }

    const presetRules = builtInPresetRules(name);

    await prisma.$transaction([
      prisma.policyRule.deleteMany({
        where: {
          userId: req.user!.userId,
          preset: { in: [...COMPLIANCE_PRESET_TAGS, ...PRODUCT_PRESET_TAGS] }
        }
      }),
      prisma.policyRule.createMany({
        data: presetRules.map((r, idx) => ({
          userId: req.user!.userId,
          condition: r.condition,
          action: r.action,
          priority: PRESET_DB_PRIORITY_OFFSET + r.priority + idx,
          enabled: r.enabled,
          preset: name
        }))
      })
    ]);

    res.status(200).json({ success: true, data: { preset: name, applied: true, ruleCount: presetRules.length } });
  } catch (err: unknown) {
    res.status(500).json({ success: false, error: "Failed to apply preset" });
  }
});

policiesRouter.post("/compliance/:mode", requireAuth, async (req, res) => {
  try {
    const modeParam = String(req.params.mode ?? "");
    const modeUpper = modeParam.toUpperCase();
    const mode: ComplianceFrameworkMode | null =
      modeUpper === "GDPR" || modeUpper === "HIPAA" || modeUpper === "PCI-DSS" || modeUpper === "GENERAL"
        ? modeUpper === "PCI-DSS"
          ? "PCI-DSS"
          : (modeUpper as ComplianceFrameworkMode)
        : null;
    if (!mode) {
      res.status(404).json({ success: false, error: "Unknown compliance mode" });
      return;
    }

    const presetRules = complianceFrameworkRules(mode);

    await prisma.$transaction([
      prisma.policyRule.deleteMany({
        where: {
          userId: req.user!.userId,
          preset: { in: [...COMPLIANCE_PRESET_TAGS, ...PRODUCT_PRESET_TAGS] }
        }
      }),
      prisma.policyRule.createMany({
        data: presetRules.map((r, idx) => ({
          userId: req.user!.userId,
          condition: r.condition,
          action: r.action,
          priority: PRESET_DB_PRIORITY_OFFSET + r.priority + idx,
          enabled: true,
          preset: mode
        }))
      })
    ]);

    res.status(200).json({ success: true, data: { mode, preset: mode, applied: true, ruleCount: presetRules.length } });
  } catch (_err: unknown) {
    res.status(500).json({ success: false, error: "Failed to apply compliance mode" });
  }
});
