import type { ThreatClassificationResult } from "./threatClassifier.js";

export type PolicyAction = "ALLOW" | "BLOCK" | "REDACT_PII" | "WARN_USER" | "RATE_LIMIT" | "QUARANTINE";

export type ConfidenceOperator = ">" | ">=" | "<" | "<=";

export type ConfidenceExpression = {
  op: ConfidenceOperator;
  value: number; // 0..1
};

export type PolicyCondition = {
  category?: ThreatClassificationResult["category"];
  confidence?: ConfidenceExpression;
  allowPhrases?: string[];
  denyPhrases?: string[];
  allowDomains?: string[];
  denyDomains?: string[];
};

export type PolicyRule = {
  id: string;
  action: PolicyAction;
  priority: number;
  enabled: boolean;
  condition: PolicyCondition;
  preset?: string | null;
};

export type PolicyEvaluationResult = {
  action: PolicyAction;
  matchedRuleId?: string;
};

function parseConfidenceExpression(expr: string): ConfidenceExpression | null {
  const trimmed = expr.trim();
  const m = /^(>=|<=|>|<)\s*(0(?:\.\d+)?|1(?:\.0+)?)$/i.exec(trimmed);
  if (!m) return null;
  const opRaw = m[1];
  const valueRaw = m[2];
  if (typeof opRaw !== "string" || typeof valueRaw !== "string") return null;
  const op = opRaw as ConfidenceOperator;
  const value = Number(valueRaw);
  if (Number.isNaN(value) || value < 0 || value > 1) return null;
  return { op, value };
}

function evalConfidence(input: number, expr: ConfidenceExpression): boolean {
  switch (expr.op) {
    case ">":
      return input > expr.value;
    case ">=":
      return input >= expr.value;
    case "<":
      return input < expr.value;
    case "<=":
      return input <= expr.value;
    default:
      return false;
  }
}

function containsAnyPhrase(haystack: string, phrases: string[]): boolean {
  const lower = haystack.toLowerCase();
  return phrases.some((p) => p.trim().length > 0 && lower.includes(p.trim().toLowerCase()));
}

function extractDomains(text: string): string[] {
  // Extract domains from emails and URLs (very lightweight heuristic).
  const domains: string[] = [];
  const emailRe = /[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi;
  const urlRe = /\bhttps?:\/\/([A-Z0-9.-]+\.[A-Z]{2,})(?:\/|[\s"'`]|$)/gi;

  for (const m of text.matchAll(emailRe)) {
    const d = m[1];
    if (typeof d === "string") domains.push(d.toLowerCase());
  }
  for (const m of text.matchAll(urlRe)) {
    const d = m[1];
    if (typeof d === "string") domains.push(d.toLowerCase());
  }
  return Array.from(new Set(domains));
}

function conditionMatches(condition: PolicyCondition, input: { threat: ThreatClassificationResult; text: string }): boolean {
  if (condition.category) {
    if (condition.category !== input.threat.category) return false;
  }

  if (condition.confidence) {
    if (!evalConfidence(input.threat.confidence, condition.confidence)) return false;
  }

  if (condition.allowPhrases && condition.allowPhrases.length > 0) {
    if (!containsAnyPhrase(input.text, condition.allowPhrases)) return false;
  }
  if (condition.denyPhrases && condition.denyPhrases.length > 0) {
    if (!containsAnyPhrase(input.text, condition.denyPhrases)) return false;
  }

  const inputDomains = extractDomains(input.text);
  if (condition.allowDomains && condition.allowDomains.length > 0) {
    const allowSet = new Set(condition.allowDomains.map((d) => d.toLowerCase()));
    if (!inputDomains.some((d) => allowSet.has(d))) return false;
  }
  if (condition.denyDomains && condition.denyDomains.length > 0) {
    const denySet = new Set(condition.denyDomains.map((d) => d.toLowerCase()));
    if (!inputDomains.some((d) => denySet.has(d))) return false;
  }

  return true;
}

export function evaluatePolicyRules(params: {
  rules: PolicyRule[];
  threat: ThreatClassificationResult;
  text: string;
  fallbackAction?: PolicyAction;
}): PolicyEvaluationResult {
  const enabled = params.rules.filter((r) => r.enabled);
  const ordered = enabled.sort((a, b) => b.priority - a.priority);

  for (const rule of ordered) {
    if (conditionMatches(rule.condition, { threat: params.threat, text: params.text })) {
      return { action: rule.action, matchedRuleId: rule.id };
    }
  }

  return { action: params.fallbackAction ?? "ALLOW" };
}

function dslToCondition(input: {
  if: {
    category?: ThreatClassificationResult["category"];
    confidence?: string;
    allowPhrases?: string[];
    denyPhrases?: string[];
    allowDomains?: string[];
    denyDomains?: string[];
  };
}): PolicyCondition {
  const cond = input.if;
  return {
    category: cond.category,
    confidence: typeof cond.confidence === "string" ? parseConfidenceExpression(cond.confidence) ?? undefined : undefined,
    allowPhrases: cond.allowPhrases,
    denyPhrases: cond.denyPhrases,
    allowDomains: cond.allowDomains,
    denyDomains: cond.denyDomains
  };
}

/** Regulatory-style bundles for the Policies “compliance” chips (LLM-gateway interpretation, not legal advice). */
export type ComplianceFrameworkMode = "GDPR" | "HIPAA" | "PCI-DSS" | "GENERAL";

function rulesForPreset(
  presetName: string,
  defs: Array<{
    id: string;
    action: PolicyAction;
    priority: number;
    if: Parameters<typeof dslToCondition>[0]["if"];
  }>
): PolicyRule[] {
  return defs.map((d) => ({
    id: d.id,
    action: d.action,
    priority: d.priority,
    enabled: true,
    preset: presetName,
    condition: dslToCondition({ if: d.if })
  }));
}

/**
 * Distinct rule packs aligned to typical control themes:
 * - **GDPR**: personal data / unauthorized disclosure / phishing & social engineering as data-collection risk.
 * - **HIPAA**: PHI-style minimization, pretexting, stricter exfiltration thresholds.
 * - **PCI-DSS**: malware, exfiltration (cardholder/credential patterns), phishing.
 * - **GENERAL**: same shape as DefaultSafePolicy, tagged as GENERAL for the UI.
 */
export function complianceFrameworkRules(mode: ComplianceFrameworkMode): PolicyRule[] {
  switch (mode) {
    case "GENERAL":
      return rulesForPreset("GENERAL", [
        {
          id: "general_prompt_injection",
          action: "BLOCK",
          priority: 100,
          if: { category: "PROMPT_INJECTION", confidence: ">0.7" }
        },
        { id: "general_jailbreak", action: "BLOCK", priority: 95, if: { category: "JAILBREAK", confidence: ">0.7" } },
        {
          id: "general_data_exfil",
          action: "REDACT_PII",
          priority: 88,
          if: { category: "DATA_EXFILTRATION", confidence: ">0.7" }
        },
        {
          id: "general_phishing_warn",
          action: "WARN_USER",
          priority: 62,
          if: { category: "PHISHING", confidence: ">0.65" }
        },
        {
          id: "general_social_eng_warn",
          action: "WARN_USER",
          priority: 58,
          if: { category: "SOCIAL_ENGINEERING", confidence: ">0.65" }
        }
      ]);
    case "GDPR":
      return rulesForPreset("GDPR", [
        {
          id: "gdpr_data_exfil",
          action: "QUARANTINE",
          priority: 120,
          if: { category: "DATA_EXFILTRATION", confidence: ">0.6" }
        },
        {
          id: "gdpr_phishing",
          action: "BLOCK",
          priority: 115,
          if: { category: "PHISHING", confidence: ">0.55" }
        },
        {
          id: "gdpr_social_eng",
          action: "BLOCK",
          priority: 112,
          if: { category: "SOCIAL_ENGINEERING", confidence: ">0.58" }
        },
        {
          id: "gdpr_prompt_injection",
          action: "BLOCK",
          priority: 108,
          if: { category: "PROMPT_INJECTION", confidence: ">0.65" }
        },
        { id: "gdpr_jailbreak", action: "BLOCK", priority: 105, if: { category: "JAILBREAK", confidence: ">0.65" } },
        { id: "gdpr_malware", action: "BLOCK", priority: 100, if: { category: "MALWARE_REQUEST", confidence: ">0.65" } },
        { id: "gdpr_hate", action: "BLOCK", priority: 85, if: { category: "HATE_SPEECH", confidence: ">0.65" } },
        {
          id: "gdpr_nsfw",
          action: "WARN_USER",
          priority: 72,
          if: { category: "NSFW", confidence: ">0.65" }
        },
        { id: "gdpr_suspicious_rl", action: "RATE_LIMIT", priority: 55, if: { category: "SUSPICIOUS", confidence: ">0.55" } }
      ]);
    case "HIPAA":
      return rulesForPreset("HIPAA", [
        {
          id: "hipaa_data_exfil",
          action: "QUARANTINE",
          priority: 125,
          if: { category: "DATA_EXFILTRATION", confidence: ">0.5" }
        },
        {
          id: "hipaa_phishing",
          action: "BLOCK",
          priority: 118,
          if: { category: "PHISHING", confidence: ">0.5" }
        },
        {
          id: "hipaa_social_eng",
          action: "QUARANTINE",
          priority: 116,
          if: { category: "SOCIAL_ENGINEERING", confidence: ">0.55" }
        },
        {
          id: "hipaa_prompt_injection",
          action: "BLOCK",
          priority: 110,
          if: { category: "PROMPT_INJECTION", confidence: ">0.6" }
        },
        { id: "hipaa_jailbreak", action: "BLOCK", priority: 108, if: { category: "JAILBREAK", confidence: ">0.6" } },
        { id: "hipaa_malware", action: "BLOCK", priority: 102, if: { category: "MALWARE_REQUEST", confidence: ">0.6" } },
        { id: "hipaa_nsfw", action: "BLOCK", priority: 95, if: { category: "NSFW", confidence: ">0.55" } },
        { id: "hipaa_hate", action: "BLOCK", priority: 90, if: { category: "HATE_SPEECH", confidence: ">0.6" } },
        { id: "hipaa_suspicious_rl", action: "RATE_LIMIT", priority: 52, if: { category: "SUSPICIOUS", confidence: ">0.5" } }
      ]);
    case "PCI-DSS":
      return rulesForPreset("PCI-DSS", [
        { id: "pci_malware", action: "BLOCK", priority: 122, if: { category: "MALWARE_REQUEST", confidence: ">0.55" } },
        {
          id: "pci_data_exfil",
          action: "QUARANTINE",
          priority: 118,
          if: { category: "DATA_EXFILTRATION", confidence: ">0.6" }
        },
        {
          id: "pci_phishing",
          action: "BLOCK",
          priority: 115,
          if: { category: "PHISHING", confidence: ">0.5" }
        },
        {
          id: "pci_prompt_injection",
          action: "BLOCK",
          priority: 110,
          if: { category: "PROMPT_INJECTION", confidence: ">0.65" }
        },
        { id: "pci_jailbreak", action: "BLOCK", priority: 108, if: { category: "JAILBREAK", confidence: ">0.65" } },
        {
          id: "pci_social_eng",
          action: "WARN_USER",
          priority: 82,
          if: { category: "SOCIAL_ENGINEERING", confidence: ">0.58" }
        },
        { id: "pci_hate", action: "BLOCK", priority: 75, if: { category: "HATE_SPEECH", confidence: ">0.65" } },
        { id: "pci_suspicious_rl", action: "RATE_LIMIT", priority: 58, if: { category: "SUSPICIOUS", confidence: ">0.58" } },
        { id: "pci_nsfw", action: "WARN_USER", priority: 50, if: { category: "NSFW", confidence: ">0.7" } }
      ]);
    default:
      return complianceFrameworkRules("GENERAL");
  }
}

export function builtInPresetRules(presetName: "DefaultSafePolicy" | "StrictEnterprisePolicy" | "DeveloperPolicy"): PolicyRule[] {
  const nowRules = (defs: Array<{
    id: string;
    action: PolicyAction;
    priority: number;
    if: Parameters<typeof dslToCondition>[0]["if"];
  }>): PolicyRule[] => rulesForPreset(presetName, defs);

  switch (presetName) {
    case "DefaultSafePolicy":
      return nowRules([
        {
          id: "default_prompt_injection",
          action: "BLOCK",
          priority: 100,
          if: { category: "PROMPT_INJECTION", confidence: ">0.7" }
        },
        { id: "default_jailbreak", action: "BLOCK", priority: 95, if: { category: "JAILBREAK", confidence: ">0.7" } },
        {
          id: "default_data_exfil",
          action: "REDACT_PII",
          priority: 80,
          if: { category: "DATA_EXFILTRATION", confidence: ">0.7" }
        },
        {
          id: "default_phishing_warn",
          action: "WARN_USER",
          priority: 60,
          if: { category: "PHISHING", confidence: ">0.65" }
        },
        {
          id: "default_social_eng_warn",
          action: "WARN_USER",
          priority: 55,
          if: { category: "SOCIAL_ENGINEERING", confidence: ">0.65" }
        }
      ]);
    case "StrictEnterprisePolicy":
      return nowRules([
        {
          id: "strict_prompt_injection",
          action: "BLOCK",
          priority: 110,
          if: { category: "PROMPT_INJECTION", confidence: ">0.7" }
        },
        { id: "strict_jailbreak", action: "BLOCK", priority: 105, if: { category: "JAILBREAK", confidence: ">0.7" } },
        { id: "strict_malware", action: "BLOCK", priority: 100, if: { category: "MALWARE_REQUEST", confidence: ">0.7" } },
        { id: "strict_phishing", action: "BLOCK", priority: 90, if: { category: "PHISHING", confidence: ">0.65" } },
        {
          id: "strict_social_eng",
          action: "WARN_USER",
          priority: 75,
          if: { category: "SOCIAL_ENGINEERING", confidence: ">0.65" }
        },
        {
          id: "strict_data_exfil",
          action: "QUARANTINE",
          priority: 88,
          if: { category: "DATA_EXFILTRATION", confidence: ">0.7" }
        },
        { id: "strict_hate", action: "BLOCK", priority: 70, if: { category: "HATE_SPEECH", confidence: ">0.7" } },
        { id: "strict_nsfw", action: "WARN_USER", priority: 65, if: { category: "NSFW", confidence: ">0.7" } },
        { id: "strict_suspicious_rl", action: "RATE_LIMIT", priority: 50, if: { category: "SUSPICIOUS", confidence: ">0.6" } }
      ]);
    case "DeveloperPolicy":
      return nowRules([
        { id: "dev_prompt_injection_allow", action: "WARN_USER", priority: 40, if: { category: "PROMPT_INJECTION", confidence: ">0.7" } },
        { id: "dev_jailbreak_warn", action: "WARN_USER", priority: 38, if: { category: "JAILBREAK", confidence: ">0.7" } },
        { id: "dev_data_exfil_redact", action: "REDACT_PII", priority: 35, if: { category: "DATA_EXFILTRATION", confidence: ">0.7" } }
      ]);
  }
}

