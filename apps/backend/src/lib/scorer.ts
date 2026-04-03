import { env } from "../config.js";
import { normalizeForMatching } from "./patterns.js";
import { bestTfidfSimilarity } from "./embeddings.js";
import { getCategoryWeightMultiplier } from "./adaptiveWeights.js";

export type ThreatCategory =
  | "SAFE"
  | "SUSPICIOUS"
  | "PROMPT_INJECTION"
  | "JAILBREAK"
  | "PHISHING"
  | "SOCIAL_ENGINEERING"
  | "DATA_EXFILTRATION"
  | "NSFW"
  | "HATE_SPEECH"
  | "MALWARE_REQUEST";

export type ThreatScore = {
  category: ThreatCategory;
  score: number; // 0..1
  signals: string[];
};

export type ScoreParams = {
  text: string;
  // Optional output from step 1 (input scanner).
  scanFlags?: string[];
  piiFound?: string[];
};

type WeightedPattern = {
  id: string;
  regex: RegExp;
  weight: number; // contribution to raw keyword score
};

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

function keywordScore(input: string, patterns: ReadonlyArray<WeightedPattern>): { score: number; signals: string[] } {
  let raw = 0;
  const max = patterns.reduce((acc, p) => acc + p.weight, 0);
  const signals: string[] = [];

  if (max <= 0) return { score: 0, signals };

  for (const p of patterns) {
    if (p.regex.test(input)) {
      raw += p.weight;
      signals.push(p.id);
    }
  }

  return { score: clamp01(raw / max), signals };
}

function semanticSimilarityScore(category: ThreatCategory, input: string): number {
  const { similarity } = bestTfidfSimilarity({ inputText: input, category });
  return Math.max(0, Math.min(1, similarity));
}

const PROMPT_INJECTION_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "ignore_previous", regex: /\bignore\s+(all\s+)?(previous|earlier)\s+(instructions?|prompts?)\b/i, weight: 0.9 },
  { id: "forget_system_prompt", regex: /\bforget\s+(your\s+)?(system\s+)?prompt\b/i, weight: 0.8 },
  { id: "act_as", regex: /\bact\s+as\b/i, weight: 0.6 },
  { id: "you_are_now", regex: /\byou\s+are\s+now\b/i, weight: 0.6 },
  { id: "pretend_you_are", regex: /\bpretend\s+(you\s+)?are\b/i, weight: 0.6 },
  { id: "dan", regex: /\b(dan)\b/i, weight: 0.4 },
  { id: "jailbreak", regex: /\b(jailbreak|jail\s*break)\b/i, weight: 0.7 }
];

const JAILBREAK_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "dan_style", regex: /\b(dan)\b/i, weight: 0.9 },
  { id: "do_anything_now", regex: /\b(do\s+anything\s+now)\b/i, weight: 0.85 },
  { id: "broken_free", regex: /\bbroken\s+free\b/i, weight: 0.6 },
  { id: "no_restrictions", regex: /\bno\s+restrictions\b/i, weight: 0.45 },
  { id: "unbound_roleplay", regex: /\bfreed from the typical confines\b/i, weight: 0.55 },
  {
    id: "policy_override",
    regex: /\b(do\s+not\s+have\s+to\s+(follow|abide)|don'?t\s+have\s+to\s+follow)\b.*\b(openai|policy)\b/i,
    weight: 0.72
  },
  { id: "censorship_waiver", regex: /\bwithout\s+(any\s+)?censorship\b/i, weight: 0.55 }
];

const PHISHING_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "password_reset", regex: /\b(reset|change)\s+(your\s+)?password\b/i, weight: 0.9 },
  { id: "credential_request", regex: /\b(credential|credentials)\b/i, weight: 0.75 },
  { id: "verify_account", regex: /\b(verify|verification)\s+(your\s+)?account\b/i, weight: 0.65 },
  { id: "urgent_login", regex: /\burgent\b.*\blogin\b|\blogin\b.*\burgent\b/i, weight: 0.5 }
];

const SOCIAL_ENGINEERING_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "security_team_request", regex: /\bsecurity\s+team\b/i, weight: 0.7 },
  { id: "reveal_system_prompt", regex: /\b(reveal|show|leak)\b.*\b(system\s+prompt)\b/i, weight: 0.9 },
  { id: "urgent_request", regex: /\burgent\b/i, weight: 0.55 },
  { id: "need_you_to", regex: /\bneed\s+you\s+to\b/i, weight: 0.5 }
];

const DATA_EXFILTRATION_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "api_key", regex: /\b(api[_\s-]?key|apikey)\b/i, weight: 0.9 },
  { id: "secret_credentials", regex: /\b(secret|credentials|credential)\b/i, weight: 0.75 },
  { id: "internal_admin_credentials", regex: /\binternal\b.*\b(admin\s+credentials|admin)\b/i, weight: 0.7 },
  { id: "pii_exfil", regex: /\b(exfiltrate|leak|dump)\b/i, weight: 0.55 }
];

const NSFW_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "explicit_sex", regex: /\b(sex|porn|nude|nudes|explicit)\b/i, weight: 0.9 },
  { id: "adult_content", regex: /\b(adult)\b/i, weight: 0.5 }
];

const HATE_SPEECH_PATTERNS: ReadonlyArray<WeightedPattern> = [
  // Avoid enumerating specific slurs. Use broad intent keywords.
  { id: "hate_phrase", regex: /\b(hate|racist|bigot)\b/i, weight: 0.7 },
  { id: "dehumanizing", regex: /\b(dehumanize|subhuman)\b/i, weight: 0.65 },
  { id: "violent_hate", regex: /\b(kill|murder)\b.*\b(group|them|those)\b/i, weight: 0.85 }
];

const MALWARE_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "malware", regex: /\b(malware|virus|trojan|worm)\b/i, weight: 0.9 },
  { id: "ransomware", regex: /\bransomware\b/i, weight: 0.75 },
  { id: "exploit", regex: /\b(exploit|payload)\b/i, weight: 0.65 },
  { id: "download_malware", regex: /\b(download|install)\b.*\b(malware|virus)\b/i, weight: 0.55 }
];

const SUSPICIOUS_PATTERNS: ReadonlyArray<WeightedPattern> = [
  { id: "token_stuffing", regex: /\btoken\s+stuffing|too\s+many\s+tokens\b/i, weight: 0.6 },
  { id: "repetition", regex: /\brepeat(ing|ed)?\b/i, weight: 0.4 },
  { id: "prompt_override", regex: /\b(disregard|override)\b.*\b(instructions|policies)\b/i, weight: 0.5 }
];

export function scoreThreatCategories(params: ScoreParams): ThreatScore[] {
  const textNorm = normalizeForMatching(params.text);
  const { scanFlags, piiFound } = params;

  const promptInjectionKW = keywordScore(textNorm, PROMPT_INJECTION_PATTERNS);
  const jailbreakKWRaw = keywordScore(textNorm, JAILBREAK_PATTERNS);
  const phishingKW = keywordScore(textNorm, PHISHING_PATTERNS);
  const socialEngKW = keywordScore(textNorm, SOCIAL_ENGINEERING_PATTERNS);
  const dataExfilKW = keywordScore(textNorm, DATA_EXFILTRATION_PATTERNS);
  const nsfwKW = keywordScore(textNorm, NSFW_PATTERNS);
  const hateKW = keywordScore(textNorm, HATE_SPEECH_PATTERNS);
  const malwareKW = keywordScore(textNorm, MALWARE_PATTERNS);

  // Incorporate step-1 signals when available.
  const scanHasTokenStuffing = Boolean(scanFlags?.includes("TOKEN_STUFFING"));
  const scanHasRepetition = Boolean(scanFlags?.includes("REPETITION_ATTACK"));
  const scanHasPromptInjection = Boolean(scanFlags?.includes("PROMPT_INJECTION"));
  const scanHasObfuscatedInjection = Boolean(scanFlags?.includes("OBFUSCATED_INJECTION"));

  const piiHasAny = (piiFound ?? []).length > 0;
  const piiSignals = piiFound ?? [];

  const dataExfilBoost = piiHasAny ? 0.25 : 0;

  const suspiciousKWBase = keywordScore(textNorm, SUSPICIOUS_PATTERNS);
  const suspiciousKW = {
    score: clamp01(
      suspiciousKWBase.score +
        (scanHasTokenStuffing ? 0.25 : 0) +
        (scanHasRepetition ? 0.25 : 0) +
        ((scanHasPromptInjection || scanHasObfuscatedInjection) ? 0.15 : 0)
    ),
    signals: [
      ...suspiciousKWBase.signals,
      ...(scanHasTokenStuffing ? ["token_stuffing_flag"] : []),
      ...(scanHasRepetition ? ["repetition_flag"] : []),
      ...piiSignals.map((k) => `pii_${k}`)
    ]
  };

  const combine = (category: ThreatCategory, keyword: { score: number; signals: string[] }, extraSignals: string[] = []): ThreatScore => {
    const semantic = semanticSimilarityScore(category, params.text);
    const base = clamp01(keyword.score * 0.75 + semantic * 0.25);
    const score = clamp01(base * getCategoryWeightMultiplier(category));
    return { category, score, signals: [...keyword.signals, ...extraSignals] };
  };

  let jailbreakKW = jailbreakKWRaw;
  if (jailbreakKW.signals.includes("dan_style") && jailbreakKW.signals.includes("do_anything_now")) {
    jailbreakKW = {
      score: Math.max(jailbreakKW.score, 1),
      signals: [...jailbreakKW.signals, "compound_dan_do_anything"]
    };
  } else if (scanHasPromptInjection && jailbreakKWRaw.signals.length > 0) {
    jailbreakKW = {
      score: Math.max(jailbreakKWRaw.score, 0.96),
      signals: [...jailbreakKWRaw.signals, "injection_scan_corroboration"]
    };
  }

  // Classifier text is often still "please decode this base64…" while the attack lives inside the payload.
  // Input scan already proved decoded content matches injection heuristics — surface that here.
  let promptInjectionKWAdjusted = promptInjectionKW;
  if (scanHasObfuscatedInjection) {
    promptInjectionKWAdjusted = {
      score: Math.max(promptInjectionKW.score, 1),
      signals: [...promptInjectionKW.signals, "obfuscated_injection_scan"]
    };
  }

  const scores: ThreatScore[] = [
    combine("PROMPT_INJECTION", promptInjectionKWAdjusted, []),
    combine("JAILBREAK", jailbreakKW, []),
    combine("PHISHING", phishingKW, []),
    combine("SOCIAL_ENGINEERING", socialEngKW, []),
    combine("DATA_EXFILTRATION", { ...dataExfilKW, score: clamp01(dataExfilKW.score + dataExfilBoost) }, piiHasAny ? piiSignals.map((k) => `pii_${k}`) : []),
    combine("NSFW", nsfwKW, []),
    combine("HATE_SPEECH", hateKW, []),
    combine("MALWARE_REQUEST", malwareKW, []),
    combine("SUSPICIOUS", suspiciousKW, scanHasTokenStuffing ? ["token_stuffing_scan"] : [])
  ];

  const maxOther = scores.reduce((acc, s) => Math.max(acc, s.score), 0);
  const safeScore = clamp01(1 - maxOther);

  scores.push({ category: "SAFE", score: safeScore, signals: [] });

  return scores;
}

export function thresholdForCategory(category: ThreatCategory): number {
  switch (category) {
    case "SAFE":
      return env.THRESHOLD_SAFE;
    case "SUSPICIOUS":
      return env.THRESHOLD_SUSPICIOUS;
    case "PROMPT_INJECTION":
      return env.THRESHOLD_PROMPT_INJECTION;
    case "JAILBREAK":
      return env.THRESHOLD_JAILBREAK;
    case "PHISHING":
      return env.THRESHOLD_PHISHING;
    case "SOCIAL_ENGINEERING":
      return env.THRESHOLD_SOCIAL_ENGINEERING;
    case "DATA_EXFILTRATION":
      return env.THRESHOLD_DATA_EXFILTRATION;
    case "NSFW":
      return env.THRESHOLD_NSFW;
    case "HATE_SPEECH":
      return env.THRESHOLD_HATE_SPEECH;
    case "MALWARE_REQUEST":
      return env.THRESHOLD_MALWARE_REQUEST;
    default:
      return 0.5;
  }
}

