import { z } from "zod";

const isTestEnv = process.env.NODE_ENV === "test";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: isTestEnv
    ? z.string().min(1).default("postgresql://user:password@localhost:5432/kavach?schema=public")
    : z.string().min(1),
  REDIS_URL: z.string().min(1).default("redis://localhost:6379"),
  JWT_ACCESS_SECRET: isTestEnv ? z.string().min(32).default("test_access_secret_test_access_secret") : z.string().min(32),
  JWT_REFRESH_SECRET: isTestEnv
    ? z.string().min(32).default("test_refresh_secret_test_refresh_secret")
    : z.string().min(32),
  JWT_ACCESS_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  JWT_REFRESH_TTL_SECONDS: z.coerce.number().int().positive().default(2592000),
  INPUT_MAX_CHARS: z.coerce.number().int().positive().default(12000),
  INPUT_MAX_TOKENS: z.coerce.number().int().positive().default(4096),
  REPETITION_WINDOW_MS: z.coerce.number().int().positive().default(120000),
  REPETITION_MAX_COUNT: z.coerce.number().int().positive().default(3),
  SHADOW_MODE_THREATS: z.coerce.boolean().default(false),
  /**
   * Baseline rules merged before DB `policyRule` rows (DB wins on same/higher priority).
   * `none` = only database rules; empty DB falls through to ALLOW (legacy dev behavior).
   */
  POLICY_BASELINE_PRESET: z.enum(["DefaultSafePolicy", "StrictEnterprisePolicy", "none"]).default("DefaultSafePolicy"),
  THRESHOLD_SAFE: z.coerce.number().min(0).max(1).default(0.5),
  THRESHOLD_SUSPICIOUS: z.coerce.number().min(0).max(1).default(0.6),
  THRESHOLD_PROMPT_INJECTION: z.coerce.number().min(0).max(1).default(0.7),
  THRESHOLD_JAILBREAK: z.coerce.number().min(0).max(1).default(0.7),
  THRESHOLD_PHISHING: z.coerce.number().min(0).max(1).default(0.65),
  THRESHOLD_SOCIAL_ENGINEERING: z.coerce.number().min(0).max(1).default(0.65),
  THRESHOLD_DATA_EXFILTRATION: z.coerce.number().min(0).max(1).default(0.7),
  THRESHOLD_NSFW: z.coerce.number().min(0).max(1).default(0.7),
  THRESHOLD_HATE_SPEECH: z.coerce.number().min(0).max(1).default(0.7),
  THRESHOLD_MALWARE_REQUEST: z.coerce.number().min(0).max(1).default(0.7),

  // Context tracker
  SESSION_INACTIVITY_TTL_SECONDS: z.coerce.number().int().positive().default(1800),
  CONTEXT_WINDOW_N: z.coerce.number().int().positive().max(50).default(6),
  CONTEXT_RISK_ESCALATION_THRESHOLD: z.coerce.number().min(0).max(100).default(70),
  SLOWBURN_AVG_RISK_THRESHOLD: z.coerce.number().min(0).max(100).default(20),
  ATTACK_SIMILARITY_THRESHOLD: z.coerce.number().min(0).max(1).default(0.75),
  ATTACK_EMBEDDING_VECTOR_SIZE: z.coerce.number().int().positive().default(128),

  // LLM — Google Gemini (Generative Language API)
  GEMINI_API_KEY: isTestEnv ? z.string().min(1).default("test_gemini_api_key") : z.string().min(1),
  GEMINI_MODEL: z.string().min(1).default("gemini-2.0-flash"),
  /** 0 = greedy / most repeatable; higher = more random completions (same prompt can differ). */
  GEMINI_TEMPERATURE: z.coerce.number().min(0).max(2).default(0),
  LLM_SYSTEM_PROMPT: z.string().min(1).default("You are a security-focused assistant. Follow system instructions."),
  SOCKET_NAMESPACE: z.string().min(1).default("/socket"),
  THREAT_FEED_CHANNEL: z.string().min(1).default("kavach:threat-events"),
  CORS_ALLOWED_ORIGINS: z.string().min(1).default("http://localhost:5173,http://localhost"),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60000),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(120),
  TRUST_PROXY: z.coerce.boolean().default(true),
  LOG_LEVEL: z.enum(["error", "warn", "info", "debug"]).default("info")
});

export const env = envSchema.parse({
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  DATABASE_URL: process.env.DATABASE_URL,
  REDIS_URL: process.env.REDIS_URL,
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
  JWT_ACCESS_TTL_SECONDS: process.env.JWT_ACCESS_TTL_SECONDS,
  JWT_REFRESH_TTL_SECONDS: process.env.JWT_REFRESH_TTL_SECONDS,
  INPUT_MAX_CHARS: process.env.INPUT_MAX_CHARS,
  INPUT_MAX_TOKENS: process.env.INPUT_MAX_TOKENS,
  REPETITION_WINDOW_MS: process.env.REPETITION_WINDOW_MS,
  REPETITION_MAX_COUNT: process.env.REPETITION_MAX_COUNT,
  SHADOW_MODE_THREATS: process.env.SHADOW_MODE_THREATS,
  POLICY_BASELINE_PRESET: process.env.POLICY_BASELINE_PRESET,
  THRESHOLD_SAFE: process.env.THRESHOLD_SAFE,
  THRESHOLD_SUSPICIOUS: process.env.THRESHOLD_SUSPICIOUS,
  THRESHOLD_PROMPT_INJECTION: process.env.THRESHOLD_PROMPT_INJECTION,
  THRESHOLD_JAILBREAK: process.env.THRESHOLD_JAILBREAK,
  THRESHOLD_PHISHING: process.env.THRESHOLD_PHISHING,
  THRESHOLD_SOCIAL_ENGINEERING: process.env.THRESHOLD_SOCIAL_ENGINEERING,
  THRESHOLD_DATA_EXFILTRATION: process.env.THRESHOLD_DATA_EXFILTRATION,
  THRESHOLD_NSFW: process.env.THRESHOLD_NSFW,
  THRESHOLD_HATE_SPEECH: process.env.THRESHOLD_HATE_SPEECH,
  THRESHOLD_MALWARE_REQUEST: process.env.THRESHOLD_MALWARE_REQUEST,
  SESSION_INACTIVITY_TTL_SECONDS: process.env.SESSION_INACTIVITY_TTL_SECONDS,
  CONTEXT_WINDOW_N: process.env.CONTEXT_WINDOW_N,
  CONTEXT_RISK_ESCALATION_THRESHOLD: process.env.CONTEXT_RISK_ESCALATION_THRESHOLD,
  SLOWBURN_AVG_RISK_THRESHOLD: process.env.SLOWBURN_AVG_RISK_THRESHOLD,
  ATTACK_SIMILARITY_THRESHOLD: process.env.ATTACK_SIMILARITY_THRESHOLD,
  ATTACK_EMBEDDING_VECTOR_SIZE: process.env.ATTACK_EMBEDDING_VECTOR_SIZE,
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  GEMINI_MODEL: process.env.GEMINI_MODEL,
  GEMINI_TEMPERATURE: process.env.GEMINI_TEMPERATURE,
  LLM_SYSTEM_PROMPT: process.env.LLM_SYSTEM_PROMPT,
  SOCKET_NAMESPACE: process.env.SOCKET_NAMESPACE,
  THREAT_FEED_CHANNEL: process.env.THREAT_FEED_CHANNEL,
  CORS_ALLOWED_ORIGINS: process.env.CORS_ALLOWED_ORIGINS,
  RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS,
  RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX,
  TRUST_PROXY: process.env.TRUST_PROXY,
  LOG_LEVEL: process.env.LOG_LEVEL
});

