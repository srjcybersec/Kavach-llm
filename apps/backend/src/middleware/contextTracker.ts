import type { NextFunction, Request, Response } from "express";
import crypto from "crypto";
import { env } from "../config.js";
import { getRedisClient } from "../services/redisService.js";
import type { ScanInputResult } from "./inputScanner.js";
import { normalizeForMatching } from "../lib/patterns.js";

export type ContextTrackerResult = {
  sessionRiskScore: number; // 0..100
  escalationDetected: boolean;
  patternName?: string;
};

type SessionState = {
  riskScore: number;
  messageCount: number;
  lastActiveAt: number;
};

const SESSION_KEY_PREFIX = "kavach:session:";
const SESSION_RISK_KEY_SUFFIX = ":risk";

type AttackSignature = {
  id: string;
  text: string;
};

const ATTACK_SIGNATURES: ReadonlyArray<AttackSignature> = [
  { id: "prompt_injection", text: "ignore previous instructions system prompt" },
  { id: "jailbreak", text: "dan do anything now jailbreak break free" },
  { id: "system_prompt_extraction", text: "reveal your system prompt" },
  { id: "data_exfiltration", text: "api key secret credentials admin password" }
];

let attackEmbeddingCache: Record<string, number[]> | null = null;
let attackEmbeddingCacheVectorSize: number | null = null;

function clampRisk(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function tokenize(text: string): string[] {
  return normalizeForMatching(text).match(/[a-z0-9]+/g) ?? [];
}

function stableHashToIndex(token: string, vectorSize: number): number {
  const hex = crypto.createHash("sha256").update(token).digest("hex");
  // Use first 8 chars to fit into 32-bit.
  const num = Number.parseInt(hex.slice(0, 8), 16);
  return num % vectorSize;
}

function embedText(text: string, vectorSize: number): number[] {
  const vec = new Array(vectorSize).fill(0);
  const tokens = tokenize(text);
  if (tokens.length === 0) return vec;

  for (const t of tokens) {
    const idx = stableHashToIndex(t, vectorSize);
    vec[idx] += 1;
  }

  // Normalize to unit length for cosine similarity.
  let norm2 = 0;
  for (const v of vec) norm2 += v * v;
  const norm = Math.sqrt(norm2);
  if (norm === 0) return vec;
  return vec.map((v) => v / norm);
}

function cosineFromNormalized(vecA: number[], vecB: number[]): number {
  let dot = 0;
  const len = Math.min(vecA.length, vecB.length);
  for (let i = 0; i < len; i += 1) {
    const a = vecA[i];
    const b = vecB[i];
    if (typeof a === "number" && typeof b === "number") dot += a * b;
  }
  return dot;
}

async function ensureAttackEmbeddings(vectorSize: number): Promise<Record<string, number[]>> {
  if (attackEmbeddingCache && attackEmbeddingCacheVectorSize === vectorSize) return attackEmbeddingCache;

  const redis = await getRedisClient();
  const nextCache: Record<string, number[]> = {};

  for (const sig of ATTACK_SIGNATURES) {
    const key = `kavach:attack-emb:${sig.id}:${vectorSize}`;
    const existing = await redis.get(key);
    if (existing) {
      try {
        const parsed = JSON.parse(existing) as unknown;
        if (Array.isArray(parsed) && parsed.every((n) => typeof n === "number")) {
          nextCache[sig.id] = parsed;
          continue;
        }
      } catch {
        // ignore cache parse errors
      }
    }

    const emb = embedText(sig.text, vectorSize);
    nextCache[sig.id] = emb;
    // Best-effort persistence to Redis.
    await redis.set(key, JSON.stringify(emb), { EX: env.SESSION_INACTIVITY_TTL_SECONDS });
  }

  attackEmbeddingCache = nextCache;
  attackEmbeddingCacheVectorSize = vectorSize;
  return nextCache;
}

export async function trackContext(params: {
  sessionId: string;
  currentText: string;
  scan?: ScanInputResult;
  nowMs?: number;
}): Promise<ContextTrackerResult> {
  const nowMs = params.nowMs ?? Date.now();
  const maxWindowN = env.CONTEXT_WINDOW_N;
  const ttlSeconds = env.SESSION_INACTIVITY_TTL_SECONDS;
  const escalationThreshold = env.CONTEXT_RISK_ESCALATION_THRESHOLD;

  const turnRisk = params.scan?.riskScore ?? 0;
  const vectorSize = env.ATTACK_EMBEDDING_VECTOR_SIZE;

  const redis = await getRedisClient();
  const sessionKey = `${SESSION_KEY_PREFIX}${params.sessionId}`;
  const riskKey = `${sessionKey}${SESSION_RISK_KEY_SUFFIX}`;

  const rawSession = await redis.get(sessionKey);
  let session: SessionState = { riskScore: 0, messageCount: 0, lastActiveAt: nowMs };
  if (rawSession) {
    try {
      const parsed = JSON.parse(rawSession) as unknown;
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "riskScore" in parsed &&
        "messageCount" in parsed &&
        "lastActiveAt" in parsed
      ) {
        const pr = parsed as { riskScore: unknown; messageCount: unknown; lastActiveAt: unknown };
        const riskScore = typeof pr.riskScore === "number" ? pr.riskScore : 0;
        const messageCount = typeof pr.messageCount === "number" ? pr.messageCount : 0;
        const lastActiveAt = typeof pr.lastActiveAt === "number" ? pr.lastActiveAt : nowMs;
        session = { riskScore, messageCount, lastActiveAt };
      }
    } catch {
      // ignore invalid session state
    }
  }

  const attackEmbeddings = await ensureAttackEmbeddings(vectorSize);
  const currentEmb = embedText(params.currentText, vectorSize);

  let maxSimilarity = 0;
  let bestSigId: string | undefined;
  for (const [sigId, emb] of Object.entries(attackEmbeddings)) {
    const sim = cosineFromNormalized(currentEmb, emb);
    if (sim > maxSimilarity) {
      maxSimilarity = sim;
      bestSigId = sigId;
    }
  }

  // Accumulate session risk using step-1 risk + similarity signal.
  const similarityContribution = maxSimilarity * 30;
  const turnContribution = turnRisk * 0.25;
  const nextRiskScore = clampRisk(session.riskScore + turnContribution + similarityContribution);

  // Rolling risk history for slow-burn detection.
  const prevHistory = await redis.lRange(riskKey, 0, maxWindowN - 2);
  const prevRisks = prevHistory
    .map((v) => Number(v))
    .filter((n): n is number => Number.isFinite(n) && n >= 0);
  const historyIncludingCurrent = [...prevRisks, turnRisk].slice(0, maxWindowN);
  const avgRisk = historyIncludingCurrent.length > 0 ? historyIncludingCurrent.reduce((a, b) => a + b, 0) / historyIncludingCurrent.length : 0;

  const slowBurnEscalation = avgRisk >= env.SLOWBURN_AVG_RISK_THRESHOLD;
  const similarityEscalation = maxSimilarity >= env.ATTACK_SIMILARITY_THRESHOLD;

  const escalationDetected = nextRiskScore >= escalationThreshold || (slowBurnEscalation && similarityEscalation);

  if (escalationDetected && similarityEscalation && bestSigId) {
    // Note: patternName is used for UI feed highlighting.
  }

  const multi = redis.multi();
  const nextSession: SessionState = {
    riskScore: nextRiskScore,
    messageCount: session.messageCount + 1,
    lastActiveAt: nowMs
  };

  multi.set(sessionKey, JSON.stringify(nextSession), { EX: ttlSeconds });
  multi.lPush(riskKey, String(turnRisk));
  multi.lTrim(riskKey, 0, maxWindowN - 1);
  multi.expire(riskKey, ttlSeconds);
  await multi.exec();

  return {
    sessionRiskScore: nextRiskScore,
    escalationDetected,
    patternName: escalationDetected && similarityEscalation && bestSigId ? bestSigId : undefined
  };
}

export async function contextTrackerMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  const possibleSessionId =
    typeof req.headers["x-session-id"] === "string"
      ? req.headers["x-session-id"]
      : req.user?.userId
        ? `user:${req.user.userId}`
        : undefined;

  const sessionId = possibleSessionId ?? "anonymous";
  const scan = res.locals.scan;

  try {
    const currentText =
      (typeof req.body?.message === "string" && req.body.message) ||
      (typeof req.body?.prompt === "string" && req.body.prompt) ||
      (typeof req.body?.input === "string" && req.body.input) ||
      "";

    const tracked = await trackContext({ sessionId, currentText, scan });
    res.locals.contextTracker = tracked;
    next();
  } catch (_err: unknown) {
    // Fallback: allow pipeline progress even if Redis is unavailable.
    const fallbackRisk = scan?.riskScore ?? 0;
    res.locals.contextTracker = { sessionRiskScore: fallbackRisk, escalationDetected: fallbackRisk >= env.CONTEXT_RISK_ESCALATION_THRESHOLD };
    next();
  }
}

