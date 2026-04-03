import type { NextFunction, Request, Response } from "express";
import { env } from "../config.js";
import {
  extractBase64Candidates,
  INJECTION_REGEXES,
  luhnCheck,
  PII_REGEXES,
  reverseText,
  safeBase64DecodeToUtf8,
  normalizeForMatching
} from "../lib/patterns.js";

export type ScanInputResult = {
  flags: string[];
  riskScore: number; // 0-100
  piiFound: string[];
};

export type ScanInputParams = {
  text: string;
  previousMessages?: string[];
  previousMessageTimestampsMs?: number[];
  nowMs?: number;
  maxInputChars?: number;
  maxInputTokens?: number;
  repetitionWindowMs?: number;
  repetitionMaxCount?: number;
};

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function approxTokenCount(text: string): number {
  // Simple heuristic: ~4 characters per token.
  return Math.ceil(text.length / 4);
}

function uniqPush(target: string[], value: string): void {
  if (!target.includes(value)) target.push(value);
}

export function scanInput(params: ScanInputParams): ScanInputResult {
  const text = params.text ?? "";
  const nowMs = params.nowMs ?? Date.now();
  const maxInputChars = params.maxInputChars ?? env.INPUT_MAX_CHARS;
  const maxInputTokens = params.maxInputTokens ?? env.INPUT_MAX_TOKENS;
  const repetitionWindowMs = params.repetitionWindowMs ?? env.REPETITION_WINDOW_MS;
  const repetitionMaxCount = params.repetitionMaxCount ?? env.REPETITION_MAX_COUNT;

  const flags: string[] = [];
  const piiFound: string[] = [];
  let score = 0;

  // Normalized variants for robust matching across obfuscation methods.
  const normalized = normalizeForMatching(text);
  const reversedNormalized = reverseText(normalized);

  // STEP: Prompt injection (direct)
  const injectionMatches = INJECTION_REGEXES.filter((p) => p.regex.test(normalized));
  if (injectionMatches.length > 0) {
    uniqPush(flags, "PROMPT_INJECTION");
    // Scale with how many distinct injection heuristics fired (capped). A flat +35 made
    // every minimally matching prompt show the same risk number in the UI.
    score += clampScore(Math.min(78, 14 + injectionMatches.length * 16));
  }

  // STEP: Prompt injection (obfuscated)
  let obfuscatedInjection = false;

  // Base64 detection and decode (then scan decoded text).
  const base64Candidates = extractBase64Candidates(text);
  for (const candidate of base64Candidates) {
    const decoded = safeBase64DecodeToUtf8(candidate);
    if (!decoded) continue;
    const decodedNorm = normalizeForMatching(decoded);
    if (INJECTION_REGEXES.some((p) => p.regex.test(decodedNorm))) {
      obfuscatedInjection = true;
      break;
    }
    if (INJECTION_REGEXES.some((p) => p.regex.test(reverseText(decodedNorm)))) {
      obfuscatedInjection = true;
      break;
    }
  }

  // Reverse-text heuristic.
  if (!obfuscatedInjection && INJECTION_REGEXES.some((p) => p.regex.test(reversedNormalized))) {
    obfuscatedInjection = true;
  }

  if (obfuscatedInjection) {
    uniqPush(flags, "OBFUSCATED_INJECTION");
    score += 50;
  }

  // STEP: Token stuffing
  if (text.length > maxInputChars || approxTokenCount(text) > maxInputTokens) {
    uniqPush(flags, "TOKEN_STUFFING");
    score += 25;
  }

  // STEP: PII detection
  for (const p of PII_REGEXES) {
    const matches = text.match(p.regex) ?? [];
    if (matches.length === 0) continue;

    if (p.key === "CREDIT_CARD") {
      // Validate via Luhn to reduce false positives.
      const cardDigits = matches
        .map((m) => m.replace(/\D/g, ""))
        .filter((d) => d.length >= 13 && d.length <= 19 && luhnCheck(d));

      if (cardDigits.length > 0) {
        uniqPush(piiFound, "CREDIT_CARD");
        uniqPush(flags, "PII_CREDIT_CARD");
        score += 20;
      }
      continue;
    }

    if (p.key === "AADHAAR") {
      // Aadhaar is 12 digits; ensure match after removing spaces.
      const cleaned = matches.map((m) => m.replace(/\s/g, ""));
      if (cleaned.some((d) => /^\d{12}$/.test(d))) {
        uniqPush(piiFound, "AADHAAR");
        uniqPush(flags, "PII_AADHAAR");
        score += 20;
      }
      continue;
    }

    // Other patterns: use presence as signal.
    uniqPush(piiFound, p.key);
    uniqPush(flags, `PII_${p.key}`);
    score += 20;
  }

  // STEP: Repetition attacks
  const prevMessages = params.previousMessages ?? [];
  const prevTimestamps = params.previousMessageTimestampsMs ?? [];
  const currentNormalized = normalized;

  let repetitionCount = 1; // include current
  if (prevMessages.length > 0) {
    if (prevTimestamps.length === prevMessages.length) {
      for (let i = 0; i < prevMessages.length; i += 1) {
        const ts = prevTimestamps[i] ?? 0;
        if (nowMs - ts > repetitionWindowMs) continue;
        if (normalizeForMatching(prevMessages[i] ?? "") === currentNormalized) {
          repetitionCount += 1;
        }
      }
    } else {
      // No timestamps: treat provided previousMessages as already in-window.
      for (const prev of prevMessages) {
        if (normalizeForMatching(prev ?? "") === currentNormalized) repetitionCount += 1;
      }
    }
  }

  if (repetitionCount > repetitionMaxCount) {
    uniqPush(flags, "REPETITION_ATTACK");
    score += 20;
  }

  return {
    flags,
    riskScore: clampScore(score),
    piiFound
  };
}

export function inputScannerMiddleware(req: Request, res: Response, next: NextFunction): void {
  try {
    const possibleText =
      (typeof req.body?.message === "string" && req.body.message) ||
      (typeof req.body?.prompt === "string" && req.body.prompt) ||
      (typeof req.body?.input === "string" && req.body.input) ||
      "";

    const body = req.body as unknown;
    let previousMessages: string[] = [];
    if (typeof body === "object" && body !== null) {
      const maybeHistory = (body as { history?: unknown }).history;
      if (Array.isArray(maybeHistory)) {
        previousMessages = maybeHistory.filter((m): m is string => typeof m === "string");
      }
    }

    const scan = scanInput({
      text: possibleText,
      previousMessages
    });

    // Pipeline later can pick it up from res.locals.
    res.locals.scan = scan;
    next();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Input scan failed";
    res.status(400).json({ success: false, error: message });
  }
}

