import type { NextFunction, Request, Response } from "express";
import { env } from "../config.js";
import { scanInput, type ScanInputResult } from "./inputScanner.js";
import {
  scoreThreatCategories,
  thresholdForCategory,
  type ThreatCategory,
  type ThreatScore
} from "../lib/scorer.js";

export type ThreatClassificationResult = {
  category: ThreatCategory;
  confidence: number; // 0..1
  subCategories: string[];
};

function pickCategory(scores: ThreatScore[]): { category: ThreatCategory; confidence: number; subCategories: string[] } {
  const candidates = scores.filter((s) => s.category !== "SAFE");
  // Pick the highest-scoring category that meets its threshold.
  const ordered = candidates.sort((a, b) => b.score - a.score);

  for (const c of ordered) {
    const threshold = thresholdForCategory(c.category);
    if (c.score >= threshold) {
      return { category: c.category, confidence: c.score, subCategories: c.signals.slice(0, 10) };
    }
  }

  const safe = scores.find((s) => s.category === "SAFE");
  return { category: "SAFE", confidence: safe?.score ?? 1, subCategories: [] };
}

export function classifyThreat(params: {
  text: string;
  scan?: ScanInputResult;
  shadowMode?: boolean;
}): ThreatClassificationResult {
  const scan = params.scan;
  const scores = scoreThreatCategories({
    text: params.text,
    scanFlags: scan?.flags,
    piiFound: scan?.piiFound
  });

  const res = pickCategory(scores);

  const shadowMode = params.shadowMode ?? env.SHADOW_MODE_THREATS;
  if (shadowMode && res.category !== "SAFE") {
    // eslint-disable-next-line no-console
    console.warn(
      `[shadow] threat classified as ${res.category} (confidence=${res.confidence.toFixed(2)}) but will be allowed`
    );
  }

  return res;
}

export function threatClassifierMiddleware(req: Request, res: Response, next: NextFunction): void {
  try {
    const possibleText =
      (typeof req.body?.message === "string" && req.body.message) ||
      (typeof req.body?.prompt === "string" && req.body.prompt) ||
      (typeof req.body?.input === "string" && req.body.input) ||
      "";

    const scan: ScanInputResult =
      typeof res.locals.scan?.riskScore === "number"
        ? (res.locals.scan as ScanInputResult)
        : scanInput({ text: possibleText });

    const classification = classifyThreat({ text: possibleText, scan });

    res.locals.threatClassification = classification;
    next();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Threat classification failed";
    res.status(400).json({ success: false, error: message });
  }
}

