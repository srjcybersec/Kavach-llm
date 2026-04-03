import type { ThreatClassificationResult } from "../middleware/threatClassifier.js";

export type ArbitrationResult = {
  primaryCategory: string;
  secondaryCategory: string;
  agree: boolean;
};

// Stub for multi-model arbitration (F4).
// Later commits can replace this with OpenAI moderation or a local model.
export async function arbitrateSafety(params: {
  scanRiskScore: number; // 0..100
  threat: ThreatClassificationResult;
}): Promise<ArbitrationResult | null> {
  if (params.scanRiskScore <= 80) return null;

  const primaryCategory = params.threat.category;

  // Deterministic stub: introduce a disagreement for very high-risk inputs.
  const secondaryCategory =
    params.scanRiskScore >= 95 && primaryCategory !== "SAFE" ? "SUSPICIOUS" : primaryCategory;

  const agree = secondaryCategory === primaryCategory;

  return { primaryCategory, secondaryCategory, agree };
}

