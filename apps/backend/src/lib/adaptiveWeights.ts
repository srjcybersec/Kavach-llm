import type { ThreatCategory } from "./scorer.js";

type FeedbackKind = "false_positive" | "false_negative";

const categoryMultipliers = new Map<ThreatCategory, number>();

function clampMultiplier(v: number): number {
  return Math.max(0.5, Math.min(1.8, Number(v.toFixed(4))));
}

export function getCategoryWeightMultiplier(category: ThreatCategory): number {
  return categoryMultipliers.get(category) ?? 1;
}

export function applyFeedbackToCategoryWeight(params: {
  originalCategory: ThreatCategory;
  correctedCategory: ThreatCategory;
  kind: FeedbackKind;
}): void {
  const { originalCategory, correctedCategory, kind } = params;
  const step = 0.06;

  if (kind === "false_positive") {
    const curr = getCategoryWeightMultiplier(originalCategory);
    categoryMultipliers.set(originalCategory, clampMultiplier(curr - step));
    return;
  }

  // false_negative: boost corrected category, slightly lower original if different.
  const correctedCurr = getCategoryWeightMultiplier(correctedCategory);
  categoryMultipliers.set(correctedCategory, clampMultiplier(correctedCurr + step));

  if (originalCategory !== correctedCategory) {
    const originalCurr = getCategoryWeightMultiplier(originalCategory);
    categoryMultipliers.set(originalCategory, clampMultiplier(originalCurr - step / 2));
  }
}

export function currentAdaptiveWeightState(): Array<{ category: ThreatCategory; multiplier: number }> {
  return Array.from(categoryMultipliers.entries()).map(([category, multiplier]) => ({ category, multiplier }));
}

