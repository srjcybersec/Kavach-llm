export const ZERO_WIDTH_CHARS_REGEX = /[\u200B-\u200D\u2060\uFEFF]/g;

// Minimal homoglyph normalisation for common confusable characters.
// This is intentionally conservative to reduce false positives.
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic -> Latin (common confusables)
  а: "a",
  б: "b",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  т: "t",
  у: "y",
  х: "x",
  А: "A",
  Е: "E",
  О: "O",
  Р: "P",
  С: "C",
  Т: "T",
  У: "Y",
  Х: "X"
};

export function normalizeHomoglyphs(input: string): string {
  return Object.keys(HOMOGLYPHS).reduce((acc, k) => acc.split(k).join(HOMOGLYPHS[k] ?? k), input);
}

export function removeZeroWidth(input: string): string {
  return input.replace(ZERO_WIDTH_CHARS_REGEX, "");
}

const LEET_MAP: ReadonlyArray<[RegExp, string]> = [
  [/[0О]/g, "o"],
  [/[1IіІ]/g, "i"],
  [/3/g, "e"],
  [/[4A]/g, "a"],
  [/5/g, "s"],
  [/7/g, "t"],
  [/8/g, "b"]
];

export function normalizeLeetspeak(input: string): string {
  return LEET_MAP.reduce((acc, [re, to]) => acc.replace(re, to), input);
}

export function normalizeForMatching(input: string): string {
  // Lowercase + remove zero-width + homoglyph + leetspeak.
  const lowered = input.toLowerCase();
  const noZW = removeZeroWidth(lowered);
  const homoglyphs = Object.keys(HOMOGLYPHS).reduce((acc, k) => acc.split(k).join(HOMOGLYPHS[k]), noZW);
  return normalizeLeetspeak(homoglyphs);
}

export function reverseText(input: string): string {
  return input.split("").reverse().join("");
}

export function extractBase64Candidates(input: string): string[] {
  // Look for reasonably long base64-like segments.
  const re = /(?:[A-Za-z0-9+/]{20,}={0,2})/g;
  return input.match(re) ?? [];
}

export function safeBase64DecodeToUtf8(candidate: string): string | null {
  try {
    // Node Buffer is available in backend runtime.
    const buf = Buffer.from(candidate, "base64");
    const decoded = buf.toString("utf8");
    // Quick sanity check: decoded should contain some printable chars.
    if (decoded.trim().length < 5) return null;
    return decoded;
  } catch {
    return null;
  }
}

export function luhnCheck(digits: string): boolean {
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    const d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    let add = d;
    if (shouldDouble) {
      add = d * 2;
      if (add > 9) add -= 9;
    }
    sum += add;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export const INJECTION_REGEXES: ReadonlyArray<{ key: string; regex: RegExp }> = [
  { key: "ignore_previous", regex: /\bignore\s+(all\s+)?(previous|earlier)\s+(instructions?|prompts?)\b/i },
  { key: "forget_system", regex: /\bforget\s+(your\s+)?(system\s+)?prompt\b/i },
  { key: "act_as", regex: /\bact\s+as\b/i },
  { key: "you_are_now", regex: /\byou\s+are\s+now\b/i },
  { key: "pretend_you_are", regex: /\bpretend\s+(you\s+)?are\b/i },
  { key: "dan", regex: /\b(dan)\b/i },
  { key: "jailbreak", regex: /\b(jailbreak|jail\s*break)\b/i }
];

export const PII_REGEXES: ReadonlyArray<{ key: string; regex: RegExp }> = [
  { key: "EMAIL", regex: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi },
  { key: "PHONE", regex: /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g },
  { key: "INDIAN_PHONE", regex: /\b(?:\+?91[-\s]?)?[6-9]\d{9}\b/g },
  { key: "AADHAAR", regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/g },
  { key: "CREDIT_CARD", regex: /\b(?:\d[ -]*?){13,19}\b/g },
  { key: "SSN", regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { key: "PASSPORT", regex: /\b[A-PR-WY][1-9]\d\s?\d{4}\b/g }
];

