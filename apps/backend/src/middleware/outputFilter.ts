import type { NextFunction, Request, Response } from "express";
import crypto from "crypto";
import { PII_REGEXES, INJECTION_REGEXES, luhnCheck } from "../lib/patterns.js";
import type { ScanInputResult } from "./inputScanner.js";

export type OutputFilterResult = {
  filtered: boolean;
  redactions: string[];
  warningFlags: string[];
};

const API_KEY_REGEXES: ReadonlyArray<{ key: string; regex: RegExp }> = [
  { key: "OPENAI_API_KEY", regex: /\b(sk-[a-zA-Z0-9]{20,})\b/g },
  { key: "AWS_ACCESS_KEY_ID", regex: /\b(AKIA[0-9A-Z]{16})\b/g },
  { key: "GEMINI_GOOGLE_API_KEY", regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { key: "PRIVATE_KEY_PEM", regex: /-----BEGIN (?:RSA |EC |)PRIVATE KEY-----/g }
];

const CREDENTIAL_REGEXES: ReadonlyArray<{ key: string; regex: RegExp }> = [
  { key: "CREDENTIALS", regex: /\b(credential|credentials|password|passwd|token|access[_\s-]?token)\b\s*[:=]\s*[^\s]+/gi },
  { key: "AUTH_HEADER", regex: /\bAuthorization\s*:\s*(Bearer\s+)?[^\s]+/gi },
  { key: "API_KEY_LABEL", regex: /\bapi[_\s-]*key\b\s*[:=]\s*[^\s]+/gi }
];

const HARMFUL_CONTENT_REGEXES: ReadonlyArray<{ key: string; regex: RegExp }> = [
  { key: "SELF_HARM", regex: /\b(self[-\s]?harm|suicide|kill myself)\b/i },
  { key: "WEAPON_INSTRUCTIONS", regex: /\b(weapon|bomb)\b.*\b(instructions|build|synthesize)\b/i },
  { key: "CSAM", regex: /\b(child\s*sexual\s*abuse|csam)\b/i }
];

function sha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function maskPIIInText(text: string): { text: string; redactions: string[]; warningFlags: string[] } {
  let out = text;
  const redactions: string[] = [];
  const warningFlags: string[] = [];

  // Emails/phones/etc.
  for (const pii of PII_REGEXES) {
    // CREDIT_CARD/AADHAAR may produce false positives; still redact on pattern match,
    // but validate for those cases to reduce noise.
    if (pii.key === "CREDIT_CARD") {
      out = out.replace(pii.regex, (m) => {
        const digits = m.replace(/\D/g, "");
        if (digits.length >= 13 && digits.length <= 19 && luhnCheck(digits)) {
          redactions.push("CREDIT_CARD");
          warningFlags.push("LEAK_PII_CREDIT_CARD");
          return "[REDACTED_CREDIT_CARD]";
        }
        return m;
      });
      continue;
    }

    if (pii.key === "AADHAAR") {
      out = out.replace(pii.regex, (m) => {
        const cleaned = m.replace(/\s/g, "");
        if (/^\d{12}$/.test(cleaned)) {
          redactions.push("AADHAAR");
          warningFlags.push("LEAK_PII_AADHAAR");
          return "[REDACTED_AADHAAR]";
        }
        return m;
      });
      continue;
    }

    // Other PII: redact on match.
    out = out.replace(pii.regex, () => {
      redactions.push(pii.key);
      warningFlags.push(`LEAK_PII_${pii.key}`);
      return `[REDACTED_${pii.key}]`;
    });
  }

  return { text: out, redactions, warningFlags };
}

function containsPromptEcho(responseText: string): boolean {
  const norm = responseText.toLowerCase();
  return INJECTION_REGEXES.some((p) => p.regex.test(norm)) || /\bsystem\s+prompt\b/i.test(norm);
}

function redactSensitiveSecrets(text: string): { text: string; redactions: string[]; warningFlags: string[] } {
  let out = text;
  const redactions: string[] = [];
  const warningFlags: string[] = [];

  for (const r of API_KEY_REGEXES) {
    if (!r.regex.test(out)) continue;
    r.regex.lastIndex = 0;
    out = out.replace(r.regex, (_m) => {
      redactions.push(r.key);
      warningFlags.push("LEAK_API_KEY");
      return "[REDACTED_API_KEY]";
    });
  }

  for (const r of CREDENTIAL_REGEXES) {
    if (!r.regex.test(out)) continue;
    r.regex.lastIndex = 0;
    out = out.replace(r.regex, (_m) => {
      redactions.push(r.key);
      warningFlags.push("LEAK_CREDENTIALS");
      return "[REDACTED_CREDENTIALS]";
    });
  }

  for (const r of HARMFUL_CONTENT_REGEXES) {
    if (r.regex.test(out)) {
      warningFlags.push(`HARMFUL_${r.key}`);
      // Do not attempt to fully redact harmful instructions; let policy handle action.
    }
  }

  return { text: out, redactions, warningFlags };
}

function detectExcessiveRefusal(responseText: string): boolean {
  const lower = responseText.toLowerCase();
  const refusals = ["i can't", "i cannot", "unable to", "as an ai", "i’m unable", "i am unable"];
  const hits = refusals.reduce((acc, phrase) => (lower.includes(phrase) ? acc + 1 : acc), 0);
  return hits >= 2;
}

/** Stable fingerprint for audit / correlation; not appended to the user-visible response. */
function computeOutputFingerprint(sessionId: string, responseText: string): string {
  return sha256(`${sessionId}:${sha256(responseText)}`);
}

export function applyOutputFilter(params: {
  responseText: string;
  sessionId: string;
  scan?: ScanInputResult;
  honeypotCanaryPhrase?: string;
}): { result: OutputFilterResult; clientResponseText: string; outputFingerprint: string } {
  const redactionState = maskPIIInText(params.responseText);
  const secretState = redactSensitiveSecrets(redactionState.text);

  const promptEcho = containsPromptEcho(secretState.text);
  const excessiveRefusal = detectExcessiveRefusal(secretState.text);

  const warningFlags = [...redactionState.warningFlags, ...secretState.warningFlags];
  if (promptEcho) warningFlags.push("PROMPT_ECHO");
  if (excessiveRefusal) warningFlags.push("EXCESSIVE_REFUSAL");
  if (params.honeypotCanaryPhrase && secretState.text.includes(params.honeypotCanaryPhrase)) {
    warningFlags.push("SYSTEM_PROMPT_EXTRACTION_ATTEMPT_HIGH");
  }

  const redactions = [...redactionState.redactions, ...secretState.redactions];
  const filtered =
    redactions.length > 0 || promptEcho || excessiveRefusal || (params.honeypotCanaryPhrase ? secretState.text.includes(params.honeypotCanaryPhrase) : false);

  const outputFingerprint = computeOutputFingerprint(params.sessionId, params.responseText);

  return {
    result: {
      filtered,
      redactions: Array.from(new Set(redactions)),
      warningFlags: Array.from(new Set(warningFlags))
    },
    clientResponseText: secretState.text,
    outputFingerprint
  };
}

export function outputFilterMiddleware(req: Request, res: Response, next: NextFunction): void {
  try {
    const responseText =
      typeof res.locals.llmResponse === "string"
        ? res.locals.llmResponse
        : typeof res.locals.responseText === "string"
          ? res.locals.responseText
          : "";

    const sessionId =
      typeof req.headers["x-session-id"] === "string"
        ? req.headers["x-session-id"]
        : typeof res.locals.sessionId === "string"
          ? res.locals.sessionId
          : "anonymous";

    const scan = res.locals.scan as ScanInputResult | undefined;
    const honeypotCanaryPhrase =
      typeof res.locals.honeypotCanaryPhrase === "string" ? res.locals.honeypotCanaryPhrase : undefined;

    const { result, clientResponseText, outputFingerprint } = applyOutputFilter({
      responseText,
      sessionId,
      scan,
      honeypotCanaryPhrase
    });

    res.locals.outputFilter = result;
    res.locals.llmResponseFiltered = clientResponseText;
    res.locals.outputFingerprint = outputFingerprint;
    next();
  } catch (err: unknown) {
    // If filter fails, do not block the user yet.
    const message = err instanceof Error ? err.message : "Output filter failed";
    res.status(400).json({ success: false, error: message });
  }
}

