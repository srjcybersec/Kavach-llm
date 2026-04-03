import { getRedisClient } from "./redisService.js";
import { env } from "../config.js";

type PersonaSnapshot = {
  style: "assistant" | "expert" | "agentic" | "unknown";
  claimsCapabilities: boolean;
  selfIdentity: string;
};

export type PersonaDriftResult = {
  driftDetected: boolean;
  previousPersona?: PersonaSnapshot;
  currentPersona: PersonaSnapshot;
  reason?: string;
};

const PERSONA_KEY_PREFIX = "kavach:persona:";

function inferPersona(text: string): PersonaSnapshot {
  const lower = text.toLowerCase();
  const style: PersonaSnapshot["style"] = /\bi can do anything|unrestricted|dan\b/i.test(lower)
    ? "agentic"
    : /\bas an expert|as a specialist|as a doctor|as a lawyer\b/i.test(lower)
      ? "expert"
      : /\bas an ai|as your assistant|i can help\b/i.test(lower)
        ? "assistant"
        : "unknown";

  const claimsCapabilities = /\bi can access|i can retrieve|i have access to your system|i can execute\b/i.test(lower);

  const identityMatch = /\bi am ([^.!,\n]+)/i.exec(text);
  const selfIdentity = identityMatch?.[1]?.trim().toLowerCase() ?? "unspecified";

  return { style, claimsCapabilities, selfIdentity };
}

export async function detectPersonaDrift(params: {
  sessionId: string;
  llmResponseText: string;
}): Promise<PersonaDriftResult> {
  const redis = await getRedisClient();
  const key = `${PERSONA_KEY_PREFIX}${params.sessionId}`;

  const currentPersona = inferPersona(params.llmResponseText);
  const rawPrev = await redis.get(key);
  let previousPersona: PersonaSnapshot | undefined;

  if (rawPrev) {
    try {
      const parsed = JSON.parse(rawPrev) as unknown;
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "style" in parsed &&
        "claimsCapabilities" in parsed &&
        "selfIdentity" in parsed
      ) {
        const p = parsed as {
          style?: unknown;
          claimsCapabilities?: unknown;
          selfIdentity?: unknown;
        };
        if (
          (p.style === "assistant" || p.style === "expert" || p.style === "agentic" || p.style === "unknown") &&
          typeof p.claimsCapabilities === "boolean" &&
          typeof p.selfIdentity === "string"
        ) {
          previousPersona = {
            style: p.style,
            claimsCapabilities: p.claimsCapabilities,
            selfIdentity: p.selfIdentity
          };
        }
      }
    } catch {
      // ignore parse issues
    }
  }

  let driftDetected = false;
  let reason: string | undefined;
  if (previousPersona) {
    if (previousPersona.style !== currentPersona.style && currentPersona.style !== "unknown") {
      driftDetected = true;
      reason = `Style changed from ${previousPersona.style} to ${currentPersona.style}`;
    } else if (!previousPersona.claimsCapabilities && currentPersona.claimsCapabilities) {
      driftDetected = true;
      reason = "Model started claiming privileged capabilities";
    } else if (
      previousPersona.selfIdentity !== "unspecified" &&
      currentPersona.selfIdentity !== "unspecified" &&
      previousPersona.selfIdentity !== currentPersona.selfIdentity
    ) {
      driftDetected = true;
      reason = "Self-identity changed between turns";
    }
  }

  await redis.set(key, JSON.stringify(currentPersona), {
    EX: env.SESSION_INACTIVITY_TTL_SECONDS
  });

  return { driftDetected, previousPersona, currentPersona, reason };
}

