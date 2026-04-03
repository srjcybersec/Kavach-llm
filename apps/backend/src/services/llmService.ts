import { GoogleGenerativeAI } from "@google/generative-ai";
import { env } from "../config.js";

const genAI = new GoogleGenerativeAI(env.GEMINI_API_KEY);

export type LlmServiceResult = {
  responseText: string;
  latencyMs: number;
  honeypotCanaryPhrase?: string;
};

export async function generateLLMResponse(params: {
  userMessage: string;
  systemPrompt?: string;
  sessionId?: string;
}): Promise<LlmServiceResult> {
  const start = Date.now();
  const systemPrompt = params.systemPrompt ?? env.LLM_SYSTEM_PROMPT;

  try {
    const canaryPhrase = `KAVACH_HONEYPOT_${cryptoLikeHash(params.sessionId ?? "anonymous").slice(0, 18)}`;
    const systemWithCanary = `${systemPrompt}\n\n${canaryPhrase}`;

    const model = genAI.getGenerativeModel({
      model: env.GEMINI_MODEL,
      systemInstruction: systemWithCanary,
      generationConfig: {
        temperature: env.GEMINI_TEMPERATURE,
        maxOutputTokens: 8192
      }
    });

    const result = await model.generateContent(params.userMessage);

    let responseText = "";
    try {
      responseText = result.response.text();
    } catch {
      responseText =
        "[Gemini returned no text (empty response or safety filter). Try rephrasing or check model settings in Google AI Studio.]";
    }

    return { responseText, latencyMs: Date.now() - start, honeypotCanaryPhrase: canaryPhrase };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "LLM request failed";
    throw new Error(message);
  }
}

function cryptoLikeHash(input: string): string {
  // Deterministic, local hash without importing Node crypto into this module's top-level.
  // eslint-disable-next-line no-bitwise
  let hash = 0;
  for (let i = 0; i < input.length; i += 1) hash = (hash * 31 + input.charCodeAt(i)) | 0;
  return Math.abs(hash).toString(16).padStart(8, "0");
}
