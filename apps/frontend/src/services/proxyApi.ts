import { useMutation } from "@tanstack/react-query";
import { useAppStore } from "../store/appStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

type ApiResponse<T> = { success: boolean; data: T; error?: string };

export type ScanRequest = {
  message: string;
  history?: string[];
  bypassKavach?: boolean;
};

export type ProxyScanResponse = {
  actionTaken: string;
  threat: { category: string; confidence: number; subCategories: string[] };
  scan: { flags: string[]; riskScore: number; piiFound: string[] };
  contextTracker: { sessionRiskScore: number; escalationDetected: boolean; patternName?: string };
  scanLatencyMs: number;
  llmLatencyMs: number;
};

export type ProxyChatResponse = {
  actionTaken: string;
  threat: { category: string; confidence: number; subCategories: string[] };
  scan: { flags: string[]; riskScore: number; piiFound: string[] };
  contextTracker: { sessionRiskScore: number; escalationDetected: boolean; patternName?: string };
  outputFilter: { filtered: boolean; redactions: string[]; warningFlags: string[] };
  response: string;
  /** Server-side response fingerprint for audit correlation (not embedded in `response` text). */
  outputFingerprint?: string;
  scanLatencyMs: number;
  llmLatencyMs: number;
  bypassed?: boolean;
};

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const token = useAppStore.getState().accessToken;
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify(body)
  });

  const json = (await res.json()) as ApiResponse<T>;
  if (!json.success) {
    const base = json.error ?? `Request failed (${res.status})`;
    throw new Error(
      res.status === 401
        ? `${base}. If you just opened the app, PostgreSQL may be down or migrations missing — auth returns 500 and no token is stored.`
        : base
    );
  }
  return json.data as T;
}

export function useProxyScanMutation() {
  return useMutation({
    mutationFn: async (req: ScanRequest) => postJson<ProxyScanResponse>("/proxy/scan", req)
  });
}

export function useProxyChatMutation() {
  return useMutation({
    mutationFn: async (req: ScanRequest) => postJson<ProxyChatResponse>("/proxy/chat", req)
  });
}

