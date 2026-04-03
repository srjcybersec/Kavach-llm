import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "../store/appStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

type ApiResponse<T> = { success: boolean; data: T; error?: string };

export type AuditEntry = {
  id: string;
  sessionId: string;
  apiKeyId: string;
  userId: string;
  inputHash: string;
  threatCategory: string;
  confidence: number;
  action: string;
  responseHash: string;
  latencyMs: number;
  piiFields: unknown;
  scanBreakdown: unknown;
  createdAt: string;
};

export type AuditSortKey = "createdAt" | "threatCategory" | "confidence" | "action" | "latencyMs";

export type AuditQueryParams = {
  page?: number;
  pageSize?: number;
  category?: string;
  action?: string;
  startDate?: string;
  endDate?: string;
  sortBy?: AuditSortKey;
  sortDir?: "asc" | "desc";
  /** Server-side search (id, session, category, hashes). */
  q?: string;
};

type AuditListResponse = {
  items: AuditEntry[];
  total: number;
  page: number;
  pageSize: number;
};

function authHeaders() {
  const token = useAppStore.getState().accessToken;
  return {
    ...(token ? { authorization: `Bearer ${token}` } : {})
  };
}

export function buildAuditListQuery(params: AuditQueryParams): string {
  const search = new URLSearchParams();
  if (params.page) search.set("page", String(params.page));
  if (params.pageSize) search.set("pageSize", String(params.pageSize));
  if (params.category) search.set("category", params.category);
  if (params.action) search.set("action", params.action);
  if (params.startDate) search.set("startDate", params.startDate);
  if (params.endDate) search.set("endDate", params.endDate);
  if (params.sortBy) search.set("sortBy", params.sortBy);
  if (params.sortDir) search.set("sortDir", params.sortDir);
  if (params.q) search.set("q", params.q);
  const q = search.toString();
  return q.length > 0 ? `?${q}` : "";
}

async function requestJson<T>(path: string): Promise<ApiResponse<T>> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "GET",
    headers: authHeaders()
  });
  const json = (await res.json()) as ApiResponse<T>;
  return json;
}

/** First chunk (up to `pageSize`) of the current filter/sort — useful for export. */
export async function fetchAuditListChunk(params: AuditQueryParams): Promise<AuditEntry[]> {
  const json = await requestJson<AuditListResponse>(`/audit${buildAuditListQuery(params)}`);
  if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to fetch audit logs");
  return json.data.items;
}

export function useAuditListQuery(params: AuditQueryParams) {
  return useQuery({
    queryKey: ["audit", params],
    queryFn: async () => {
      const json = await requestJson<AuditListResponse>(`/audit${buildAuditListQuery(params)}`);
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to fetch audit logs");
      return json.data;
    }
  });
}

export function useAuditDetailQuery(id: string | null) {
  return useQuery({
    queryKey: ["audit", "detail", id],
    enabled: Boolean(id),
    queryFn: async () => {
      const json = await requestJson<AuditEntry>(`/audit/${id}`);
      if (!json.success) throw new Error(json.error ?? "Failed to fetch audit entry");
      return json.data;
    }
  });
}

