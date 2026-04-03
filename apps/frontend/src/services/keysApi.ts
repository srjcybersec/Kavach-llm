import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../store/appStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

type ApiResponse<T> = { success: boolean; data: T; error?: string };

export type ApiKeyRow = {
  id: string;
  label: string;
  reputationScore: number;
  status: "ACTIVE" | "REVOKED" | "SUSPENDED";
  createdAt: string;
  lastUsed: string | null;
};

type CreatedApiKey = ApiKeyRow & { plainKey: string };

const queryKeyKeys = ["api-keys"] as const;

function authHeaders() {
  const token = useAppStore.getState().accessToken;
  return {
    "content-type": "application/json",
    ...(token ? { authorization: `Bearer ${token}` } : {})
  };
}

async function requestJson<T>(path: string, init: RequestInit): Promise<ApiResponse<T>> {
  const res = await fetch(`${API_BASE_URL}${path}`, init);
  const json = (await res.json()) as ApiResponse<T>;
  return json;
}

export function useApiKeysQuery() {
  return useQuery({
    queryKey: queryKeyKeys,
    queryFn: async () => {
      const json = await requestJson<ApiKeyRow[]>("/keys", {
        method: "GET",
        headers: authHeaders()
      });
      if (!json.success || !Array.isArray(json.data)) throw new Error(json.error ?? "Failed to fetch keys");
      return json.data;
    }
  });
}

export function useCreateApiKeyMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (label: string) => {
      const json = await requestJson<CreatedApiKey>("/keys", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ label })
      });
      if (!json.success) throw new Error(json.error ?? "Failed to create key");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyKeys });
    }
  });
}

export function useRevokeApiKeyMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const json = await requestJson<{ revoked: boolean }>(`/keys/${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers: authHeaders()
      });
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to revoke key");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyKeys });
    }
  });
}

