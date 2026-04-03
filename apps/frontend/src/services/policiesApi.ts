import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../store/appStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

type ApiResponse<T> = { success: boolean; data?: T; error?: string };

export type ThreatCategory =
  | "SAFE"
  | "SUSPICIOUS"
  | "PROMPT_INJECTION"
  | "JAILBREAK"
  | "PHISHING"
  | "SOCIAL_ENGINEERING"
  | "DATA_EXFILTRATION"
  | "NSFW"
  | "HATE_SPEECH"
  | "MALWARE_REQUEST";

export type PolicyAction = "ALLOW" | "BLOCK" | "REDACT_PII" | "WARN_USER" | "RATE_LIMIT" | "QUARANTINE";

export type PolicyRule = {
  id: string;
  userId: string;
  condition: {
    category?: ThreatCategory;
    confidence?: { op: ">" | ">=" | "<" | "<="; value: number };
    allowPhrases?: string[];
    denyPhrases?: string[];
    allowDomains?: string[];
    denyDomains?: string[];
  };
  action: PolicyAction;
  priority: number;
  enabled: boolean;
  preset: string | null;
  createdAt: string;
};

export type RuleBuilderInput = {
  if: {
    category?: ThreatCategory;
    confidence?: string;
    allowPhrases?: string[];
    denyPhrases?: string[];
    allowDomains?: string[];
    denyDomains?: string[];
  };
  then: PolicyAction;
  priority?: number;
  enabled?: boolean;
  preset?: string;
};

const queryKeyPolicies = ["policies"] as const;

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
  if (!res.ok && !json.error) {
    return { success: false, error: `Request failed (${res.status})` };
  }
  return json;
}

export function usePoliciesQuery() {
  return useQuery({
    queryKey: queryKeyPolicies,
    queryFn: async () => {
      const json = await requestJson<PolicyRule[]>("/policies", {
        method: "GET",
        headers: authHeaders()
      });
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to fetch rules");
      return json.data;
    }
  });
}

export function useCreatePolicyRuleMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: RuleBuilderInput) => {
      const json = await requestJson<PolicyRule>("/policies", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(input)
      });
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to create rule");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyPolicies });
    }
  });
}

export function useUpdatePolicyRuleMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: { id: string; patch: Partial<RuleBuilderInput> & { enabled?: boolean; priority?: number } }) => {
      const json = await requestJson<PolicyRule>(`/policies/${input.id}`, {
        method: "PATCH",
        headers: authHeaders(),
        body: JSON.stringify(input.patch)
      });
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to update rule");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyPolicies });
    }
  });
}

export function useDeletePolicyRuleMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const json = await requestJson<{ deleted: boolean }>(`/policies/${id}`, {
        method: "DELETE",
        headers: authHeaders()
      });
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to delete rule");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyPolicies });
    }
  });
}

export type ProductPresetName = "DefaultSafePolicy" | "StrictEnterprisePolicy" | "DeveloperPolicy";

export function useApplyPresetMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (preset: ProductPresetName) => {
      const json = await requestJson<{ preset: string; applied: boolean; ruleCount?: number }>(
        `/policies/preset/${encodeURIComponent(preset)}`,
        {
          method: "POST",
          headers: authHeaders()
        }
      );
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to apply preset");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyPolicies });
    }
  });
}

export function useRemovePresetMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (preset: ProductPresetName) => {
      const json = await requestJson<{ preset: string; removed: number }>(
        `/policies/preset/${encodeURIComponent(preset)}`,
        {
          method: "DELETE",
          headers: authHeaders()
        }
      );
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to remove preset");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyPolicies });
    }
  });
}

export function useApplyComplianceModeMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (mode: "GDPR" | "HIPAA" | "PCI-DSS" | "GENERAL") => {
      const json = await requestJson<{ mode: string; preset: string; applied: boolean }>(`/policies/compliance/${encodeURIComponent(mode)}`, {
        method: "POST",
        headers: authHeaders()
      });
      if (!json.success || json.data === undefined) throw new Error(json.error ?? "Failed to apply compliance mode");
      return json.data;
    },
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: queryKeyPolicies });
    }
  });
}

