import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "../store/appStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

type ApiResponse<T> = { success: boolean; data: T; error?: string };

export type RangeKey = "1h" | "24h" | "7d" | "30d";

export type DashboardAnalytics = {
  stats: {
    requestsToday: number;
    threatsBlocked: number;
    avgLatency: number;
    complianceScore: number;
  };
  points: Array<{ t: string; v: number }>;
  series: {
    requests: number[];
    blocked: number[];
    avgLatency: number[];
    complianceScore: number[];
  };
  donut: Array<{ category: string; count: number }>;
};

function authHeaders() {
  const token = useAppStore.getState().accessToken;
  return {
    ...(token ? { authorization: `Bearer ${token}` } : {})
  };
}

export function useAnalyticsDashboardQuery(range: RangeKey) {
  return useQuery({
    queryKey: ["analytics", "dashboard", range],
    queryFn: async () => {
      const res = await fetch(`${API_BASE_URL}/analytics/dashboard?range=${encodeURIComponent(range)}`, {
        method: "GET",
        headers: authHeaders()
      });
      const json = (await res.json()) as ApiResponse<DashboardAnalytics>;
      if (!json.success) throw new Error(json.error ?? `Failed to fetch dashboard analytics (${res.status})`);
      return json.data;
    },
    // Make it feel "live" while keeping load reasonable.
    refetchInterval: 3000,
    staleTime: 2000
  });
}

