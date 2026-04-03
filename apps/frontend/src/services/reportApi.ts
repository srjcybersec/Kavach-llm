import { useMutation } from "@tanstack/react-query";
import { useAppStore } from "../store/appStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:4000/api/v1";

function authHeaders() {
  const token = useAppStore.getState().accessToken;
  return {
    ...(token ? { authorization: `Bearer ${token}` } : {})
  };
}

function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function useDownloadComplianceReportMutation() {
  return useMutation({
    mutationFn: async (input: {
      mode: "GDPR" | "HIPAA" | "PCI-DSS" | "GENERAL";
      startDate?: string;
      endDate?: string;
    }) => {
      const q = new URLSearchParams();
      q.set("mode", input.mode);
      if (input.startDate) q.set("startDate", input.startDate);
      if (input.endDate) q.set("endDate", input.endDate);

      const res = await fetch(`${API_BASE_URL}/analytics/report/compliance?${q.toString()}`, {
        method: "GET",
        headers: authHeaders()
      });
      if (!res.ok) {
        throw new Error(`Failed to download report (${res.status})`);
      }
      const blob = await res.blob();
      const name = `kavach-compliance-report-${input.mode.toLowerCase()}.pdf`;
      downloadBlob(name, blob);
      return { ok: true };
    }
  });
}

