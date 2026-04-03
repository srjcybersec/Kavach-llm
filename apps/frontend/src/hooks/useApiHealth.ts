import { useEffect, useState } from "react";
import { getApiV1Base } from "../lib/apiBase";

export type ApiHealthState =
  | { status: "checking" }
  | { status: "ok" }
  | { status: "offline"; message: string };

const INTERVAL_MS = 8000;

export function useApiHealth(): ApiHealthState {
  const [state, setState] = useState<ApiHealthState>({ status: "checking" });

  useEffect(() => {
    let cancelled = false;

    async function probe(): Promise<void> {
      try {
        const ctrl = new AbortController();
        const t = window.setTimeout(() => ctrl.abort(), 3500);
        const res = await fetch(`${getApiV1Base()}/health`, { signal: ctrl.signal });
        window.clearTimeout(t);
        if (cancelled) return;
        if (res.ok) setState({ status: "ok" });
        else setState({ status: "offline", message: `HTTP ${res.status}` });
      } catch (e) {
        if (cancelled) return;
        const msg = e instanceof Error ? e.message : "Unreachable";
        setState({
          status: "offline",
          message: msg.includes("abort") ? "Timeout — is the API running on port 4000?" : msg
        });
      }
    }

    void probe();
    const id = window.setInterval(() => void probe(), INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  return state;
}
