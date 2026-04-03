import { useEffect, useMemo, useState } from "react";
import { io, type Socket } from "socket.io-client";
import { getApiOrigin } from "../lib/apiBase";
import type { ThreatFeedEvent } from "../types/threat";

type ServerToClientEvents = {
  threat_event: (payload: ThreatFeedEvent) => void;
};

type ClientToServerEvents = Record<string, never>;

const HEALTH_PROBE_MS = 2500;
const RETRY_INTERVAL_MS = 12000;

/**
 * Socket.IO for the threat feed. Waits until the API health check succeeds so we
 * do not spam connection errors when the backend is not running (e.g. frontend-only dev).
 */
export function useSocket(namespace: string): Socket<ServerToClientEvents, ClientToServerEvents> | null {
  const apiBaseUrl = useMemo(() => getApiOrigin(), []);

  const [socket, setSocket] = useState<Socket<ServerToClientEvents, ClientToServerEvents> | null>(null);

  useEffect(() => {
    let cancelled = false;
    let client: Socket<ServerToClientEvents, ClientToServerEvents> | null = null;
    let busy = false;

    async function backendReachable(): Promise<boolean> {
      try {
        const ctrl = new AbortController();
        const t = window.setTimeout(() => ctrl.abort(), HEALTH_PROBE_MS);
        const res = await fetch(`${apiBaseUrl}/api/v1/health`, { signal: ctrl.signal });
        window.clearTimeout(t);
        return res.ok;
      } catch {
        return false;
      }
    }

    async function tryConnect(): Promise<void> {
      if (cancelled || busy) return;
      if (client?.connected) return;

      busy = true;
      try {
        const ok = await backendReachable();
        if (cancelled || !ok) return;

        if (client) {
          client.disconnect();
          client = null;
          setSocket(null);
        }

        const ns = io(`${apiBaseUrl}${namespace}`, {
          transports: ["polling", "websocket"],
          autoConnect: true,
          reconnectionAttempts: 5,
          reconnectionDelay: 1500
        }) as Socket<ServerToClientEvents, ClientToServerEvents>;

        if (cancelled) {
          ns.disconnect();
          return;
        }

        client = ns;
        setSocket(ns);
      } finally {
        busy = false;
      }
    }

    void tryConnect();
    const interval = window.setInterval(() => {
      void tryConnect();
    }, RETRY_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
      client?.disconnect();
      setSocket(null);
    };
  }, [apiBaseUrl, namespace]);

  return socket;
}
