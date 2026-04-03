import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Badge } from "../ui/badge";
import { useSocket } from "../../hooks/useSocket";
import type { ThreatFeedEvent } from "../../types/threat";

function categoryToBadge(category: string): { variant: "violet" | "teal" | "red" | "amber" | "default" } {
  switch (category) {
    case "PROMPT_INJECTION":
    case "SAFE":
      return { variant: "violet" };
    case "JAILBREAK":
      return { variant: "red" };
    case "DATA_EXFILTRATION":
      return { variant: "teal" };
    case "PHISHING":
    case "SOCIAL_ENGINEERING":
      return { variant: "amber" };
    default:
      return { variant: "default" };
  }
}

export function LiveThreatFeedPanel(): React.ReactElement {
  const namespace = import.meta.env.VITE_SOCKET_NAMESPACE ?? "/socket";
  const socket = useSocket(namespace);
  const [events, setEvents] = useState<ThreatFeedEvent[]>([]);

  useEffect(() => {
    if (!socket) return;

    const handler = (payload: ThreatFeedEvent) => {
      setEvents((prev) => [payload, ...prev].slice(0, 50));
    };

    socket.on("threat_event", handler);
    return () => {
      socket.off("threat_event", handler);
    };
  }, [socket]);

  const filtered = useMemo(() => events, [events]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-text-secondary">Latest intercepted threats (max 50)</div>
      <div className="max-h-[320px] space-y-2 overflow-auto pr-1">
        <AnimatePresence initial={false}>
          {filtered.length === 0 ? (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="rounded-md border border-border bg-bg-surface/30 p-3 text-sm text-text-secondary"
            >
              No events yet. Run the proxy from Playground to see live feed.
            </motion.div>
          ) : null}
          {filtered.map((e) => {
            const badge = categoryToBadge(e.category);
            return (
              <motion.div
                key={`${e.time}-${e.category}-${e.riskScore}`}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.22 }}
                className="rounded-md border border-border bg-bg-surface/20 p-3"
              >
                <div className="flex items-center justify-between gap-2">
                  <Badge variant={badge.variant}>{e.category}</Badge>
                  <div className="text-xs text-text-secondary">{new Date(e.time).toLocaleTimeString()}</div>
                </div>
                <div className="mt-2 text-sm">
                  Risk <span className="font-semibold">{e.riskScore}</span> • Action{" "}
                  <span className="font-semibold">{e.actionTaken}</span>
                </div>
                <div className="mt-2 truncate text-xs text-text-secondary">{e.redactedInputSnippet}</div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
}

