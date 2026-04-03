import { Link } from "react-router-dom";
import { useAppStore } from "../../store/appStore";
import { useApiHealth } from "../../hooks/useApiHealth";
import { getApiV1Base } from "../../lib/apiBase";
import { cn } from "../../lib/utils";

export function SystemStatusBar(): React.ReactElement {
  const health = useApiHealth();
  const token = useAppStore((s) => s.accessToken);

  const apiLine =
    health.status === "checking"
      ? "Checking API…"
      : health.status === "ok"
        ? `API online (${getApiV1Base().replace(/^https?:\/\//, "")})`
        : `API offline — ${health.message}. From repo root run: npm run dev -w @kavach-llm/backend`;

  const dotClass =
    health.status === "ok"
      ? "bg-accent-teal shadow-[0_0_10px_rgba(45,212,191,0.55)] animate-pulse-soft motion-reduce:animate-none"
      : health.status === "checking"
        ? "bg-accent-amber shadow-[0_0_8px_rgba(251,191,36,0.4)] animate-pulse-soft motion-reduce:animate-none"
        : "bg-accent-red shadow-[0_0_10px_rgba(251,113,133,0.55)]";

  return (
    <div
      className={cn(
        "border-b px-5 py-2.5 text-xs sm:text-sm",
        health.status === "ok" && "border-white/[0.05] bg-bg-card/35 text-text-secondary backdrop-blur-md",
        health.status === "checking" && "border-white/[0.05] bg-bg-card/35 text-text-secondary backdrop-blur-md",
        health.status === "offline" && "border-accent-red/35 bg-accent-red/[0.08] text-text-primary backdrop-blur-md"
      )}
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span className="flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-text-secondary">
          <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full motion-reduce:animate-none", dotClass)} aria-hidden />
          Status
        </span>
        <span className="font-mono text-[11px] text-text-primary/90 sm:text-xs">{apiLine}</span>
        <span className="hidden text-text-secondary sm:inline">·</span>
        <span className={cn("font-mono text-[11px] sm:text-xs", token ? "text-accent-teal" : "text-accent-amber")}>
          {token ? "Signed in (demo account)" : "Not signed in — use Playground Send to sign in"}
        </span>
        <span className="hidden text-text-secondary lg:inline">·</span>
        <Link
          to="/playground"
          className="font-mono text-[11px] text-accent-violet/90 underline-offset-4 transition-colors hover:text-accent-teal hover:underline sm:text-xs"
        >
          Try the Playground
        </Link>
      </div>
    </div>
  );
}
