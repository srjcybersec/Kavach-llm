import { useAppStore, type AppEnvironment } from "../../store/appStore";
import { Badge } from "../ui/badge";
import { cn } from "../../lib/utils";

function Avatar() {
  return (
    <div className="flex h-9 w-9 items-center justify-center rounded-full border border-accent-violet/25 bg-bg-card/90 text-accent-violet shadow-[0_0_16px_-6px_rgba(124,92,255,0.5)]">
      <span className="font-mono text-xs font-medium">U</span>
    </div>
  );
}

export function Topbar(): React.ReactElement {
  const environment = useAppStore((s) => s.environment);
  const setEnvironment = useAppStore((s) => s.setEnvironment);

  const envBadgeVariant: Record<AppEnvironment, "violet" | "teal" | "amber"> = {
    dev: "teal",
    staging: "amber",
    prod: "violet"
  };

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-white/[0.06] bg-bg-surface/70 px-5 py-3 backdrop-blur-xl">
      <div className="flex items-center gap-3">
        <div className="flex flex-col">
          <span className="text-sm font-semibold tracking-tight text-text-primary">Kavach.LLM</span>
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-text-secondary/90">Intercept · Analyse · Shield</span>
        </div>
        <Badge variant={envBadgeVariant[environment]} className="hidden sm:inline-flex">
          {environment.toUpperCase()}
        </Badge>
      </div>

      <div className="flex items-center gap-3">
        <select
          className={cn(
            "h-10 rounded-lg border border-white/[0.08] bg-bg-card/80 px-3 text-sm text-text-primary backdrop-blur-sm transition-colors",
            "focus:border-accent-teal/35 focus:outline-none focus:ring-2 focus:ring-accent-teal/35"
          )}
          value={environment}
          onChange={(e) => setEnvironment(e.target.value as AppEnvironment)}
          aria-label="Environment selector"
        >
          <option value="dev">dev</option>
          <option value="staging">staging</option>
          <option value="prod">prod</option>
        </select>
        <Avatar />
      </div>
    </header>
  );
}

