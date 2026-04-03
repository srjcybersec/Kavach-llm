import { NavLink } from "react-router-dom";
import { useState } from "react";
import { cn } from "../../lib/utils";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";

type SidebarItem = {
  to: string;
  label: string;
  badge?: string;
};

const items: SidebarItem[] = [
  { to: "/", label: "Dashboard", badge: "Live" },
  { to: "/playground", label: "Playground" },
  { to: "/policies", label: "Policies" },
  { to: "/audit", label: "Audit" },
  { to: "/settings", label: "Settings" }
];

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className={className} strokeWidth="1.6">
      <path
        d="M12 2.7c3.2 2.2 6.4 2.7 8.7 2.9v7.1c0 6-4.2 9.3-8.7 10.6C7.5 22 3.3 18.7 3.3 11.7V5.6c2.3-.2 5.5-.7 8.7-2.9Z"
      />
      <path d="M7 10h10M8 14h8" opacity="0.7" />
    </svg>
  );
}

export function Sidebar(): React.ReactElement {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        "relative flex h-screen shrink-0 flex-col border-r border-white/[0.06] bg-bg-surface/80 backdrop-blur-xl transition-[width] duration-300 ease-out",
        collapsed ? "w-[60px]" : "w-[248px]"
      )}
    >
      <div className="pointer-events-none absolute inset-y-0 right-0 w-px bg-gradient-to-b from-transparent via-accent-teal/25 to-transparent" />

      <div className="flex items-center gap-3 px-3 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent-violet/35 bg-bg-card/90 text-accent-violet shadow-[0_0_20px_-6px_rgba(124,92,255,0.4)] transition-shadow duration-300 hover:shadow-[0_0_28px_-4px_rgba(124,92,255,0.45)]">
          <ShieldIcon className="h-5 w-5" />
        </div>
        {!collapsed && (
          <div className="flex flex-col leading-tight">
            <span className="text-sm font-semibold">Kavach.LLM</span>
            <span className="text-xs text-text-secondary">Intercept. Analyse. Shield.</span>
          </div>
        )}
      </div>

      <div className="px-2 pb-2">
        <Button
          variant="ghost"
          size="sm"
          className={cn("w-full justify-center", !collapsed && "justify-start px-2")}
          onClick={() => setCollapsed((v) => !v)}
          type="button"
        >
          <span className="text-text-secondary">{collapsed ? "Expand" : "Collapse"}</span>
        </Button>
      </div>

      <nav className="flex flex-col gap-1 px-2">
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              cn(
                "group flex items-center gap-3 rounded-lg border px-2 py-2 text-sm transition-all duration-200",
                isActive
                  ? "border-accent-violet/40 bg-bg-card/90 text-accent-violet shadow-[inset_3px_0_0_0_rgba(45,212,191,0.65),0_0_24px_-14px_rgba(124,92,255,0.12)]"
                  : "border-transparent text-text-secondary hover:border-white/[0.08] hover:bg-bg-card/50 hover:text-text-primary"
              )
            }
          >
            <div className="flex h-7 w-7 items-center justify-center rounded-md border border-white/[0.08] bg-bg-surface/50 font-mono text-accent-teal transition-colors group-hover:border-accent-teal/25 group-hover:text-accent-teal">
              <span className="text-[11px] font-medium">{item.label.slice(0, 1).toUpperCase()}</span>
            </div>
            {!collapsed && (
              <div className="flex min-w-0 flex-1 items-center justify-between gap-2">
                <span className="truncate">{item.label}</span>
                {item.badge ? <Badge variant="teal">{item.badge}</Badge> : null}
              </div>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto px-2 pb-4">
        <div className="rounded-lg border border-white/[0.06] bg-bg-card/70 p-3 backdrop-blur-sm">
          {!collapsed ? (
            <>
              <div className="text-xs text-text-secondary">Security posture</div>
              <div className="mt-1 text-sm font-semibold text-accent-teal">Stable</div>
            </>
          ) : (
            <div className="flex items-center justify-center text-accent-teal">OK</div>
          )}
        </div>
      </div>
    </aside>
  );
}

