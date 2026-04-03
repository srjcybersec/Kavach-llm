import { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { SystemStatusBar } from "./SystemStatusBar";
import { cn } from "../../lib/utils";

export function Shell({ children }: { children: ReactNode }): React.ReactElement {
  return (
    <div className="relative min-h-screen bg-bg-base">
      <div className="kavach-ambient" aria-hidden>
        <div
          className={cn(
            "kavach-ambient__mesh animate-mesh-drift motion-reduce:animate-none"
          )}
        />
        <div className="kavach-ambient__grid" />
        <div className="kavach-ambient__vignette" />
        <div className="kavach-ambient__scan motion-reduce:opacity-0" />
      </div>

      <div className="relative z-10 flex min-h-screen">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <SystemStatusBar />
          <main className="flex-1 p-5 md:p-6">{children}</main>
        </div>
      </div>
    </div>
  );
}

