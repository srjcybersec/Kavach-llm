import * as React from "react";
import { cn } from "../../lib/utils";

type BadgeVariant = "default" | "violet" | "teal" | "red" | "amber";

export function Badge({
  className,
  variant = "default",
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { variant?: BadgeVariant }): React.ReactElement {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wide",
        {
          default: "border-border bg-bg-surface text-text-primary",
          violet: "border-accent-violet/50 bg-accent-violet/10 text-accent-violet",
          teal: "border-accent-teal/50 bg-accent-teal/10 text-accent-teal",
          red: "border-accent-red/50 bg-accent-red/10 text-accent-red",
          amber: "border-accent-amber/50 bg-accent-amber/10 text-accent-amber"
        }[variant],
        className
      )}
      {...props}
    />
  );
}

