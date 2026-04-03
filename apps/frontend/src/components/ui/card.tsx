import * as React from "react";
import { cn } from "../../lib/utils";

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>): React.ReactElement {
  return (
    <div
      className={cn(
        "rounded-xl border border-white/[0.07] bg-bg-card/70 shadow-[0_0_0_1px_rgba(255,255,255,0.03)_inset] backdrop-blur-md transition-[border-color,box-shadow] duration-300",
        "hover:border-accent-teal/12 hover:shadow-[0_0_32px_-16px_var(--glow-teal),0_0_0_1px_rgba(255,255,255,0.04)_inset]",
        className
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>): React.ReactElement {
  return <div className={cn("p-4 pb-2", className)} {...props} />;
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>): React.ReactElement {
  return (
    <h3
      className={cn(
        "relative border-l-2 border-accent-teal/45 pl-3 text-sm font-semibold tracking-tight text-text-primary/95",
        className
      )}
      {...props}
    />
  );
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>): React.ReactElement {
  return <div className={cn("p-4 pt-2", className)} {...props} />;
}

export function CardFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>): React.ReactElement {
  return <div className={cn("p-4 pt-2", className)} {...props} />;
}

