import * as React from "react";
import { cn } from "../../lib/utils";

type ButtonVariant = "default" | "destructive" | "secondary" | "ghost" | "outline";
type ButtonSize = "sm" | "md" | "lg";

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
};

export function Button({
  className,
  variant = "default",
  size = "md",
  ...props
}: ButtonProps): React.ReactElement {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-all duration-200",
        "active:scale-[0.98] motion-reduce:active:scale-100",
        "focus:outline-none focus:ring-2 focus:ring-accent-teal/45 focus:ring-offset-2 focus:ring-offset-bg-base",
        {
          default:
            "border-accent-violet/35 bg-gradient-to-b from-bg-card to-bg-surface text-text-primary hover:border-accent-violet/50 hover:shadow-[0_0_24px_-10px_var(--glow-violet)]",
          destructive:
            "border-accent-red/35 bg-bg-card/90 text-accent-red hover:border-accent-red/50 hover:bg-bg-surface hover:shadow-[0_0_20px_-10px_rgba(251,113,133,0.25)]",
          secondary:
            "border-white/[0.08] bg-bg-surface/80 text-text-primary backdrop-blur-sm hover:border-white/[0.12] hover:bg-bg-card/80",
          ghost: "border-transparent bg-transparent text-text-primary hover:bg-white/[0.04]",
          outline: "border-white/[0.1] bg-transparent text-text-primary hover:border-accent-teal/25 hover:bg-bg-card/40"
        }[variant],
        {
          sm: "h-8 px-2.5",
          md: "h-10",
          lg: "h-11 px-4"
        }[size],
        className
      )}
      {...props}
    />
  );
}

