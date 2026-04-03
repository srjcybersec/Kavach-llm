import * as React from "react";
import { cn } from "../../lib/utils";

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export function Input({ className, ...props }: InputProps): React.ReactElement {
  return (
    <input
      className={cn(
        "h-10 w-full rounded-lg border border-white/[0.08] bg-bg-surface/75 px-3 text-sm text-text-primary backdrop-blur-sm placeholder:text-text-secondary/80",
        "transition-[border-color,box-shadow] duration-200 focus:border-accent-teal/30 focus:outline-none focus:ring-2 focus:ring-accent-teal/25",
        className
      )}
      {...props}
    />
  );
}

