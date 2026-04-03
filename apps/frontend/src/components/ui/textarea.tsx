import * as React from "react";
import { cn } from "../../lib/utils";

export type TextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement>;

export function Textarea({ className, ...props }: TextareaProps): React.ReactElement {
  return (
    <textarea
      className={cn(
        "min-h-[100px] w-full rounded-lg border border-white/[0.08] bg-bg-surface/75 px-3 py-2 text-sm text-text-primary backdrop-blur-sm placeholder:text-text-secondary/80",
        "transition-[border-color,box-shadow] duration-200 focus:border-accent-teal/30 focus:outline-none focus:ring-2 focus:ring-accent-teal/25",
        className
      )}
      {...props}
    />
  );
}

