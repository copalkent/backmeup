import type { ReactNode } from "react";
import { Info } from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

/**
 * A small "i" that explains a control or a figure in one sentence.
 *
 * The explanation lives in a tooltip rather than in the layout, so the screen
 * stays quiet while every number remains self-explanatory on demand. It is a
 * real button, so it can be reached and read with a keyboard.
 */
export function InfoHint({
  children,
  className,
  label = "More information",
}: {
  children: ReactNode;
  className?: string;
  label?: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          className={cn(
            "press inline-flex size-4 shrink-0 items-center justify-center rounded-full text-muted-foreground/70",
            "hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            className,
          )}
        >
          <Info className="size-3.5" aria-hidden="true" strokeWidth={2} />
        </button>
      </TooltipTrigger>
      <TooltipContent
        side="top"
        className="max-w-64 text-pretty leading-relaxed"
      >
        {children}
      </TooltipContent>
    </Tooltip>
  );
}
