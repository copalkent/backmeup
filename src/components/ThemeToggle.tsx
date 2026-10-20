import { Moon, Sun } from "lucide-react";

import { useTheme } from "@/components/ThemeProvider";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

/**
 * Sun/moon switch between the light and dark palettes.
 *
 * The visible icon shows the mode that will be applied next, and the two icons
 * cross-fade so the control reads as one object rather than flashing.
 */
export function ThemeToggle({ className }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";
  const label = isDark ? "Switch to light mode" : "Switch to dark mode";

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={toggleTheme}
          aria-label={label}
          className={cn(
            "press no-drag flex size-8 items-center justify-center rounded-md text-muted-foreground",
            "hover:bg-accent hover:text-foreground",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            className,
          )}
        >
          <span className="relative flex size-4 items-center justify-center">
            <Sun
              aria-hidden="true"
              strokeWidth={2}
              className={cn(
                "absolute size-4 transition-[opacity,transform] duration-200",
                isDark ? "scale-100 opacity-100" : "scale-75 opacity-0",
              )}
            />
            <Moon
              aria-hidden="true"
              strokeWidth={2}
              className={cn(
                "absolute size-4 transition-[opacity,transform] duration-200",
                isDark ? "scale-75 opacity-0" : "scale-100 opacity-100",
              )}
            />
          </span>
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom" sideOffset={6}>
        {label}
      </TooltipContent>
    </Tooltip>
  );
}