import * as React from "react";

import { cn } from "@/lib/utils";

type AlertVariant = "default" | "destructive" | "success" | "warning";

/**
 * The palette is strictly monochrome, so severity is carried by weight,
 * inversion and border style rather than hue: errors invert to solid, warnings
 * use a dashed rule, confirmations use a solid rule on a muted fill.
 */
const alertStyles: Record<AlertVariant, string> = {
  default: "border-border bg-card text-foreground",
  destructive: "border-foreground bg-foreground text-background",
  success: "border-foreground bg-muted text-foreground",
  warning: "border-dashed border-foreground bg-card text-foreground",
};

function Alert({
  className,
  variant = "default",
  ...props
}: React.ComponentProps<"div"> & { variant?: AlertVariant }) {
  return (
    <div
      role="alert"
      className={cn(
        "flex w-full gap-3 rounded-lg border px-4 py-3 text-sm",
        alertStyles[variant],
        className,
      )}
      {...props}
    />
  );
}

function AlertTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div className={cn("font-medium leading-tight", className)} {...props} />
  );
}

function AlertDescription({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div className={cn("text-sm leading-relaxed", className)} {...props} />
  );
}

export { Alert, AlertTitle, AlertDescription };