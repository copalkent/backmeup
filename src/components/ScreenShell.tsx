import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface ScreenShellProps {
  title: string;
  description?: string;
  /** Mark above the heading. Decorative callers must pass `aria-hidden`. */
  icon?: ReactNode;
  /** Centres the mark and heading instead of aligning them to the left. */
  center?: boolean;
  footer?: ReactNode;
  wide?: boolean;
  children: ReactNode;
}

/**
 * Shared layout for the authentication screens: a single scrollable column,
 * one heading and one form, with no decorative chrome.
 */
export function ScreenShell({
  title,
  description,
  icon,
  center,
  footer,
  wide,
  children,
}: ScreenShellProps) {
  return (
    <div className="flex h-full overflow-y-auto">
      <div
        className={cn(
          "mx-auto flex w-full flex-col justify-center gap-6 px-6 py-8",
          wide ? "max-w-2xl" : "max-w-md",
        )}
      >
        <header
          className={cn(
            "flex flex-col gap-3",
            center && "items-center text-center",
          )}
        >
          {icon ? <div className="[&_svg]:size-5">{icon}</div> : null}
          <h1 className="text-lg font-semibold tracking-tight text-foreground">
            {title}
          </h1>
          {description ? (
            <p className="text-sm leading-relaxed text-muted-foreground">
              {description}
            </p>
          ) : null}
        </header>

        <div className="flex flex-col gap-4">{children}</div>

        {footer ? <footer className="pt-1">{footer}</footer> : null}
      </div>
    </div>
  );
}

interface FieldProps {
  id: string;
  label: string;
  error?: string;
  hint?: ReactNode;
  children: ReactNode;
}

export function Field({ id, label, error, hint, children }: FieldProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-foreground">
        {label}
      </label>
      {children}
      {error ? (
        <p id={`${id}-error`} role="alert" className="text-xs font-medium text-foreground">
          {error}
        </p>
      ) : hint ? (
        <div id={`${id}-hint`} className="text-xs text-muted-foreground">
          {hint}
        </div>
      ) : null}
    </div>
  );
}