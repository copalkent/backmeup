import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export type AppSection = "dashboard" | "databases" | "history" | "settings";

export interface NavEntry {
  id: AppSection;
  label: string;
  icon: ReactNode;
}

interface AppShellProps {
  section: AppSection;
  onNavigate: (section: AppSection) => void;
  children: ReactNode;
}

/**
 * Signed-in layout: a fixed sidebar and a single scrolling content column.
 *
 * The sidebar is exactly the four sections of BackMeUp and nothing else -
 * website backups, deployments and hosting are out of scope, so they do not
 * appear. Account actions live in Settings.
 */
export function AppShell({ section, onNavigate, children }: AppShellProps) {
  const entries: NavEntry[] = [
    { id: "dashboard", label: "Dashboard", icon: <LayoutIcon /> },
    { id: "databases", label: "Databases", icon: <DatabaseIcon /> },
    { id: "history", label: "Backups", icon: <HistoryIcon /> },
    { id: "settings", label: "Settings", icon: <SettingsIcon /> },
  ];

  return (
    <div className="flex h-full min-h-0">
      <nav
        aria-label="Sections"
        className="w-48 shrink-0 border-r border-border bg-background px-3 py-3"
      >
        <ul className="flex flex-col gap-0.5">
          {entries.map((entry) => {
            const current = entry.id === section;
            return (
              <li key={entry.id}>
                <button
                  type="button"
                  onClick={() => onNavigate(entry.id)}
                  aria-current={current ? "page" : undefined}
                  className={cn(
                    "press flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    current
                      ? "bg-secondary font-medium text-foreground"
                      : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground",
                  )}
                >
                  <span className="shrink-0 text-current" aria-hidden="true">
                    {entry.icon}
                  </span>
                  {entry.label}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      <main className="min-h-0 flex-1 overflow-y-auto">
        {/*
          A plain scrolling column. It is wide enough for the history table to
          show a location and a reason without clipping.
        */}
        <div className="mx-auto w-full max-w-5xl px-6 py-6">{children}</div>
      </main>
    </div>
  );
}

function LayoutIcon() {
  return (
    <svg viewBox="0 0 16 16" className="size-4" fill="none" strokeWidth={1.5} stroke="currentColor" strokeLinecap="round">
      <rect x="2" y="2.5" width="12" height="11" rx="1.5" />
      <path d="M2 6h12M6 6v7.5" />
    </svg>
  );
}

function DatabaseIcon() {
  return (
    <svg viewBox="0 0 16 16" className="size-4" fill="none" strokeWidth={1.5} stroke="currentColor" strokeLinecap="round">
      <ellipse cx="8" cy="4" rx="5.25" ry="2.25" />
      <path d="M2.75 4v8c0 1.24 2.35 2.25 5.25 2.25S13.25 13.24 13.25 12V4" />
      <path d="M2.75 8c0 1.24 2.35 2.25 5.25 2.25S13.25 9.24 13.25 8" />
    </svg>
  );
}

function HistoryIcon() {
  return (
    <svg viewBox="0 0 16 16" className="size-4" fill="none" strokeWidth={1.5} stroke="currentColor" strokeLinecap="round">
      <path d="M2.5 8a5.5 5.5 0 1 0 1.7-3.97" />
      <path d="M2.25 2.5v2.75H5" />
      <path d="M8 5v3.25l2.25 1.25" />
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg viewBox="0 0 16 16" className="size-4" fill="none" strokeWidth={1.5} stroke="currentColor" strokeLinecap="round">
      <circle cx="8" cy="8" r="2" />
      <path d="M8 1.75v1.5M8 12.75v1.5M14.25 8h-1.5M3.25 8h-1.5M12.42 3.58l-1.06 1.06M4.64 11.36l-1.06 1.06M12.42 12.42l-1.06-1.06M4.64 4.64L3.58 3.58" />
    </svg>
  );
}