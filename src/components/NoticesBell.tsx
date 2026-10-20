import { useCallback, useEffect, useRef, useState } from "react";
import {
  Bell,
  CircleCheck,
  Download,
  Info,
  KeyRound,
  X,
} from "lucide-react";

import { api, type Notice } from "@/lib/api";
import { onNoticesChanged } from "@/lib/events";
import { cn } from "@/lib/utils";

/**
 * The bell in the title bar, and the panel it opens.
 *
 * A toast is gone in five seconds, which is the right length for "that
 * worked" and the wrong length for "a new version is ready" or "the password
 * for one of the databases was rejected". Those live here, until the thing
 * they are about is resolved.
 *
 * The panel is deliberately plain: a list of sentences, each with the one
 * action that would settle it.
 */
export function NoticesBell({
  onEditDatabase,
  onOpenHistory,
}: {
  /** Open the editor for a connection whose password was refused. */
  onEditDatabase: (id: string) => void;
  /** Open the backup history. */
  onOpenHistory: () => void;
}) {
  const [notices, setNotices] = useState<Notice[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      setNotices(await api.listNotices());
    } catch {
      // Signed out, or the backend is not ready. The bell stays quiet.
      setNotices([]);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // A finished backup or a tested connection changes what the bell says.
  useEffect(() => onNoticesChanged(() => void load()), [load]);

  // A click outside the panel closes it, the way every menu does.
  useEffect(() => {
    if (!open) return;

    const onPointerDown = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };

    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const act = useCallback(
    async (notice: Notice) => {
      switch (notice.action) {
        case "install_update":
          setBusy(true);
          try {
            await api.installUpdate();
          } catch {
            // The install reports its own failure; the notice stays so the
            // the releases page can be used instead.
            setBusy(false);
          }
          break;
        case "edit_database":
          if (notice.target) onEditDatabase(notice.target);
          setOpen(false);
          break;
        case "open_history":
          onOpenHistory();
          setOpen(false);
          break;
        default:
          break;
      }
    },
    [onEditDatabase, onOpenHistory],
  );

  const count = notices.length;

  return (
    <div className="relative" ref={containerRef}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-label={
          count === 0
            ? "Notifications"
            : `Notifications, ${count} ${count === 1 ? "item" : "items"}`
        }
        aria-expanded={open}
        className="press relative flex size-9 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Bell className="size-4" strokeWidth={2} aria-hidden="true" />
        {count > 0 ? (
          <span
            aria-hidden="true"
            className="absolute right-1 top-1 flex size-3.5 items-center justify-center rounded-full bg-foreground text-[9px] font-semibold leading-none text-background"
          >
            {count > 9 ? "9+" : count}
          </span>
        ) : null}
      </button>

      {open ? (
        <div
          role="dialog"
          aria-label="Notifications"
          className="absolute right-0 top-11 z-50 w-[22rem] overflow-hidden rounded-lg border border-border bg-background text-foreground shadow-lg"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
            <h2 className="text-xs font-semibold tracking-tight text-foreground">
              Notifications
            </h2>
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Close notifications"
              className="press -mr-1 flex size-6 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <X className="size-3.5" aria-hidden="true" />
            </button>
          </div>

          {notices.length === 0 ? (
            <p className="px-4 py-6 text-center text-xs text-muted-foreground">
              Nothing to say.
            </p>
          ) : (
            <ul className="max-h-80 overflow-y-auto">
              {notices.map((notice) => (
                <li
                  key={notice.id}
                  className="flex items-start gap-3 border-b border-border px-4 py-3 last:border-b-0"
                >
                  <span className="mt-0.5 shrink-0">
                    {iconFor(notice)}
                  </span>
                  <div className="min-w-0 flex-1 space-y-1">
                    <p className="text-xs font-medium text-foreground">
                      {notice.title}
                    </p>
                    <p className="text-xs leading-relaxed text-muted-foreground">
                      {notice.body}
                    </p>
                    {notice.action && notice.actionLabel ? (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void act(notice)}
                        className="press mt-1 inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs font-medium text-foreground hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
                      >
                        {notice.action === "install_update" ? (
                          <Download className="size-3.5" aria-hidden="true" />
                        ) : null}
                        {notice.actionLabel}
                      </button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </div>
  );
}

/** The mark that matches the kind of notice. */
function iconFor(notice: Notice) {
  switch (notice.kind) {
    case "credential":
      return (
        <KeyRound className="size-4 text-foreground" strokeWidth={2} aria-hidden="true" />
      );
    case "update":
      return (
        <Download className="size-4 text-foreground" strokeWidth={2} aria-hidden="true" />
      );
    case "backup":
      return (
        <CircleCheck className="size-4 text-foreground" strokeWidth={2} aria-hidden="true" />
      );
    default:
      return <Info className="size-4 text-foreground" strokeWidth={2} aria-hidden="true" />;
  }
}

/** A warning notice, for the parts of the panel that need one. */
export function noticeSeverityClass(notice: Notice): string {
  return cn(notice.severity === "warning" ? "text-foreground" : "text-muted-foreground");
}
