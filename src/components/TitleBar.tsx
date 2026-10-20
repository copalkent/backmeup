import { useCallback, useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Copy, Folder, Minus, Square, X } from "lucide-react";

import { GoogleDriveMark } from "@/components/icons";
import { NoticesBell } from "@/components/NoticesBell";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api, type OwnerProfile } from "@/lib/api";
import { onDestinationsChanged } from "@/lib/events";
import { cn } from "@/lib/utils";

const appWindow = getCurrentWindow();

interface WindowButtonProps {
  label: string;
  onClick: () => void;
  icon: React.ReactNode;
  className?: string;
}

/**
 * A window control whose label appears only while it is hovered or focused.
 *
 * The tooltip is controlled rather than left to the tooltip's own open logic,
 * so a label can never linger once the pointer has left the button.
 */
function WindowButton({ label, onClick, icon, className }: WindowButtonProps) {
  const [labelled, setLabelled] = useState(false);

  return (
    <Tooltip open={labelled}>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          onClick={onClick}
          onPointerEnter={() => setLabelled(true)}
          onPointerLeave={() => setLabelled(false)}
          onFocus={() => setLabelled(true)}
          onBlur={() => setLabelled(false)}
          className={cn(
            "press no-drag flex size-10 items-center justify-center text-muted-foreground",
            "hover:bg-accent hover:text-foreground",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            "disabled:pointer-events-none disabled:opacity-50",
            className,
          )}
        >
          {icon}
        </button>
      </TooltipTrigger>
      {labelled ? (
        <TooltipContent side="bottom" sideOffset={6}>
          {label}
        </TooltipContent>
      ) : null}
    </Tooltip>
  );
}

interface TitleBarProps {
  signedIn: boolean;
  owner: OwnerProfile | null;
  /** Where the status chips and the profile lead. */
  onOpenSettings: () => void;
  /** Open the editor for a connection whose password was refused. */
  onEditDatabase: (id: string) => void;
  /** Open the backup history. */
  onOpenHistory: () => void;
}

/**
 * Custom borderless window chrome.
 *
 * The native frame is removed through the Tauri window configuration
 * (`decorations: false`), not with CSS. Window movement uses Tauri's supported
 * `startDragging` API, so the window behaves like a normal Windows window:
 * resizable, maximizable to the work area, and still attached to the taskbar.
 *
 * The bar carries the product name, a live readout of where backups are saved,
 * and the account chip, so status is visible from every screen instead of only
 * inside Settings.
 */
export function TitleBar({
  signedIn,
  owner,
  onOpenSettings,
  onEditDatabase,
  onOpenHistory,
}: TitleBarProps) {
  const [isMaximized, setIsMaximized] = useState(false);

  const syncMaximized = useCallback(async () => {
    try {
      setIsMaximized(await appWindow.isMaximized());
    } catch {
      setIsMaximized(false);
    }
  }, []);

  useEffect(() => {
    void syncMaximized();

    let dispose: (() => void) | undefined;
    let cancelled = false;

    void appWindow
      .onResized(() => {
        void syncMaximized();
      })
      .then((unlisten) => {
        if (cancelled) {
          unlisten();
          return;
        }
        dispose = unlisten;
      })
      .catch(() => {
        /* Window events are unavailable outside the desktop shell. */
      });

    return () => {
      cancelled = true;
      dispose?.();
    };
  }, [syncMaximized]);

  const handleError = useCallback((error: unknown) => {
    console.error("[backmeup] window action failed", error);
  }, []);

  const minimize = useCallback(() => {
    appWindow.minimize().catch(handleError);
  }, [handleError]);

  const toggleMaximize = useCallback(() => {
    if (isMaximized) {
      appWindow.unmaximize().catch(handleError);
    } else {
      appWindow.maximize().catch(handleError);
    }
  }, [handleError, isMaximized]);

  const close = useCallback(() => {
    appWindow.close().catch(handleError);
  }, [handleError]);

  const startDragging = useCallback(() => {
    appWindow.startDragging().catch(handleError);
  }, [handleError]);

  return (
    <header
      data-tauri-drag-region
      onMouseDown={(event) => {
        // Explicit drag start so moving the window works reliably regardless of
        // which element inside the title bar received the pointer event.
        if (event.button === 0 && !(event.target as HTMLElement).closest("button")) {
          startDragging();
        }
      }}
      onDoubleClick={toggleMaximize}
      className="flex h-11 shrink-0 items-center justify-between border-b border-border bg-background pl-4 select-none"
    >
      <span
        data-tauri-drag-region
        className="min-w-0 truncate pr-4 text-[13px] font-semibold tracking-tight text-foreground"
      >
        BackMeUp
      </span>

      <div className="no-drag flex items-center gap-0.5 pr-1.5">
        <ThemeToggle />

        {signedIn ? (
          <>
            <NoticesBell
              onEditDatabase={onEditDatabase}
              onOpenHistory={onOpenHistory}
            />
            <DestinationChips onOpenSettings={onOpenSettings} />
            <ProfileChip owner={owner} onOpenSettings={onOpenSettings} />
          </>
        ) : null}

        <span aria-hidden="true" className="mx-1 h-4 w-px bg-border" />

        <WindowButton
          label="Minimize"
          onClick={minimize}
          icon={<Minus className="size-4" strokeWidth={2} aria-hidden="true" />}
        />
        <WindowButton
          label={isMaximized ? "Restore" : "Maximize"}
          onClick={toggleMaximize}
          icon={
            isMaximized ? (
              <Copy className="size-3.5" strokeWidth={2} aria-hidden="true" />
            ) : (
              <Square className="size-3.5" strokeWidth={2.2} aria-hidden="true" />
            )
          }
        />
        <WindowButton
          label="Close"
          onClick={close}
          icon={<X className="size-4" strokeWidth={2} aria-hidden="true" />}
          className="hover:bg-foreground hover:text-background"
        />
      </div>
    </header>
  );
}

interface DestinationStatus {
  hasLocalFolder: boolean;
  localPath: string | null;
  hasDrive: boolean;
  rootFolder: string;
}

/**
 * Where backups are saved, at a glance.
 *
 * Two dots and two marks rather than words: the shapes are recognisable from
 * every screen, and the full sentence is one hover away. Both chips lead to the
 * destination controls in Settings.
 */
function DestinationChips({
  onOpenSettings,
}: {
  onOpenSettings: () => void;
}) {
  const [status, setStatus] = useState<DestinationStatus | null>(null);

  const load = useCallback(async () => {
    try {
      const [overview, destinations] = await Promise.all([
        api.backupOverview(),
        api.listDestinations(),
      ]);
      const local = destinations.find(
        (destination) => destination.kind === "local_folder",
      );
      setStatus({
        hasLocalFolder: overview.hasLocalFolder,
        localPath: local?.location ?? null,
        hasDrive: overview.hasDrive,
        rootFolder: "BackMeUp",
      });
    } catch {
      // Signed out, or the backend is not ready yet. The chips stay neutral.
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Settings and the destination dialog announce every change, and a window
  // focus re-checks: the state can also change by signing in again.
  useEffect(() => onDestinationsChanged(() => void load()), [load]);
  useEffect(() => {
    const onFocus = () => void load();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [load]);

  return (
    <>
      <Chip
        label="Local backup folder"
        ready={status?.hasLocalFolder ?? false}
        icon={<Folder className="size-4" aria-hidden="true" />}
        detail={
          status?.hasLocalFolder
            ? `Saving to: ${status.localPath ?? "a folder on this computer"}. Click to change.`
            : "Not saving to this computer. Click to choose a folder."
        }
        onClick={onOpenSettings}
      />
      <Chip
        label="Google Drive"
        ready={status?.hasDrive ?? false}
        icon={<GoogleDriveMark className="size-4" />}
        detail={
          status?.hasDrive
            ? `Connected. Every backup is also uploaded to ${status.rootFolder}/<database>/<date>. Click for options.`
            : "Not connected. Click to sign in and upload backups to Drive."
        }
        onClick={onOpenSettings}
      />
    </>
  );
}

/** One status chip: an icon, a state dot, and a sentence on hover. */
function Chip({
  label,
  ready,
  icon,
  detail,
  onClick,
}: {
  label: string;
  ready: boolean;
  icon: React.ReactNode;
  detail: string;
  onClick: () => void;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={`${label}: ${ready ? "connected" : "not connected"}`}
          onClick={onClick}
          className={cn(
            "press no-drag flex h-8 items-center gap-1.5 rounded-md px-2",
            "text-muted-foreground hover:bg-accent hover:text-foreground",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          )}
        >
          {icon}
          <span
            aria-hidden="true"
            className={cn(
              "size-1.5 rounded-full",
              ready ? "bg-emerald-500" : "bg-muted-foreground/40",
            )}
          />
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom" sideOffset={6} className="max-w-72 text-pretty leading-relaxed">
        {detail}
      </TooltipContent>
    </Tooltip>
  );
}

/** Initials for the avatar. Falls back to a neutral mark, never a guess. */
function initialsOf(fullName: string): string {
  const parts = fullName.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";

  return parts
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

/** The signed-in account, between the status chips and the window controls. */
function ProfileChip({
  owner,
  onOpenSettings,
}: {
  owner: OwnerProfile | null;
  onOpenSettings: () => void;
}) {
  const name = owner?.fullName ?? "";

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={onOpenSettings}
          aria-label={name ? `Signed in as ${name}` : "Account"}
          className={cn(
            "press no-drag ml-1 flex h-8 items-center gap-2 rounded-full border border-border pl-1 pr-2.5",
            "hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          )}
        >
          <span className="flex size-6 items-center justify-center rounded-full bg-foreground text-[10px] font-semibold text-background">
            {initialsOf(name)}
          </span>
          {name ? (
            <span className="hidden max-w-28 truncate text-xs font-medium text-foreground sm:block">
              {name}
            </span>
          ) : null}
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom" sideOffset={6} className="max-w-72 text-pretty leading-relaxed">
        {name ? `${name}${owner?.email ? ` - ${owner.email}` : ""}. Click to open Settings.` : "Open Settings."}
      </TooltipContent>
    </Tooltip>
  );
}
