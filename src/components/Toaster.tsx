import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { CircleAlert, CircleCheck, Info, X } from "lucide-react";

import { cn } from "@/lib/utils";

type ToastVariant = "success" | "error" | "info";

interface ToastInput {
  title: string;
  /** One short sentence explaining what happened. */
  description?: string;
  variant?: ToastVariant;
}

interface ToastEntry extends Required<ToastInput> {
  id: number;
  leaving: boolean;
}

interface ToastContextValue {
  /** Show a toast. Every result the owner should notice goes through here. */
  toast: (input: ToastInput) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const value = useContext(ToastContext);
  if (!value) {
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return value;
}

const VARIANT_ICON: Record<ToastVariant, typeof Info> = {
  success: CircleCheck,
  error: CircleAlert,
  info: Info,
};

const EXIT_MS = 180;
/** Oldest toasts drop off once this many are visible. */
const MAX_VISIBLE = 3;

/**
 * Global toasts, centred at the bottom edge.
 *
 * Results that are by nature momentary - a sign-in finished, a folder synced,
 * a run failed - appear here rather than inline, so no screen has to reserve
 * layout for a message that will be gone in five seconds. Each toast is a
 * polite live region, so a screen reader announces it without stealing focus.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const nextId = useRef(1);
  const timers = useRef(new Map<number, number>());

  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const timer of pending.values()) window.clearTimeout(timer);
      pending.clear();
    };
  }, []);

  const remove = useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer !== undefined) {
      window.clearTimeout(timer);
      timers.current.delete(id);
    }
    setToasts((current) => current.filter((entry) => entry.id !== id));
  }, []);

  const dismiss = useCallback(
    (id: number) => {
      // Play the exit animation, then drop the entry.
      setToasts((current) =>
        current.map((entry) =>
          entry.id === id ? { ...entry, leaving: true } : entry,
        ),
      );
      const timer = window.setTimeout(() => remove(id), EXIT_MS);
      timers.current.set(id, timer);
    },
    [remove],
  );

  const toast = useCallback(
    (input: ToastInput) => {
      const id = nextId.current++;
      const entry: ToastEntry = {
        id,
        title: input.title,
        description: input.description ?? "",
        variant: input.variant ?? "info",
        leaving: false,
      };

      setToasts((current) => [...current, entry].slice(-MAX_VISIBLE));

      // Failures stay a little longer: they carry a sentence worth reading.
      const lifetime = entry.variant === "error" ? 8000 : 5000;
      timers.current.set(id, window.setTimeout(() => dismiss(id), lifetime));
    },
    [dismiss],
  );

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed inset-x-0 bottom-5 z-[100] flex flex-col items-center gap-2 px-4"
      >
        {toasts.map((entry) => {
          const Icon = VARIANT_ICON[entry.variant];
          return (
            <div
              key={entry.id}
              role="status"
              className={cn(
                "pointer-events-auto flex w-full max-w-md items-start gap-3 rounded-xl border border-border bg-popover px-4 py-3",
                "shadow-lg shadow-black/10 dark:shadow-black/40",
                entry.leaving ? "animate-toast-out" : "animate-toast-in",
              )}
            >
              <Icon
                className={cn(
                  "mt-0.5 size-4 shrink-0",
                  entry.variant === "success" &&
                    "text-emerald-600 dark:text-emerald-400",
                  entry.variant === "error" && "text-red-600 dark:text-red-400",
                  entry.variant === "info" && "text-muted-foreground",
                )}
                aria-hidden="true"
              />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground">
                  {entry.title}
                </p>
                {entry.description ? (
                  <p className="mt-0.5 text-xs leading-relaxed break-words text-muted-foreground">
                    {entry.description}
                  </p>
                ) : null}
              </div>
              <button
                type="button"
                onClick={() => dismiss(entry.id)}
                aria-label="Dismiss"
                className="press -mt-0.5 -mr-1 flex size-6 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <X className="size-3.5" aria-hidden="true" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
