import { useEffect, useId, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

import { cn } from "@/lib/utils";

interface ModalProps {
  open: boolean;
  title: string;
  description?: string;
  /** Widens the panel so two-column forms have room to breathe. */
  wide?: boolean;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}

/**
 * Minimal modal built on the native `<dialog>` element.
 *
 * Using the platform primitive gives real modal semantics, backdrop, Escape to
 * close and focus containment without pulling in another dependency. The body
 * is only mounted while `open`, so a dismissed dialog leaves nothing behind.
 */
export function Modal({
  open,
  title,
  description,
  wide,
  onClose,
  children,
  footer,
}: ModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  // Unique per instance: more than one Modal can be mounted at a time, so a
  // fixed id would be duplicated in the document.
  const titleId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (open && !dialog.open) {
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={titleId}
      // Fires for Escape as well as the close button, so there is one path out.
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        // A click on the backdrop is a click on the dialog element itself,
        // because the panel below stops propagation.
        if (event.target === dialogRef.current) onClose();
      }}
      className={cn(
        "m-auto rounded-lg border border-border bg-background p-0 text-foreground",
        wide
          ? "w-[min(44rem,calc(100vw-3rem))]"
          : "w-[min(32rem,calc(100vw-3rem))]",
        "backdrop:bg-black/40",
      )}
    >
      <div className="flex flex-col">
        <header className="flex items-start justify-between gap-4 border-b border-border px-5 py-3.5">
          <div className="space-y-1">
            <h2
              id={titleId}
              className="text-sm font-semibold tracking-tight text-foreground"
            >
              {title}
            </h2>
            {description ? (
              <p className="text-xs leading-relaxed text-muted-foreground">
                {description}
              </p>
            ) : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="press -mt-1 -mr-1 flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <X className="size-4" aria-hidden="true" />
          </button>
        </header>

        <div
          className="max-h-[65vh] overflow-y-auto px-5 py-4"
          onClick={(event) => event.stopPropagation()}
        >
          {children}
        </div>

        {footer ? (
          <footer
            className="flex justify-end gap-2 border-t border-border px-5 py-3"
            onClick={(event) => event.stopPropagation()}
          >
            {footer}
          </footer>
        ) : null}
      </div>
    </dialog>
  );
}