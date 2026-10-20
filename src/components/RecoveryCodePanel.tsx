import { useState } from "react";
import { Check, ClipboardCopy, Download, Loader2 } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { api } from "@/lib/api";
import { formatRecoveryCode } from "@/lib/password";
import { cn } from "@/lib/utils";

interface RecoveryCodePanelProps {
  codes: string[];
  /** Checkbox confirmation is only required during first-run setup. */
  requireConfirmation: boolean;
  confirmed: boolean;
  onConfirmedChange: (value: boolean) => void;
  onConfirm: () => void | Promise<void>;
  confirming: boolean;
  confirmLabel: string;
  cancelLabel?: string;
  onCancel?: () => void | Promise<void>;
  cancelling?: boolean;
}

/**
 * One-time display of the generated recovery codes.
 *
 * The codes are held in component state only for as long as they are visible;
 * they are never written to storage by the frontend and never logged.
 */
export function RecoveryCodePanel({
  codes,
  requireConfirmation,
  confirmed,
  onConfirmedChange,
  onConfirm,
  confirming,
  confirmLabel,
  cancelLabel,
  onCancel,
  cancelling = false,
}: RecoveryCodePanelProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  async function copy(text: string, index: number | "all") {
    try {
      await navigator.clipboard.writeText(text);
      if (index === "all") {
        setCopiedAll(true);
        window.setTimeout(() => setCopiedAll(false), 1600);
      } else {
        setCopiedIndex(index);
        window.setTimeout(() => setCopiedIndex(null), 1600);
      }
    } catch {
      setError("Copying is unavailable. Use \"Save to file\" instead.");
    }
  }

  async function handleExport() {
    setError(null);
    setNotice(null);
    setExporting(true);
    try {
      const result = await api.exportRecoveryCodes();
      if (result.saved) {
        setNotice(`Saved to ${result.fileName}. Store it somewhere secure.`);
      }
    } catch (exportError) {
      setError(
        exportError instanceof Error
          ? exportError.message
          : "The file could not be saved.",
      );
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Alert variant="warning">
        <AlertDescription>
          These 10 codes are the only way to recover this account if you forget
          your password. Anyone who holds them can take over BackMeUp. They are
          shown once and cannot be displayed again.
        </AlertDescription>
      </Alert>

      <ul className="grid gap-2">
        {codes.map((code, index) => (
          <li
            key={`${index}-${code.slice(0, 5)}`}
            className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted px-3 py-2"
          >
            <span
              data-allow-select
              className="font-mono text-sm tracking-[0.18em] text-foreground"
            >
              {formatRecoveryCode(code)}
            </span>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => void copy(code, index)}
              aria-label={`Copy recovery code ${index + 1}`}
              className={cn(
                "shrink-0",
                copiedIndex === index && "text-foreground hover:text-foreground",
              )}
            >
              {copiedIndex === index ? (
                <Check className="size-4" aria-hidden="true" />
              ) : (
                <ClipboardCopy className="size-4" aria-hidden="true" />
              )}
              <span className="sr-only">
                {copiedIndex === index ? "Copied" : "Copy"}
              </span>
            </Button>
          </li>
        ))}
      </ul>

      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => void copy(codes.join("\n"), "all")}
          className={cn(copiedAll && "border-foreground/50 text-foreground")}
        >
          {copiedAll ? (
            <Check className="size-4" aria-hidden="true" />
          ) : (
            <ClipboardCopy className="size-4" aria-hidden="true" />
          )}
          Copy all
        </Button>

        <Button
          type="button"
          variant="outline"
          onClick={() => void handleExport()}
          disabled={exporting}
        >
          {exporting ? (
            <Loader2 className="size-4 animate-spin" aria-hidden="true" />
          ) : (
            <Download className="size-4" aria-hidden="true" />
          )}
          Save to file
        </Button>
      </div>

      {notice ? (
        <p role="status" className="text-xs text-muted-foreground">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs font-medium text-foreground">
          {error}
        </p>
      ) : null}

      {requireConfirmation ? (
        <div className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4">
          <label
            htmlFor="confirm-recovery-codes"
            className="flex cursor-pointer items-start gap-3 text-sm text-foreground"
          >
            <Checkbox
              id="confirm-recovery-codes"
              checked={confirmed}
              onCheckedChange={(value) => onConfirmedChange(value === true)}
              className="mt-0.5"
            />
            <span>I have saved my recovery codes in a secure place.</span>
          </label>

          <div className="flex justify-end gap-2">
            {cancelLabel && onCancel ? (
              <Button
                type="button"
                variant="ghost"
                onClick={() => void onCancel()}
                disabled={cancelling}
              >
                {cancelling ? (
                  <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                ) : null}
                {cancelLabel}
              </Button>
            ) : null}
            <Button
              type="button"
              onClick={() => void onConfirm()}
              disabled={!confirmed || confirming}
            >
              {confirming ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : null}
              {confirmLabel}
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}