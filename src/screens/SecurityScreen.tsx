import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, Loader2, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";

import { PasswordField } from "@/components/PasswordField";
import { RecoveryCodePanel } from "@/components/RecoveryCodePanel";
import { Field, ScreenShell } from "@/components/ScreenShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  ApiError,
  api,
  type RecoveryCodeStatus,
  type RecoveryCodesView,
} from "@/lib/api";

interface SecurityScreenProps {
  /** True when first-run setup was never confirmed and codes must be replaced. */
  setupIncomplete: boolean;
  onBack: () => void;
}

type Stage = "idle" | "verifying" | "codes";

export function SecurityScreen({
  setupIncomplete,
  onBack,
}: SecurityScreenProps) {
  const [stage, setStage] = useState<Stage>("idle");
  const [password, setPassword] = useState("");
  const [codes, setCodes] = useState<RecoveryCodesView | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState<RecoveryCodeStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await api.recoveryCodeStatus());
    } catch (statusError) {
      if (!(statusError instanceof ApiError)) setStatus(null);
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  async function handleGenerate(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    if (!password) {
      setError("Enter your current password.");
      return;
    }

    setBusy(true);
    try {
      const result = await api.beginRecoveryCodeRegeneration(password);
      setPassword("");
      setCodes(result);
      setConfirmed(false);
      setStage("codes");
    } catch (generateError) {
      setError(
        generateError instanceof ApiError
          ? generateError.message
          : "The codes could not be generated.",
      );
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  async function handleCommit() {
    setBusy(true);
    setError(null);
    try {
      setStatus(await api.commitRecoveryCodeRegeneration());
      setCodes(null);
      setStage("idle");
      setConfirmed(false);
    } catch (commitError) {
      setError(
        commitError instanceof ApiError
          ? commitError.message
          : "The new codes could not be confirmed.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleCancel() {
    setCancelling(true);
    setError(null);
    try {
      await api.cancelRecoveryCodeRegeneration();
      setCodes(null);
      setStage("idle");
      await loadStatus();
    } catch (cancelError) {
      setError(
        cancelError instanceof ApiError
          ? cancelError.message
          : "The new codes could not be discarded.",
      );
    } finally {
      setCancelling(false);
    }
  }

  return (
    <ScreenShell
      wide
      icon={<ShieldCheck aria-hidden="true" />}
      title="Account security"
      description="Recovery codes are the only way back into this account if you forget your password."
      footer={
        <Button variant="ghost" onClick={onBack} disabled={busy || cancelling}>
          <ArrowLeft className="size-4" aria-hidden="true" />
          Back
        </Button>
      }
    >
      {setupIncomplete ? (
        <Alert variant="warning">
          <AlertDescription>
            Setup was not finished on this device. Generate a new set of
            recovery codes to complete it.
          </AlertDescription>
        </Alert>
      ) : null}

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {status ? (
        <div className="flex items-center justify-between rounded-lg border border-border bg-muted px-4 py-3 text-sm">
          <span className="text-foreground">Recovery codes</span>
          <span className="text-muted-foreground">
            {status.remaining} unused of {status.total}
          </span>
        </div>
      ) : null}

      {stage === "codes" && codes ? (
        <RecoveryCodePanel
          codes={codes.recoveryCodes}
          requireConfirmation
          confirmed={confirmed}
          onConfirmedChange={setConfirmed}
          onConfirm={handleCommit}
          confirming={busy}
          confirmLabel="Replace old codes"
          cancelLabel="Keep old codes"
          onCancel={handleCancel}
          cancelling={cancelling}
        />
      ) : (
        <>
          <Alert>
            <AlertDescription className="flex gap-2">
              <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
              <span>
                Generating a new set immediately invalidates all 10 previous
                codes. Your old set stays active until you confirm the
                replacement.
              </span>
            </AlertDescription>
          </Alert>

          <form className="flex flex-col gap-4" onSubmit={handleGenerate} noValidate>
            <Field
              id="current-password"
              label="Current password"
              hint="Required to confirm this change."
            >
              <PasswordField
                id="current-password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                disabled={busy}
              />
            </Field>

            <Button type="submit" disabled={busy}>
              {busy ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <RefreshCw className="size-4" aria-hidden="true" />
              )}
              Generate 10 new codes
            </Button>
          </form>
        </>
      )}
    </ScreenShell>
  );
}