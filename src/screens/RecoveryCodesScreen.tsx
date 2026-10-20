import { useState } from "react";
import { KeyRound } from "lucide-react";

import { RecoveryCodePanel } from "@/components/RecoveryCodePanel";
import { ScreenShell } from "@/components/ScreenShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ApiError, api } from "@/lib/api";

interface RecoveryCodesScreenProps {
  codes: string[];
  context: "setup" | "regenerate";
  onDone: () => void;
  onCancel?: () => void;
}

/**
 * Shows a freshly generated set of recovery codes exactly once and requires the
 * codes to be confirmed as saved.
 */
export function RecoveryCodesScreen({
  codes,
  context,
  onDone,
  onCancel,
}: RecoveryCodesScreenProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [working, setWorking] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleConfirm() {
    setWorking(true);
    setError(null);
    try {
      if (context === "setup") {
        await api.confirmSetupCodesSaved();
      } else {
        await api.commitRecoveryCodeRegeneration();
      }
      onDone();
    } catch (confirmError) {
      setError(
        confirmError instanceof ApiError
          ? confirmError.message
          : "That could not be saved.",
      );
    } finally {
      setWorking(false);
    }
  }

  async function handleCancel() {
    setCancelling(true);
    setError(null);
    try {
      await api.cancelRecoveryCodeRegeneration();
      onCancel?.();
    } catch (cancelError) {
      setError(
        cancelError instanceof ApiError
          ? cancelError.message
          : "That could not be cancelled.",
      );
    } finally {
      setCancelling(false);
    }
  }

  const isSetup = context === "setup";

  return (
    <ScreenShell
      wide
      icon={<KeyRound aria-hidden="true" />}
      title={isSetup ? "Save your recovery codes" : "Save your new recovery codes"}
      description={
        isSetup
          ? "These 10 codes were generated for your new account. Copy them now, they will not be shown again."
          : "Your previous codes stop working as soon as you confirm this new set."
      }
    >
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <RecoveryCodePanel
        codes={codes}
        requireConfirmation
        confirmed={confirmed}
        onConfirmedChange={setConfirmed}
        onConfirm={handleConfirm}
        confirming={working}
        confirmLabel={isSetup ? "Continue to dashboard" : "Replace old codes"}
        cancelLabel={isSetup ? undefined : "Keep old codes"}
        onCancel={isSetup ? undefined : handleCancel}
        cancelling={cancelling}
      />
    </ScreenShell>
  );
}