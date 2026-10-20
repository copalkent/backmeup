import { useState } from "react";
import { Download } from "lucide-react";

import { Modal } from "@/components/Modal";
import { Button } from "@/components/ui/button";
import { api, type UpdateInfo } from "@/lib/api";
import { notifyNoticesChanged } from "@/lib/events";

/**
 * The prompt that offers a newer version.
 *
 * It appears once, when a newer version has been found and the prompt has not
 * asked to be left alone about it. Closing it does not lose the offer: the
 * notice stays in the bell until the version is installed, so a dismissed
 * prompt is never forgotten.
 */
export function UpdateDialog({
  open,
  update,
  onClose,
}: {
  open: boolean;
  update: UpdateInfo | null;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open || !update?.version) {
    return null;
  }

  const later = async () => {
    // "Later" stops the prompt for this version. The notice stays in the bell,
    // so the offer is still there next time the bell is opened.
    try {
      await api.dismissUpdate(update.version as string);
      notifyNoticesChanged();
    } catch {
      // Nothing to do: the prompt simply comes back.
    }
    onClose();
  };

  const install = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.installUpdate();
      // The app restarts into the new version, so nothing follows this.
    } catch (installError) {
      setError(
        installError instanceof Error
          ? installError.message
          : "The update could not be installed.",
      );
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      title={`BackMeUp ${update.version} is available`}
      description="A new version of BackMeUp has been published."
      onClose={() => void later()}
      footer={
        <>
          <Button variant="outline" onClick={() => void later()} disabled={busy}>
            Later
          </Button>
          <Button onClick={() => void install()} disabled={busy}>
            <Download className="size-4" aria-hidden="true" />
            {busy ? "Installing..." : "Install and restart"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {update.notes ? (
          <p className="text-sm leading-relaxed text-muted-foreground">
            {update.notes}
          </p>
        ) : null}

        {error ? (
          <p role="alert" className="text-xs text-foreground">
            {error}
          </p>
        ) : null}

        <p className="text-xs leading-relaxed text-muted-foreground">
          The update is downloaded over the network and checked against the
          project's signing key before it is installed. Your databases, settings
          and backups are not touched.
        </p>
      </div>
    </Modal>
  );
}
