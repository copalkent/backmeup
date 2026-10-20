import { useCallback, useEffect, useState } from "react";
import { Check, FolderOpen, HardDrive, Loader2 } from "lucide-react";

import { GoogleDriveMark } from "@/components/icons";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toaster";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  ApiError,
  api,
  onDriveSigninUrl,
  type BackupDestination,
  type GoogleDriveStatus,
} from "@/lib/api";
import { notifyDestinationsChanged } from "@/lib/events";
import { cn } from "@/lib/utils";

interface DestinationDialogProps {
  open: boolean;
  onClose: () => void;
  /** Called once at least one destination is ready. */
  onReady: () => void;
}

/**
 * "Where should backups go?" asked only when nothing is configured.
 *
 * Both destinations are equal choices: a local folder, Google Drive, or both.
 * Choosing Drive runs the real sign-in here, so the owner never has to find
 * Settings first, and the backend creates the per-database folders before this
 * closes.
 */
export function DestinationDialog({
  open,
  onClose,
  onReady,
}: DestinationDialogProps) {
  const { toast } = useToast();
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [drive, setDrive] = useState<GoogleDriveStatus | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [picking, setPicking] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [signinUrl, setSigninUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [list, driveStatus] = await Promise.all([
        api.listDestinations(),
        api.googleDriveStatus(),
      ]);
      setDestinations(list);
      setDrive(driveStatus);
    } catch (loadError) {
      setError(
        loadError instanceof ApiError
          ? loadError.message
          : "Your backup destinations could not be loaded.",
      );
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (open) void load();
  }, [open, load]);

  useEffect(() => {
    return onDriveSigninUrl((url) => setSigninUrl(url));
  }, []);

  const folder = destinations.find((entry) => entry.kind === "local_folder");
  const localReady = Boolean(folder?.location);
  const driveReady = drive?.connected === true;
  const anyReady = localReady || driveReady;

  const chooseFolder = useCallback(async () => {
    setPicking(true);
    setError(null);
    try {
      const selection = await api.chooseLocalBackupFolder();
      if (selection.cancelled) return;
      await load();
      notifyDestinationsChanged();
      toast({
        variant: "success",
        title: "Backup folder saved",
        description: selection.location
          ? `Backups will be written to ${selection.location}.`
          : "Backups will be written to the folder you chose.",
      });
    } catch (pickError) {
      setError(
        pickError instanceof ApiError
          ? pickError.message
          : "That folder could not be used.",
      );
    } finally {
      setPicking(false);
    }
  }, [load, toast]);

  const connectDrive = useCallback(async () => {
    setConnecting(true);
    setError(null);
    try {
      const status = await api.connectGoogleDrive();
      setDrive(status);
      setSigninUrl(null);
      notifyDestinationsChanged();
      toast({
        variant: "success",
        title: "Google Drive connected",
        description:
          status.folders.length > 0
            ? `Folders ready: ${status.folders.join(", ")}.`
            : "Your databases will get their folders the next time one is backed up.",
      });
    } catch (connectError) {
      if (connectError instanceof ApiError && connectError.code === "drive_cancelled") {
        toast({
          variant: "info",
          title: "Sign-in cancelled",
          description: "Nothing was changed and no access was granted.",
        });
      } else {
        setError(
          connectError instanceof ApiError
            ? connectError.message
            : "Google Drive could not be connected.",
        );
      }
    } finally {
      setConnecting(false);
    }
  }, [toast]);

  const cancelConnect = useCallback(async () => {
    try {
      await api.cancelGoogleDriveConnect();
    } catch {
      // The wait will time out on its own if this cannot be delivered.
    }
  }, []);

  // Closing the dialog while the sign-in is still waiting would leave it
  // running with no way to see or stop it, so closing cancels it first.
  const handleClose = useCallback(() => {
    if (connecting) void cancelConnect();
    onClose();
  }, [cancelConnect, connecting, onClose]);

  return (
    <Modal
      open={open}
      title="Choose where backups are saved"
      description="Pick one destination or both. You can change this later in Settings."
      onClose={handleClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={picking || connecting}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              onClose();
              onReady();
            }}
            disabled={!anyReady || picking || connecting}
          >
            {anyReady ? "Continue" : "Choose a destination first"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {!loaded ? (
          <div className="flex h-24 items-center justify-center">
            <Loader2
              className="size-4 animate-spin text-muted-foreground"
              aria-label="Loading"
            />
          </div>
        ) : (
          <>
            <DestinationOption
              icon={<HardDrive className="size-5" aria-hidden />}
              title="This computer"
              description={
                localReady
                  ? folder?.location ?? "A folder is ready."
                  : "Choose a folder on this computer. Backups go into a BackMeUp folder inside it, one folder per database."
              }
              ready={localReady}
              action={
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void chooseFolder()}
                  disabled={picking || connecting}
                >
                  {picking ? (
                    <Loader2 className="size-4 animate-spin" aria-hidden />
                  ) : (
                    <FolderOpen className="size-4" aria-hidden />
                  )}
                  {picking
                    ? "Opening picker"
                    : localReady
                      ? "Change folder"
                      : "Choose folder"}
                </Button>
              }
            />

            <DestinationOption
              icon={<GoogleDriveMark className="size-5" />}
              title="Google Drive"
              description={
                driveReady
                  ? `Backups go to a ${drive?.rootFolder ?? "BackMeUp"} folder in your Drive, one folder per database.`
                  : "Sign in with Google. BackMeUp never sees your Google password."
              }
              ready={driveReady}
              action={
                driveReady ? null : connecting ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => void cancelConnect()}
                  >
                    Cancel sign-in
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    onClick={() => void connectDrive()}
                    disabled={picking}
                  >
                    Sign in
                  </Button>
                )
              }
            />

            {connecting ? (
              <p className="px-1 text-xs leading-relaxed text-muted-foreground">
                A Google sign-in page should have opened in your browser.
                Approve access there and this finishes on its own.
                {signinUrl ? (
                  <>
                    {" "}
                    No page opened?{" "}
                    <a
                      href={signinUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="underline underline-offset-2"
                    >
                      Open the Google sign-in page
                    </a>
                    .
                  </>
                ) : null}
              </p>
            ) : null}

            {driveReady && drive && drive.folders.length > 0 ? (
              <p className="px-1 text-xs leading-relaxed text-muted-foreground">
                Folders ready in Drive: {drive.folders.join(", ")}.
              </p>
            ) : null}
          </>
        )}

        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
      </div>
    </Modal>
  );
}

function DestinationOption({
  icon,
  title,
  description,
  ready,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  ready: boolean;
  action: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3",
        ready ? "border-foreground/40 bg-muted/40" : "border-border",
      )}
    >
      <div className="flex min-w-0 items-start gap-3">
        <span className="mt-0.5 text-muted-foreground">{icon}</span>
        <div className="min-w-0 space-y-0.5">
          <p className="flex items-center gap-1.5 text-sm font-medium text-foreground">
            {title}
            {ready ? (
              <Check className="size-3.5 text-foreground" aria-label="Ready" />
            ) : null}
          </p>
          <p className="max-w-prose break-words text-xs leading-relaxed text-muted-foreground">
            {description}
          </p>
        </div>
      </div>
      {action}
    </div>
  );
}
