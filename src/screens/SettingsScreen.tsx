import { useCallback, useEffect, useState } from "react";
import {
  FolderOpen,
  FolderSync,
  Loader2,
  Moon,
  PlugZap,
  Sun,
  Unplug,
} from "lucide-react";

import { Panel, PanelRow, SectionHeading } from "@/components/EmptyState";
import { GoogleDriveMark } from "@/components/icons";
import { InfoHint } from "@/components/InfoHint";
import { useToast } from "@/components/Toaster";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/ThemeProvider";
import {
  ApiError,
  api,
  onDriveSigninUrl,
  type BackupDestination,
  type GoogleDriveStatus,
} from "@/lib/api";
import { notifyDestinationsChanged } from "@/lib/events";
import { formatBytes } from "@/lib/format";

interface SettingsScreenProps {
  fullName: string;
  email: string;
  onOpenSecurity: () => void;
  onSignOut: () => void;
}

type DestinationStatus = "loading" | "ready" | "error";

/**
 * Where backups go, appearance and the account.
 *
 * Local folder and Google Drive are both first-class destinations: either can
 * be the only one, and when both are set up every backup is written locally and
 * uploaded. The title bar shows the live state; this screen holds the controls.
 */
export function SettingsScreen({
  fullName,
  email,
  onOpenSecurity,
  onSignOut,
}: SettingsScreenProps) {
  const { toast } = useToast();
  const { theme, toggleTheme } = useTheme();
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [status, setStatus] = useState<DestinationStatus>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      setDestinations(await api.listDestinations());
      setStatus("ready");
    } catch (error) {
      setLoadError(
        error instanceof ApiError
          ? error.message
          : "Your backup destinations could not be loaded.",
      );
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function chooseFolder() {
    setWorking(true);
    try {
      const result = await api.chooseLocalBackupFolder();
      // A cancelled dialog changes nothing.
      if (result.cancelled) return;

      await load();
      notifyDestinationsChanged();
      toast({
        variant: "success",
        title: "Backup folder saved",
        description: result.location
          ? `Every backup will also be written to ${result.location}.`
          : "Every backup will be written to the folder you chose.",
      });
    } catch (error) {
      toast({
        variant: "error",
        title: "That folder could not be used",
        description:
          error instanceof ApiError
            ? error.message
            : "The folder picker did not return a usable folder.",
      });
    } finally {
      setWorking(false);
    }
  }

  async function clearFolder() {
    setWorking(true);
    try {
      await api.clearLocalBackupFolder();
      await load();
      notifyDestinationsChanged();
      toast({
        variant: "info",
        title: "Local folder removed",
        description:
          "Backups will only be saved to Google Drive from now on. Files already in the folder are untouched.",
      });
    } catch (error) {
      toast({
        variant: "error",
        title: "The folder could not be removed",
        description:
          error instanceof ApiError
            ? error.message
            : "BackMeUp could not update the local backup folder.",
      });
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionHeading title="Settings" />

      {loadError ? (
        <Alert variant="destructive">
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-2">
        <h2 className="flex items-center gap-1.5 text-sm font-medium text-foreground">
          Where backups are saved
          <InfoHint label="About backup destinations">
            A backup can go to one place or both. Both is the safest: one copy
            on this computer and one in Google Drive.
          </InfoHint>
        </h2>

        {status === "loading" ? (
          <div className="flex h-16 items-center justify-center">
            <Loader2
              className="size-4 animate-spin text-muted-foreground"
              aria-label="Loading"
            />
          </div>
        ) : (
          <Panel className="divide-y divide-border">
            <LocalFolderRow
              destinations={destinations}
              working={working}
              onChoose={() => void chooseFolder()}
              onClear={() => void clearFolder()}
            />
            <GoogleDriveRow />
          </Panel>
        )}
      </div>

      <div className="space-y-2">
        <h2 className="text-sm font-medium text-foreground">Appearance</h2>
        <Panel>
          <PanelRow
            title="Theme"
            description="Light or dark. Remembered on this device."
          >
            <Button variant="outline" size="sm" onClick={toggleTheme}>
              {theme === "dark" ? (
                <Sun className="size-4" aria-hidden="true" />
              ) : (
                <Moon className="size-4" aria-hidden="true" />
              )}
              {theme === "dark" ? "Light" : "Dark"}
            </Button>
          </PanelRow>
        </Panel>
      </div>

      <div className="space-y-2">
        <h2 className="text-sm font-medium text-foreground">Backups</h2>
        <Panel>
          <PanelRow
            title="Automatic backups"
            description="Not available yet. For now, BackMeUp only backs up when you ask it to."
          />
        </Panel>
      </div>

      <div className="space-y-2">
        <h2 className="text-sm font-medium text-foreground">Account</h2>
        <Panel className="divide-y divide-border">
          <PanelRow title={fullName} description={email} />
          <PanelRow
            title="Account security"
            description="Recovery codes and password."
          >
            <Button variant="outline" size="sm" onClick={onOpenSecurity}>
              Manage
            </Button>
          </PanelRow>
          <PanelRow
            title="Sign out"
            description="End this session on this device."
          >
            <Button variant="ghost" size="sm" onClick={onSignOut}>
              Sign out
            </Button>
          </PanelRow>
        </Panel>
      </div>
    </div>
  );
}

/** The local folder, as one row with its own controls. */
function LocalFolderRow({
  destinations,
  working,
  onChoose,
  onClear,
}: {
  destinations: BackupDestination[];
  working: boolean;
  onChoose: () => void;
  onClear: () => void;
}) {
  const folder = destinations.find((item) => item.kind === "local_folder");

  return (
    <PanelRow
      title={
        <span className="flex items-center gap-1.5">
          <FolderOpen
            className="size-4 text-muted-foreground"
            aria-hidden="true"
          />
          This computer
          <InfoHint label="About the local backup folder">
            Backups are stored in a BackMeUp folder inside the folder you
            choose, then one folder per database, then one per day. Changing
            the folder does not move or delete backups already written.
          </InfoHint>
        </span>
      }
      description={
        folder?.location ??
        "Not set up. Choose a folder to keep a copy of every backup on this computer."
      }
    >
      <Button variant="outline" size="sm" onClick={onChoose} disabled={working}>
        {working ? (
          <Loader2 className="size-4 animate-spin" aria-hidden="true" />
        ) : null}
        {folder?.location ? "Change" : "Choose folder"}
      </Button>
      {folder?.location ? (
        <Button variant="ghost" size="sm" onClick={onClear} disabled={working}>
          Clear
        </Button>
      ) : null}
    </PanelRow>
  );
}

/**
 * Google Drive, as a destination in its own right.
 *
 * Connecting opens the owner's browser at Google's consent screen. The wait has
 * a visible Cancel: a browser profile that opens somewhere unexpected should
 * never leave the app spinning until the timeout.
 */
function GoogleDriveRow() {
  const { toast } = useToast();
  const [status, setStatus] = useState<GoogleDriveStatus | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [testing, setTesting] = useState(false);
  // The sign-in URL, sent by the backend as soon as it exists. Kept so an owner
  // whose browser did not open can still finish signing in.
  const [signinUrl, setSigninUrl] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStatus(await api.googleDriveStatus());
    } catch {
      setStatus(null);
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    return onDriveSigninUrl((url) => setSigninUrl(url));
  }, []);

  const connect = useCallback(async () => {
    setConnecting(true);
    setSigninUrl(null);
    try {
      const result = await api.connectGoogleDrive();
      setStatus(result);
      notifyDestinationsChanged();
      toast({
        variant: "success",
        title: "Google Drive connected",
        description:
          result.folders.length > 0
            ? `Folders ready: ${result.folders.join(", ")}.`
            : "Your databases will get their folders the next time one is backed up.",
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === "drive_cancelled") {
        toast({
          variant: "info",
          title: "Sign-in cancelled",
          description: "Nothing was changed and no access was granted.",
        });
      } else {
        toast({
          variant: "error",
          title: "Google Drive could not be connected",
          description:
            error instanceof ApiError
              ? error.message
              : "The sign-in did not complete. Try again.",
        });
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

  const disconnect = useCallback(async () => {
    setBusy(true);
    try {
      setStatus(await api.disconnectGoogleDrive());
      notifyDestinationsChanged();
      toast({
        variant: "info",
        title: "Google Drive disconnected",
        description:
          "Files already in your Drive were left alone. Backups go only to the folder on this computer now.",
      });
    } catch (error) {
      toast({
        variant: "error",
        title: "Google Drive could not be disconnected",
        description:
          error instanceof ApiError
            ? error.message
            : "BackMeUp could not update the Google Drive sign-in.",
      });
    } finally {
      setBusy(false);
    }
  }, [toast]);

  const syncFolders = useCallback(async () => {
    setSyncing(true);
    try {
      const result = await api.syncGoogleDriveFolders();
      setStatus(result);
      toast({
        variant: "success",
        title: "Folders are up to date",
        description:
          result.folders.length > 0
            ? `Ready in Drive: ${result.folders.join(", ")}.`
            : "No database connections yet, so there was nothing to create.",
      });
    } catch (error) {
      toast({
        variant: "error",
        title: "Folders could not be prepared",
        description:
          error instanceof ApiError
            ? error.message
            : "Google Drive did not answer. Check your connection and try again.",
      });
    } finally {
      setSyncing(false);
    }
  }, [toast]);

  const testConnection = useCallback(async () => {
    setTesting(true);
    try {
      const free = await api.testGoogleDrive();
      toast({
        variant: "success",
        title: "Google Drive is working",
        description:
          free !== null
            ? `${formatBytes(free)} free in your Google account.`
            : "Connected. Google did not report free space for this account.",
      });
    } catch (error) {
      // A dead grant is cleared by the backend, so reload to show Connect
      // again rather than a stale "connected" state.
      if (error instanceof ApiError && error.code === "drive_reconnect") {
        await load();
        notifyDestinationsChanged();
      }
      toast({
        variant: "error",
        title: "Google Drive could not be reached",
        description:
          error instanceof ApiError
            ? error.message
            : "The test did not complete. Try again.",
      });
    } finally {
      setTesting(false);
    }
  }, [load, toast]);

  const connected = status?.connected === true;
  const anyBusy = busy || testing || syncing || connecting;

  return (
    <>
      <PanelRow
        title={
          <span className="flex items-center gap-1.5">
            <GoogleDriveMark className="size-4" />
            Google Drive
            <InfoHint label="About Google Drive">
              Backups are uploaded to BackMeUp/&lt;database&gt;/&lt;date&gt; in
              your Drive. BackMeUp can only see the files it creates there, never
              the rest of your account. Drive storage is shared with the rest of
              your account, so check your free space if you back up large
              databases.
            </InfoHint>
          </span>
        }
        description={
          !loaded
            ? "Checking..."
            : connected
              ? "Every backup is also uploaded to your Drive."
              : "Sign in with Google to also keep a copy of every backup in your Drive."
        }
      >
        {connected ? (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void testConnection()}
              disabled={anyBusy}
            >
              {testing ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <PlugZap className="size-4" aria-hidden="true" />
              )}
              {testing ? "Checking" : "Test"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void syncFolders()}
              disabled={anyBusy}
            >
              {syncing ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <FolderSync className="size-4" aria-hidden="true" />
              )}
              {syncing ? "Preparing" : "Sync folders"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void disconnect()}
              disabled={anyBusy}
            >
              <Unplug className="size-4" aria-hidden="true" />
              Disconnect
            </Button>
          </>
        ) : connecting ? (
          <Button variant="ghost" size="sm" onClick={() => void cancelConnect()}>
            Cancel sign-in
          </Button>
        ) : (
          <Button
            size="sm"
            onClick={() => void connect()}
            disabled={!loaded || anyBusy}
          >
            Connect
          </Button>
        )}
      </PanelRow>

      {connecting ? (
        <div className="px-4 pb-3.5">
          <p className="text-xs leading-relaxed text-muted-foreground">
            A Google sign-in page should have opened in your browser. Approve
            access there and this finishes on its own.
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
        </div>
      ) : null}

      {connected && status ? (
        <div className="px-4 pb-3.5">
          <p className="text-xs leading-relaxed text-muted-foreground">
            {status.folders.length > 0 ? (
              <>
                Folder ready in Drive:{" "}
                <span className="text-foreground">
                  {status.folders.join(", ")}
                </span>
                . Each backup goes into the folder for its database, under a
                folder named after the day.
              </>
            ) : (
              "No database connections yet, so no folders have been created."
            )}
          </p>
        </div>
      ) : null}
    </>
  );
}
