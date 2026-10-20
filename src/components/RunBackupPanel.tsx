import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2, Play, Square } from "lucide-react";

import { DestinationDialog } from "@/components/DestinationDialog";
import { InfoHint } from "@/components/InfoHint";
import { useToast } from "@/components/Toaster";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  ApiError,
  api,
  onBackupProgress,
  type BackupProgress,
  type DatabaseConnection,
} from "@/lib/api";
import { formatBytes } from "@/lib/format";

/** Progress events arrive at most this often, so elapsed time stays honest. */
const TICK_MS = 500;

/**
 * Start a backup and follow it while it runs.
 *
 * Two states matter here: a run is in flight with live counters, and no
 * destination has been chosen yet (the destination dialog is offered when a
 * backup is requested). The outcome of a finished run is a toast, so it is
 * visible wherever the owner has moved to.
 */
export function RunBackupPanel({ onFinished }: { onFinished?: () => void }) {
  const { toast } = useToast();
  const [databases, setDatabases] = useState<DatabaseConnection[]>([]);
  const [hasDestination, setHasDestination] = useState(false);
  /** The database whose backup is waiting for a destination choice. */
  const [pendingDatabase, setPendingDatabase] =
    useState<DatabaseConnection | null>(null);
  /** The backend's run id for the run in flight, needed to cancel it. */
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [progress, setProgress] = useState<BackupProgress | null>(null);
  const [elapsed, setElapsed] = useState(0);

  const running = activeRunId !== null;

  // Kept in a ref so the event listener is registered once and always sees the
  // current state, rather than re-subscribing on every render.
  const onFinishedRef = useRef(onFinished);
  onFinishedRef.current = onFinished;

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const [connections, destinations, active] = await Promise.all([
          api.listDatabases(),
          api.listDestinations(),
          api.activeBackupRun(),
        ]);

        if (cancelled) return;
        setDatabases(connections);

        const local = destinations.find((entry) => entry.kind === "local_folder");
        const drive = destinations.find((entry) => entry.kind === "google_drive");
        setHasDestination(
          Boolean(local?.location) || drive?.status === "configured",
        );

        // A run started before a reload keeps running; show it rather than
        // pretending nothing is happening.
        if (active) setActiveRunId(active.runId);
      } catch (error) {
        if (!cancelled) {
          toast({
            variant: "error",
            title: "Backups could not be loaded",
            description:
              error instanceof ApiError
                ? error.message
                : "Your database list and destinations could not be read.",
          });
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [toast]);

  useEffect(
    () =>
      onBackupProgress((update) => {
        if (
          update.stage === "succeeded" ||
          update.stage === "failed" ||
          update.stage === "cancelled"
        ) {
          // The run is over: stop showing it as in flight.
          setActiveRunId(null);
          setProgress(update);
          onFinishedRef.current?.();
          return;
        }

        setProgress(update);
      }),
    [],
  );

  // Elapsed time, so a slow table does not look frozen.
  useEffect(() => {
    if (!running) {
      setElapsed(0);
      return;
    }

    const started = Date.now();
    const timer = window.setInterval(() => {
      setElapsed(Date.now() - started);
    }, TICK_MS);

    return () => window.clearInterval(timer);
  }, [running]);

  const start = useCallback(
    async (database: DatabaseConnection) => {
      setProgress(null);

      try {
        // The command resolves when the run ends, so the id only becomes known
        // from the first progress event; until then the panel is busy but has
        // nothing to cancel by.
        setActiveRunId("pending");
        const outcome = await api.startBackupRun(database.id);
        onFinishedRef.current?.();

        if (outcome.stage === "succeeded") {
          const details = [
            outcome.fileName ?? (outcome.fileStem ? `${outcome.fileStem}.sql` : null),
            outcome.sizeBytes !== null ? formatBytes(outcome.sizeBytes) : null,
            outcome.rows !== null ? `${outcome.rows} rows` : null,
          ]
            .filter(Boolean)
            .join(" - ");

          const where = outcome.drivePath
            ? outcome.fileName
              ? `Saved to ${outcome.destinationLabel}: ${outcome.fileName}, and uploaded to ${outcome.drivePath}.`
              : `Uploaded to Google Drive: ${outcome.drivePath}.`
            : `Saved to ${outcome.destinationLabel}.`;

          toast({
            variant: "success",
            title: `${database.label} backed up`,
            description: [details, where].filter(Boolean).join(" - "),
          });
        } else if (outcome.stage === "cancelled") {
          toast({
            variant: "info",
            title: "Backup cancelled",
            description:
              "The incomplete file was removed. Nothing on the database server was changed.",
          });
        } else {
          toast({
            variant: "error",
            title: `${database.label} could not be backed up`,
            description: outcome.reason ?? "The run did not finish.",
          });
        }
      } catch (startError) {
        // A refusal rather than a failed run: no destination, no credential, or
        // a run already going.
        if (startError instanceof ApiError && startError.code === "no_destination") {
          setHasDestination(false);
          setPendingDatabase(database);
          return;
        }

        toast({
          variant: "error",
          title: "The backup could not be started",
          description:
            startError instanceof ApiError
              ? startError.message
              : "BackMeUp could not begin that backup.",
        });
      } finally {
        setActiveRunId(null);
      }
    },
    [toast],
  );

  const requestBackup = useCallback(
    (database: DatabaseConnection) => {
      if (hasDestination) {
        void start(database);
      } else {
        setPendingDatabase(database);
      }
    },
    [hasDestination, start],
  );

  const cancel = useCallback(async () => {
    // Nothing to cancel until the backend has issued a real run id.
    if (!activeRunId || activeRunId === "pending") return;

    try {
      await api.cancelBackupRun(activeRunId);
    } catch (cancelError) {
      toast({
        variant: "error",
        title: "The backup could not be stopped",
        description:
          cancelError instanceof ApiError
            ? cancelError.message
            : "BackMeUp could not ask the running backup to stop.",
      });
    }
  }, [activeRunId, toast]);

  return (
    <div className="flex flex-col gap-4">
      {/*
        Live status. There is no percentage: the table list is only known as it
        is read, so counters and elapsed time are shown instead of a bar that
        could not be honest.
      */}
      {running ? (
        <Alert>
          <AlertTitle className="flex items-center gap-2">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {progress?.databaseLabel ?? "Backing up"}
          </AlertTitle>
          <AlertDescription className="space-y-2 text-xs">
            <p>
              {stageLabel(progress?.stage)} - {progress?.objectsDone ?? 0}{" "}
              tables and views - {progress?.rows ?? 0} rows -{" "}
              {formatBytes(progress?.bytesWritten ?? 0)} -{" "}
              {formatElapsed(elapsed)}
            </p>
            <p className="text-muted-foreground">
              {progress?.stage === "uploading"
                ? "Uploading the finished backup to Google Drive. Nothing on the server is changed."
                : "Reading your database. Nothing on the server is changed, and no locks are taken, so your site keeps running."}
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void cancel()}
              disabled={activeRunId === "pending"}
            >
              <Square className="size-4" aria-hidden />
              Cancel backup
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="flex flex-col gap-2">
        <p className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          What a backup holds
          <InfoHint label="About the backup file">
            Every table and view in the database, with its rows, read in one
            consistent snapshot so the tables agree with each other. Nothing
            on the server is changed and no locks are taken, so your site
            keeps running. Triggers, stored procedures and events are not part
            of the file.
          </InfoHint>
        </p>
        {databases.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            Add a database connection first, then back it up from here.
          </p>
        ) : (
          databases.map((database) => {
            const supported =
              database.engine === "mysql" || database.engine === "mariadb";

            return (
              <div
                key={database.id}
                className="flex items-center justify-between gap-3 rounded-lg border border-border px-4 py-3"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-foreground">
                    {database.label}
                  </p>
                  <p className="truncate text-xs text-muted-foreground">
                    {supported
                      ? [
                          database.engineLabel,
                          database.databaseName,
                          database.connectionMethodLabel,
                        ]
                          .filter(Boolean)
                          .join(" - ")
                      : `${database.engineLabel} - backing this up is not supported yet`}
                  </p>
                </div>
                <Button
                  size="sm"
                  disabled={running || !database.hasCredentials || !supported}
                  onClick={() => requestBackup(database)}
                >
                  <Play className="size-4" aria-hidden />
                  Back up now
                </Button>
              </div>
            );
          })
        )}
      </div>

      <DestinationDialog
        open={pendingDatabase !== null}
        onClose={() => setPendingDatabase(null)}
        onReady={() => {
          const database = pendingDatabase;
          setPendingDatabase(null);
          setHasDestination(true);
          if (database) void start(database);
        }}
      />
    </div>
  );
}

/** Human wording for a run stage. */
function stageLabel(stage: string | undefined): string {
  switch (stage) {
    case "preparing":
      return "Opening the connection";
    case "reading":
      return "Reading your database";
    case "uploading":
      return "Uploading to Google Drive";
    default:
      return "Working";
  }
}

/** `12s`, `3m 04s`. */
function formatElapsed(milliseconds: number): string {
  const seconds = Math.floor(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(seconds % 60).padStart(2, "0")}s`;
}
