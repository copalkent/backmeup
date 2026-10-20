import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Loader2, Play, XCircle } from "lucide-react";

import { EmptyState, SectionHeading } from "@/components/EmptyState";
import { DestinationDialog } from "@/components/DestinationDialog";
import { InfoHint } from "@/components/InfoHint";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toaster";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  ApiError,
  api,
  onBackupProgress,
  type BackupOverview,
  type DatabaseConnection,
} from "@/lib/api";
import { formatBytes, formatDateTime, formatRunStatus } from "@/lib/format";
import { cn } from "@/lib/utils";

interface DashboardScreenProps {
  fullName: string;
  /** Recovery codes left, or null while the status is unknown. */
  remainingRecoveryCodes: number | null;
  onOpenSecurity: () => void;
  onAddDatabase: () => void;
  /** Opens the screen where a single database is chosen and followed. */
  onOpenBackups: () => void;
}

/** What one database in a "back up all" batch did. */
type BatchItem = {
  id: string;
  label: string;
  state: "waiting" | "running" | "succeeded" | "failed" | "skipped";
  detail: string;
};

/**
 * Overview of what is actually configured, and the one-click backup.
 *
 * Every figure is read from the backend. There is no sample data and nothing is
 * inferred: when no backup has ever been recorded the summary says so rather
 * than showing a placeholder date or status.
 */
export function DashboardScreen({
  fullName,
  remainingRecoveryCodes,
  onOpenSecurity,
  onAddDatabase,
  onOpenBackups,
}: DashboardScreenProps) {
  const { toast } = useToast();
  const [overview, setOverview] = useState<BackupOverview | null>(null);
  const [loading, setLoading] = useState(true);

  // "Back up all" state.
  const [batch, setBatch] = useState<BatchItem[] | null>(null);
  const [batchBusy, setBatchBusy] = useState(false);
  const [choosingDestination, setChoosingDestination] = useState(false);

  const load = useCallback(async () => {
    try {
      setOverview(await api.backupOverview());
    } catch {
      // Leave the figures blank rather than showing a fabricated zero.
      setOverview(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const hasDatabases = (overview?.databaseCount ?? 0) > 0;

  /**
   * Back up every eligible database, one after another.
   *
   * Sequential on purpose: the backend allows one run at a time, and hammering
   * a small hosting account with parallel dumps is how throttling happens. Each
   * database reports its own outcome, so one failure does not hide the rest.
   */
  const backUpAll = useCallback(async () => {
    let connections: DatabaseConnection[];
    try {
      connections = await api.listDatabases();
    } catch {
      toast({
        variant: "error",
        title: "Could not read your databases",
        description: "Your connection list could not be loaded. Try again.",
      });
      return;
    }

    const eligible = connections.filter(
      (connection) =>
        (connection.engine === "mysql" || connection.engine === "mariadb") &&
        connection.hasCredentials,
    );

    if (eligible.length === 0) {
      toast({
        variant: "error",
        title: "Nothing to back up",
        description:
          "Add a MySQL or MariaDB connection with a stored password first.",
      });
      return;
    }

    setBatchBusy(true);
    setBatch(
      eligible.map((connection) => ({
        id: connection.id,
        label: connection.label,
        state: "waiting",
        detail: "Waiting",
      })),
    );

    // Live progress for whichever run is in flight.
    const dispose = onBackupProgress((progress) => {
      setBatch((current) =>
        current?.map((item) =>
          item.state === "running"
            ? {
                ...item,
                detail: progress.rows
                  ? `${progress.objectsDone} tables, ${progress.rows} rows`
                  : progress.stage === "preparing"
                    ? "Opening the connection"
                    : "Reading",
              }
            : item,
        ) ?? null,
      );
    });

    let succeeded = 0;
    let failed = 0;

    for (const connection of eligible) {
      setBatch((current) =>
        current?.map((item) =>
          item.id === connection.id
            ? { ...item, state: "running", detail: "Starting" }
            : item,
        ) ?? null,
      );

      try {
        const result = await api.startBackupRun(connection.id);
        const ok = result.stage === "succeeded";
        if (ok) succeeded += 1;
        else failed += 1;

        setBatch((current) =>
          current?.map((item) =>
            item.id === connection.id
              ? {
                  ...item,
                  state: ok ? "succeeded" : "failed",
                  detail: ok
                    ? [
                        result.sizeBytes !== null
                          ? formatBytes(result.sizeBytes)
                          : null,
                        result.rows !== null ? `${result.rows} rows` : null,
                      ]
                        .filter(Boolean)
                        .join(", ")
                    : (result.reason ?? "Failed"),
                }
              : item,
          ) ?? null,
        );
      } catch (error) {
        failed += 1;
        setBatch((current) =>
          current?.map((item) =>
            item.id === connection.id
              ? {
                  ...item,
                  state: "failed",
                  detail:
                    error instanceof ApiError
                      ? error.message
                      : "The backup could not be started.",
                }
              : item,
          ) ?? null,
        );
      }
    }

    dispose();
    setBatchBusy(false);
    await load();

    // The modal spells out each database; the toast is the one-line summary
    // for the case where the app has already moved on to another screen.
    toast({
      variant: failed > 0 ? "error" : "success",
      title:
        failed > 0
          ? `Backed up ${succeeded} of ${eligible.length} databases`
          : `Backed up ${eligible.length} ${eligible.length === 1 ? "database" : "databases"}`,
      description:
        failed > 0
          ? "Open Backups to see what happened to each one. One failure does not affect the others."
          : "Every finished file is in your backup destination.",
    });
  }, [load, toast]);

  const batchFailed = batch?.filter((item) => item.state === "failed").length ?? 0;
  const batchSucceeded = batch?.filter((item) => item.state === "succeeded").length ?? 0;
  const hasDestination =
    overview?.hasLocalFolder === true || overview?.hasDrive === true;
  const canBackUpAll = !loading && hasDatabases && !batchBusy;

  const requestBackUpAll = useCallback(() => {
    if (!hasDestination) {
      setChoosingDestination(true);
      return;
    }

    void backUpAll();
  }, [backUpAll, hasDestination]);

  return (
    <div className="flex flex-col gap-6">
      <SectionHeading
        title={`Hi, ${fullName}`}
        description="Here is the state of your backups."
      />

      {remainingRecoveryCodes !== null && remainingRecoveryCodes <= 2 ? (
        <Alert variant="warning">
          <AlertDescription>
            {remainingRecoveryCodes === 0
              ? "You have used all your recovery codes. Generate a new set so you can still get back into BackMeUp."
              : `Only ${remainingRecoveryCodes} recovery code${remainingRecoveryCodes === 1 ? " is" : "s are"} left.`}{" "}
            <button
              type="button"
              onClick={onOpenSecurity}
              className="press underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              Account security
            </button>
          </AlertDescription>
        </Alert>
      ) : null}

      {loading ? (
        <div className="flex h-24 items-center justify-center">
          <Loader2
            className="size-4 animate-spin text-muted-foreground"
            aria-label="Loading"
          />
        </div>
      ) : (
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-4">
          <Stat
            label="Databases"
            value={overview?.databaseCount ?? null}
            hint="Saved database connections BackMeUp can back up."
          />
          <Stat
            label="Backups recorded"
            value={overview?.backupCount ?? null}
            hint="Every backup run so far, successful or not. Clearing history is the only thing that lowers this."
          />
          <Stat
            label="Saved to"
            value={overview?.destinationCount ?? null}
            hint="Where a copy can go: a folder on this computer, Google Drive, or both."
          />
          <LastBackup
            value={overview?.lastBackup ?? null}
            hint="The most recent run and whether it worked."
          />
        </dl>
      )}

      <div className="flex flex-col gap-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <Button size="lg" disabled={!canBackUpAll} onClick={requestBackUpAll}>
            {batchBusy ? (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            ) : (
              <Play className="size-4" aria-hidden="true" />
            )}
            {batchBusy ? "Backing up" : "Back Up All"}
          </Button>
          <Button
            variant="outline"
            size="lg"
            onClick={onOpenBackups}
            disabled={batchBusy}
          >
            Back up one database
          </Button>
          {!hasDatabases ? (
            <Button variant="outline" size="lg" onClick={onAddDatabase}>
              Add Database
            </Button>
          ) : null}
        </div>
        <p className="text-[13px] leading-relaxed text-muted-foreground">
          {!hasDatabases
            ? "Add a database connection to begin."
            : hasDestination
              ? "Backs up each database in turn, one at a time."
              : "Choose where backups are saved first: this computer, Google Drive, or both."}
        </p>
      </div>

      {!loading && !hasDatabases ? (
        <EmptyState
          title="No databases yet"
          description="Add a MySQL or MariaDB connection and BackMeUp can start backing it up."
          action={
            <Button variant="outline" onClick={onAddDatabase}>
              Add Database
            </Button>
          }
        />
      ) : null}

      {!loading && hasDatabases && !hasDestination ? (
        <EmptyState
          title="No place to save backups"
          description="Choose a folder on this computer, connect Google Drive, or both. Until then, a backup has nowhere to go."
          action={
            <Button
              variant="outline"
              onClick={() => setChoosingDestination(true)}
            >
              Choose destination
            </Button>
          }
        />
      ) : null}

      <DestinationDialog
        open={choosingDestination}
        onClose={() => setChoosingDestination(false)}
        onReady={() => {
          setChoosingDestination(false);
          void load().then(() => void backUpAll());
        }}
      />

      {/*
        The result of a "back up all" run stays on screen until it is dismissed,
        so a failure is never something that has to be remembered. The toast
        carries the one-line summary.
      */}
      {batch ? (
        <Modal
          open
          title={batchBusy ? "Backing up your databases" : "Backup results"}
          description={
            batchBusy
              ? "Each database is backed up in turn. Nothing on the server is changed."
              : "Here is what happened to each database."
          }
          onClose={() => !batchBusy && setBatch(null)}
          footer={
            batchBusy ? (
              <Button variant="ghost" disabled>
                <Loader2 className="size-4 animate-spin" aria-hidden />
                Working
              </Button>
            ) : (
              <Button onClick={() => setBatch(null)}>Close</Button>
            )
          }
        >
          <ul className="flex flex-col gap-2">
            {batch.map((item) => (
              <li
                key={item.id}
                className="flex items-start gap-2.5 rounded-lg border border-border px-3.5 py-3"
              >
                {item.state === "succeeded" ? (
                  <CheckCircle2
                    className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                    aria-hidden
                  />
                ) : item.state === "failed" ? (
                  <XCircle
                    className="mt-0.5 size-4 shrink-0 text-red-600 dark:text-red-400"
                    aria-hidden
                  />
                ) : (
                  <Loader2
                    className={cn(
                      "mt-0.5 size-4 shrink-0",
                      item.state === "running"
                        ? "animate-spin text-muted-foreground"
                        : "text-muted-foreground/40",
                    )}
                    aria-hidden
                  />
                )}
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-foreground">
                    {item.label}
                  </p>
                  <p className="text-xs break-words text-muted-foreground">
                    {item.detail}
                  </p>
                </div>
              </li>
            ))}
          </ul>

          {!batchBusy && batchFailed > 0 ? (
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
              {batchSucceeded} of {batch.length} succeeded, {batchFailed} failed.
              A failure in one database does not affect the others.
            </p>
          ) : null}
        </Modal>
      ) : null}
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: number | null;
  hint: string;
}) {
  return (
    <div className="bg-card px-5 py-4">
      <dt className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        {label}
        <InfoHint label={`About ${label}`}>{hint}</InfoHint>
      </dt>
      <dd className="mt-1.5 text-2xl font-semibold tracking-tight tabular-nums text-foreground">
        {value === null ? "-" : value}
      </dd>
    </div>
  );
}

function LastBackup({
  value,
  hint,
}: {
  value: { status: string; at: number } | null;
  hint: string;
}) {
  return (
    <div className="bg-card px-5 py-4">
      <dt className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        Last backup
        <InfoHint label="About the last backup">{hint}</InfoHint>
      </dt>
      <dd className="mt-1.5">
        {value ? (
          <>
            <span className="text-base font-semibold tracking-tight text-foreground">
              {formatRunStatus(value.status)}
            </span>
            <span className="mt-0.5 block text-xs text-muted-foreground">
              {formatDateTime(value.at)}
            </span>
          </>
        ) : (
          <span className="text-base font-normal text-muted-foreground">
            None yet
          </span>
        )}
      </dd>
    </div>
  );
}
