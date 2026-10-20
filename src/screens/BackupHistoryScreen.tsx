import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Fingerprint, Folder, Loader2, Trash2 } from "lucide-react";

import { EmptyState, SectionHeading } from "@/components/EmptyState";
import { GoogleDriveMark } from "@/components/icons";
import { InfoHint } from "@/components/InfoHint";
import { Modal } from "@/components/Modal";
import { RunBackupPanel } from "@/components/RunBackupPanel";
import { useToast } from "@/components/Toaster";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { ApiError, api, type BackupRun } from "@/lib/api";
import { formatBytes, formatDateTime, formatRunStatus } from "@/lib/format";

/** Rows per page. The backend clamps the value it is given. */
const PAGE_SIZE = 25;

/**
 * Back up a database, and the history of what has been run.
 *
 * The panel at the top starts a run and follows it live; the table below is a
 * view over the `backup_runs` table and nothing else. If no backup has been
 * taken the table is empty and so is the history - there is no sample data.
 */
export function BackupHistoryScreen() {
  const { toast } = useToast();
  const [runs, setRuns] = useState<BackupRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmingClear, setConfirmingClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setRuns(await api.listBackupRuns(PAGE_SIZE));
    } catch (loadError) {
      setError(
        loadError instanceof ApiError
          ? loadError.message
          : "The backup history could not be loaded.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const clearHistory = useCallback(async () => {
    setClearing(true);
    setError(null);

    try {
      const removed = await api.clearBackupHistory();
      setConfirmingClear(false);
      await load();
      toast({
        variant: "success",
        title: "History cleared",
        description:
          removed === 1
            ? "1 recorded run was forgotten. Backup files were not touched."
            : `${removed} recorded runs were forgotten. Backup files were not touched.`,
      });
    } catch (clearError) {
      setError(
        clearError instanceof ApiError
          ? clearError.message
          : "The history could not be cleared.",
      );
    } finally {
      setClearing(false);
    }
  }, [load, toast]);

  return (
    <div className="flex flex-col gap-6">
      <SectionHeading
        title="Back Up"
        description="Start a backup of one database, then follow it while it runs."
      />
      <RunBackupPanel onFinished={() => void load()} />
      <ConfirmClear
        open={confirmingClear}
        busy={clearing}
        runCount={runs.length}
        onClose={() => setConfirmingClear(false)}
        onConfirm={() => void clearHistory()}
      />

      <SectionHeading
        title="Backup History"
        description="Every run that has been recorded on this device."
        action={
          runs.length > 0 ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmingClear(true)}
            >
              <Trash2 className="size-4" aria-hidden />
              Clear history
            </Button>
          ) : null
        }
      />

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {loading ? (
        <div className="flex h-20 items-center justify-center">
          <Loader2
            className="size-4 animate-spin text-muted-foreground"
            aria-label="Loading"
          />
        </div>
      ) : runs.length === 0 ? (
        <EmptyState
          title="No backups yet"
          description="Run a backup above and it will show up here, with where the file was saved."
        />
      ) : (
        <div className="overflow-hidden rounded-xl border border-border">
          <table className="w-full table-auto border-collapse text-sm">
            <caption className="sr-only">
              Recorded database backups, most recent first
            </caption>
            <thead>
              <tr className="border-b border-border bg-muted text-left">
                <Th className="w-[20%]">Database</Th>
                <Th className="w-[30%]">Status</Th>
                <Th className="w-[14%] whitespace-nowrap">Finished</Th>
                <Th className="w-[8%] whitespace-nowrap text-right">Size</Th>
                <Th className="w-[28%]">Saved to</Th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id} className="border-b border-border last:border-0">
                  <Td>
                    <span className="block truncate font-medium text-foreground">
                      {run.databaseLabel ?? "Removed database"}
                    </span>
                    <span className="block truncate text-xs text-muted-foreground">
                      {[run.engineLabel, run.databaseName]
                        .filter(Boolean)
                        .join(" - ") || "-"}
                    </span>
                  </Td>
                  <Td>
                    <span className="block font-medium text-foreground">
                      {formatRunStatus(run.status)}
                    </span>
                    {/*
                      Wrapped rather than truncated: a reason that explains the
                      failure is the whole point of the row, and a clipped
                      sentence tells the owner nothing.
                    */}
                    {run.failureReason ? (
                      <span className="mt-0.5 block text-xs break-words text-muted-foreground">
                        {run.failureReason}
                      </span>
                    ) : null}
                    {/*
                      A Drive note on a successful run stays separate from the
                      failure reason, so "saved locally, not uploaded" never
                      reads as "the backup failed".
                    */}
                    {run.driveError ? (
                      <span className="mt-0.5 block text-xs break-words text-muted-foreground">
                        Google Drive: {run.driveError}
                      </span>
                    ) : null}
                  </Td>
                  <Td className="whitespace-nowrap text-muted-foreground">
                    {formatDateTime(run.finishedAt ?? run.startedAt)}
                  </Td>
                  <Td className="whitespace-nowrap text-right text-muted-foreground">
                    {formatBytes(run.sizeBytes)}
                  </Td>
                  <Td>
                    <SavedLocation run={run} />
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/**
 * Confirmation for clearing history.
 *
 * It spells out exactly what is and is not removed, because "clear history"
 * could be misread as "delete my backups".
 */
function ConfirmClear({
  open,
  busy,
  runCount,
  onClose,
  onConfirm,
}: {
  open: boolean;
  busy: boolean;
  runCount: number;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal
      open={open}
      title="Clear backup history"
      description="This removes the recorded list of backup runs from BackMeUp."
      onClose={() => !busy && onClose()}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Keep history
          </Button>
          <Button onClick={onConfirm} disabled={busy}>
            {busy ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <Trash2 className="size-4" aria-hidden />
            )}
            {busy ? "Clearing" : "Clear history"}
          </Button>
        </>
      }
    >
      <p className="text-sm leading-relaxed text-muted-foreground">
        {runCount} recorded {runCount === 1 ? "run" : "runs"} will be forgotten,
        and the dashboard counts will go back to zero.
      </p>
      <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
        Your backup files are <strong className="text-foreground">not</strong>{" "}
        touched. Anything already written to your backup folder stays there.
      </p>
    </Modal>
  );
}

/**
 * Where a finished run put its file.
 *
 * A local copy shows the folder plus the file name; a Drive copy shows the path
 * inside the account. A run that used both shows both, so the row never has to
 * be guessed at.
 */
function SavedLocation({ run }: { run: BackupRun }) {
  const localPath = run.fileName
    ? run.destinationLocation
      ? `${run.destinationLocation}\\${run.fileName}`
      : run.fileName
    : null;

  if (!localPath && !run.drivePath) {
    return <span className="text-xs text-muted-foreground">-</span>;
  }

  return (
    <div className="flex flex-col gap-1.5">
      {localPath ? (
        <span className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <Folder className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span className="min-w-0 break-all" title={localPath}>
            {localPath}
          </span>
        </span>
      ) : null}
      {run.drivePath ? (
        <span className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <GoogleDriveMark className="mt-0.5 size-3.5 shrink-0" />
          <span className="min-w-0 break-all" title={run.drivePath}>
            {run.drivePath}
          </span>
        </span>
      ) : null}
      {run.sha256 ? (
        <span className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <Fingerprint className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span className="min-w-0 break-all font-mono text-[11px]">
            {run.sha256.slice(0, 16)}
            <InfoHint label="About the checksum">
              The SHA-256 of this file, taken while it was written. Hash the
              file again and the value must match. A different value means the
              file is no longer the one this backup produced.
            </InfoHint>
          </span>
        </span>
      ) : null}
    </div>
  );
}

function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th
      scope="col"
      className={`px-3 py-2.5 text-xs font-medium text-muted-foreground ${className ?? ""}`}
    >
      {children}
    </th>
  );
}

function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <td className={`px-3 py-3 align-top ${className ?? ""}`}>{children}</td>
  );
}
