import { useCallback, useEffect, useState } from "react";
import {
  Database,
  FilePen,
  Loader2,
  Pencil,
  PlugZap,
  Plus,
  ShieldCheck,
  Trash2,
} from "lucide-react";

import { DatabaseDialog } from "@/components/DatabaseDialog";
import { EmptyState, SectionHeading } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  ApiError,
  api,
  type ConnectionCheckSummary,
  type DatabaseConnection,
  type EngineCatalogue,
} from "@/lib/api";
import {
  type DatabaseDraft,
  clearDatabaseDraft,
  draftMatches,
  loadDatabaseDraft,
} from "@/lib/databaseDraft";
import { notifyNoticesChanged } from "@/lib/events";
import { describeTestState, formatDateTime } from "@/lib/format";

type DialogMode = { kind: "closed" } | { kind: "add" } | { kind: "edit"; row: DatabaseConnection };

/** Must match `SSH_TUNNEL_METHOD_ID` in the Rust engine registry. */
const SSH_TUNNEL_METHOD = "ssh-tunnel";

/**
 * The catalogue of database connections.
 *
 * Nothing is dialled on load. A row only ever shows a result that the backend
 * actually produced, and a past success is reported as history rather than as
 * proof that the server is reachable now.
 */
export function DatabasesScreen({
  editId,
  onEditHandled,
}: {
  /** A connection to open in the editor, asked for by a notice. */
  editId?: string | null;
  /** Called once that connection has been opened. */
  onEditHandled?: () => void;
} = {}) {
  const [databases, setDatabases] = useState<DatabaseConnection[]>([]);
  const [catalogue, setCatalogue] = useState<EngineCatalogue | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<DialogMode>({ kind: "closed" });
  /** A draft saved from the add/edit form, so it can be offered again. */
  const [draft, setDraft] = useState<DatabaseDraft | null>(() =>
    loadDatabaseDraft(),
  );
  const [pendingRemoval, setPendingRemoval] = useState<DatabaseConnection | null>(null);
  const [removing, setRemoving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  /** The result of the last sweep over every saved connection. */
  const [checkSummary, setCheckSummary] = useState<ConnectionCheckSummary | null>(
    null,
  );
  const [checking, setChecking] = useState(false);
  const [testNotice, setTestNotice] = useState<{
    id: string;
    outcome: "success" | "failed" | "unverified";
    message: string;
    /** Display-form fingerprint, present for `unverified` and changed keys. */
    fingerprint: string | null;
  } | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [engineCatalogue, rows] = await Promise.all([
        api.databaseEngines(),
        api.listDatabases(),
      ]);
      setCatalogue(engineCatalogue);
      setDatabases(rows);
    } catch (loadError) {
      setError(
        loadError instanceof ApiError
          ? loadError.message
          : "Your databases could not be loaded.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  /** Re-read the stored draft after anything that could have changed it. */
  const refreshDraft = useCallback(() => setDraft(loadDatabaseDraft()), []);

  /**
   * Open a connection that was asked to be fixed.
   *
   * A refused password is only useful if the fix is one click away, so the
   * bell hands the id over and this opens that connection's editor.
   */
  useEffect(() => {
    if (!editId) return;

    const row = databases.find((item) => item.id === editId);
    if (row) {
      setDialog({ kind: "edit", row });
    }
    onEditHandled?.();
  }, [editId, databases, onEditHandled]);

  /**
   * Open whatever the stored draft belongs to: the add form, or the row it
   * was editing. A draft whose row no longer exists has nothing to restore
   * into, so it is dropped.
   */
  function resumeDraft() {
    if (!draft) return;

    if (!draft.editingId) {
      setDialog({ kind: "add" });
      return;
    }

    const row = databases.find((item) => item.id === draft.editingId) ?? null;
    if (!row) {
      clearDatabaseDraft();
      setDraft(null);
      return;
    }
    setDialog({ kind: "edit", row });
  }

  /** Merge one updated row back into the list without a full reload. */
  function merge(database: DatabaseConnection) {    setDatabases((current) => {
      const exists = current.some((row) => row.id === database.id);
      return exists
        ? current.map((row) => (row.id === database.id ? database : row))
        : [...current, database];
    });
  }

  /**
   * Test every saved connection at once.
   *
   * A password that was rotated on the server leaves the saved copy behind,
   * and this is how the failing one is found, rather than meeting the
   * same failure on every backup.
   */
  async function checkAll() {
    setChecking(true);
    setError(null);
    try {
      const summary = await api.checkAllConnections();
      setCheckSummary(summary);
      notifyNoticesChanged();
      await load();
    } catch (checkError) {
      setError(
        checkError instanceof ApiError
          ? checkError.message
          : "The connections could not be checked.",
      );
    } finally {
      setChecking(false);
    }
  }

  async function handleTest(row: DatabaseConnection, hostKeyFingerprint?: string) {
    setTestingId(row.id);
    setError(null);
    setTestNotice(null);
    try {
      const result = await api.testSavedDatabase(row.id, hostKeyFingerprint);
      setTestNotice({
        id: row.id,
        outcome: result.outcome,
        message: result.message,
        fingerprint: result.hostKeyFingerprint,
      });
      // Re-read so the stored verdict matches what the user just saw.
      await load();
      // A refused password is now a notice, so the bell has to hear about it.
      notifyNoticesChanged();
    } catch (testError) {
      setError(
        testError instanceof ApiError
          ? testError.message
          : "The connection test could not be run.",
      );
    } finally {
      setTestingId(null);
    }
  }

  /** Whether a stored connection has the secrets its method needs to test. */
  function testable(row: DatabaseConnection): boolean {
    if (!row.hasCredentials) return false;
    if (row.connectionMethod === SSH_TUNNEL_METHOD && !row.hasSshCredentials) {
      return false;
    }
    return true;
  }

  async function handleDelete() {
    if (!pendingRemoval) return;

    setRemoving(true);
    setError(null);
    try {
      await api.deleteDatabase(pendingRemoval.id);
      setDatabases((current) =>
        current.filter((row) => row.id !== pendingRemoval.id),
      );
      // A draft editing the removed row can never be restored again.
      if (draftMatches(loadDatabaseDraft(), pendingRemoval.id)) {
        clearDatabaseDraft();
      }
      refreshDraft();
      setPendingRemoval(null);
    } catch (deleteError) {
      setError(
        deleteError instanceof ApiError
          ? deleteError.message
          : "That database could not be removed.",
      );
    } finally {
      setRemoving(false);
    }
  }

  const editing = dialog.kind === "edit" ? dialog.row : null;

  return (
    <div className="flex flex-col gap-6">
      <SectionHeading
        title="Databases"
        description="Connections BackMeUp will back up. No hosting provider is assumed."
        action={
          <>
            {draft ? (
              <Button
                variant="outline"
                onClick={resumeDraft}
                disabled={!catalogue}
                title={`Draft saved ${formatDateTime(draft.savedAt)}`}
              >
                <FilePen className="size-4" aria-hidden="true" />
                Resume draft
              </Button>
            ) : null}
            <Button
              variant="outline"
              onClick={() => void checkAll()}
              disabled={checking || databases.length === 0}
              title="Test every saved connection and report which passwords the server no longer accepts"
            >
              {checking ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <ShieldCheck className="size-4" aria-hidden="true" />
              )}
              Check all
            </Button>
            <Button
              onClick={() => setDialog({ kind: "add" })}
              disabled={!catalogue}
            >
              <Plus className="size-4" aria-hidden="true" />
              Add Database
            </Button>
          </>
        }
      />

      {checkSummary ? (
        <p className="text-xs text-muted-foreground">
          Checked {checkSummary.tested}{" "}
          {checkSummary.tested === 1 ? "connection" : "connections"}:{" "}
          {checkSummary.ok} accepted, {checkSummary.rejected} refused,{" "}
          {checkSummary.unreachable} could not be reached.
          {checkSummary.rejected > 0
            ? " The refused ones are listed in the notifications."
            : ""}
        </p>
      ) : null}

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
      ) : databases.length === 0 ? (
        <EmptyState
          title="No databases yet"
          description={`Add a database to record where it lives. BackMeUp connects to ${
            catalogue?.engines.map((engine) => engine.label).join(", ") ?? "several engines"
          }.`}
          action={
            <Button
              variant="outline"
              onClick={() => setDialog({ kind: "add" })}
              disabled={!catalogue}
            >
              <Database className="size-4" aria-hidden="true" />
              Add Database
            </Button>
          }
        />
      ) : (
        <ul className="flex flex-col gap-2">
          {databases.map((database) => (
            <li
              key={database.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3"
            >
              <div className="min-w-0 flex-1 space-y-0.5">
                <p className="truncate text-sm font-medium text-foreground">
                  {database.label}
                </p>
                <p className="truncate text-xs text-muted-foreground">
                  {describeTarget(database)}
                </p>
                <p className="text-xs text-muted-foreground">
                  {describeTestState(
                    database.testState,
                    database.lastTestedAt,
                    database.hasCredentials,
                  )}
                </p>
                {database.connectionMethod === SSH_TUNNEL_METHOD &&
                !database.hasSshCredentials ? (
                  <p className="text-xs text-muted-foreground">
                    SSH sign-in not stored yet - edit this connection to add
                    it.
                  </p>
                ) : null}
                {testNotice?.id === database.id ? (
                  <div className="space-y-1.5">
                    <p className="text-xs font-medium text-foreground">
                      {testNotice.message}
                    </p>
                    {testNotice.outcome !== "success" &&
                    testNotice.fingerprint ? (
                      <div className="flex flex-wrap items-center gap-2">
                        <code className="break-all font-mono text-[11px] text-muted-foreground">
                          {testNotice.fingerprint}
                        </code>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            void handleTest(database, testNotice.fingerprint!)
                          }
                          disabled={testingId === database.id}
                        >
                          Trust this key &amp; connect
                        </Button>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>

              <div className="flex shrink-0 items-center gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void handleTest(database)}
                  disabled={testingId === database.id || !testable(database)}
                  aria-label={`Test the connection to ${database.label}`}
                >
                  {testingId === database.id ? (
                    <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <PlugZap className="size-4" aria-hidden="true" />
                  )}
                  Test
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setDialog({ kind: "edit", row: database })}
                  disabled={!catalogue}
                  aria-label={`Edit ${database.label}`}
                >
                  <Pencil className="size-4" aria-hidden="true" />
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setPendingRemoval(database)}
                  aria-label={`Remove ${database.label}`}
                >
                  <Trash2 className="size-4" aria-hidden="true" />
                  Remove
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {catalogue ? (
        <DatabaseDialog
          open={dialog.kind !== "closed"}
          catalogue={catalogue}
          existing={editing}
          onClose={() => {
            setDialog({ kind: "closed" });
            refreshDraft();
          }}
          onSaved={(database) => {
            merge(database);
            refreshDraft();
          }}
        />
      ) : null}

      <Modal
        open={pendingRemoval !== null}
        title="Remove database"
        description={
          pendingRemoval
            ? `"${pendingRemoval.label}" and its stored credentials will be removed from BackMeUp. Backups already recorded for it are kept.`
            : undefined
        }
        onClose={() => setPendingRemoval(null)}
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => setPendingRemoval(null)}
              disabled={removing}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => void handleDelete()}
              disabled={removing}
            >
              {removing ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : null}
              Remove
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted-foreground">
          This only removes the connection record and its saved credentials.
          Nothing on the database server is changed.
        </p>
      </Modal>
    </div>
  );
}

/**
 * One-line summary of where a database lives, built only from stored,
 * already-validated values. Nothing is inferred when a field is absent.
 */
function describeTarget(database: DatabaseConnection): string {
  const where = database.host
    ? `${database.host}${database.port ? `:${database.port}` : ""}`
    : "This machine";

  const user = database.username ? ` as ${database.username}` : "";

  // Public addressing only; never a secret.
  const tunnel =
    database.connectionMethod === SSH_TUNNEL_METHOD && database.sshHost
      ? ` via ${database.sshUsername ?? "?"}@${database.sshHost}:${database.sshPort ?? 22}`
      : "";

  return `${database.engineLabel} - ${where}/${database.databaseName}${user}${tunnel}`;
}