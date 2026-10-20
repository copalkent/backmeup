import { useEffect, useMemo, useRef, useState } from "react";
import { Loader2, PlugZap } from "lucide-react";

import { Modal } from "@/components/Modal";
import { PasswordField } from "@/components/PasswordField";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ApiError,
  api,
  type ConnectionTestResult,
  type DatabaseConnection,
  type EngineCatalogue,
  type SshTunnelInput,
} from "@/lib/api";
import {
  type DatabaseDraftFields,
  clearDatabaseDraft,
  draftMatches,
  loadDatabaseDraft,
  saveDatabaseDraft,
} from "@/lib/databaseDraft";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";

/** Must match `SSH_TUNNEL_METHOD_ID` in the Rust engine registry. */
const SSH_TUNNEL_METHOD = "ssh-tunnel";

const SSH_AUTH_OPTIONS = [
  { value: "password", label: "Password" },
  { value: "private_key", label: "Private key" },
];

interface DatabaseDialogProps {
  open: boolean;
  catalogue: EngineCatalogue;
  /** Present when editing; absent when adding. */
  existing?: DatabaseConnection | null;
  onClose: () => void;
  onSaved: (database: DatabaseConnection) => void;
}

interface FormState {
  label: string;
  engine: string;
  connectionMethod: string;
  host: string;
  port: string;
  databaseName: string;
  username: string;
  password: string;
  sshHost: string;
  sshPort: string;
  sshUsername: string;
  /** `password` | `private_key`. */
  sshAuthMethod: string;
  sshPassword: string;
  sshPrivateKey: string;
  sshKeyPassphrase: string;
  /** Display form (`SHA256:<base64>`), empty until verified. */
  sshHostKeyFingerprint: string;
}

const EMPTY: FormState = {
  label: "",
  engine: "",
  connectionMethod: "",
  host: "",
  port: "",
  databaseName: "",
  username: "",
  password: "",
  sshHost: "",
  sshPort: "22",
  sshUsername: "",
  sshAuthMethod: "password",
  sshPassword: "",
  sshPrivateKey: "",
  sshKeyPassphrase: "",
  sshHostKeyFingerprint: "",
};

/** Compares two form snapshots field by field, independent of key order. */
function formsEqual(a: FormState, b: FormState): boolean {
  const keys = Object.keys(a) as (keyof FormState)[];
  return keys.every((key) => a[key] === b[key]);
}

/**
 * The non-secret subset of the form that a draft may hold. Every secret
 * (database password, SSH password, private key, passphrase) is excluded here
 * and can therefore never reach `localStorage`.
 */
function toDraftFields(form: FormState): DatabaseDraftFields {
  return {
    label: form.label,
    engine: form.engine,
    connectionMethod: form.connectionMethod,
    host: form.host,
    port: form.port,
    databaseName: form.databaseName,
    username: form.username,
    sshHost: form.sshHost,
    sshPort: form.sshPort,
    sshUsername: form.sshUsername,
    sshAuthMethod: form.sshAuthMethod,
    sshHostKeyFingerprint: form.sshHostKeyFingerprint,
  };
}

/**
 * Add or edit a database connection, with a real Test Connection action.
 *
 * Secrets are only ever form fields: they are sent to the backend, used for a
 * test, and handed to the Windows Credential Manager (or a DPAPI-protected
 * blob for an SSH key) on save. They are never fetched back - an edit
 * therefore leaves the secret fields blank by default and keeps the stored
 * values unless new ones are typed. A draft saved from this form strips the
 * secrets before writing, for the same reason.
 *
 * For an SSH tunnel the first test is a *fingerprint check*: the server's host
 * key is shown with an `unverified` outcome, and nothing is authenticated
 * until it is compared with the server and explicitly trusted.
 *
 * Closing the form with unsaved edits asks first: keep editing, discard, or
 * store the non-secret fields as a draft that "Resume draft" can restore.
 */
export function DatabaseDialog({
  open,
  catalogue,
  existing,
  onClose,
  onSaved,
}: DatabaseDialogProps) {
  const editing = existing !== undefined && existing !== null;
  /** The draft slot this dialog owns: `null` for add, the row id for edit. */
  const editingId = existing?.id ?? null;

  const [form, setForm] = useState<FormState>(EMPTY);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(
    null,
  );
  /** Epoch seconds of the restored draft, or null when nothing was restored. */
  const [restoredDraftAt, setRestoredDraftAt] = useState<number | null>(null);
  /** The "unsaved changes" prompt shown when the dialog is closed with edits. */
  const [confirmingClose, setConfirmingClose] = useState(false);

  /** The form as it was when the dialog opened, for the dirty check. */
  const initialForm = useRef<FormState>(EMPTY);

  const engine = useMemo(
    () => catalogue.engines.find((item) => item.id === form.engine),
    [catalogue.engines, form.engine],
  );
  const method = useMemo(
    () => catalogue.methods.find((item) => item.id === form.connectionMethod),
    [catalogue.methods, form.connectionMethod],
  );

  // A host is only required by the methods that declare they need one.
  const requiresHost = Boolean(method?.requiresHost && engine?.supportsHost);
  const isSshTunnel = form.connectionMethod === SSH_TUNNEL_METHOD;

  // The tunnel option only exists for engines whose adapter can tunnel.
  const methodOptions = useMemo(
    () =>
      catalogue.methods.filter(
        (item) =>
          item.id !== SSH_TUNNEL_METHOD || Boolean(engine?.supportsSshTunnel),
      ),
    [catalogue.methods, engine],
  );

  // Reset each time the dialog opens so a cancelled edit never leaks into the
  // next one, and so the secret fields always start empty. A draft for this
  // exact target (the "add" slot or this row) is laid over the base values.
  useEffect(() => {
    if (!open) return;

    setError(null);
    setTestResult(null);
    setSaving(false);
    setTesting(false);
    setConfirmingClose(false);
    setRestoredDraftAt(null);

    let next: FormState;
    if (existing) {
      next = {
        label: existing.label,
        engine: existing.engine,
        connectionMethod: existing.connectionMethod,
        host: existing.host ?? "",
        port: existing.port ? String(existing.port) : "",
        databaseName: existing.databaseName,
        username: existing.username ?? "",
        password: "",
        sshHost: existing.sshHost ?? "",
        sshPort: existing.sshPort ? String(existing.sshPort) : "22",
        sshUsername: existing.sshUsername ?? "",
        sshAuthMethod: existing.sshAuthMethod ?? "password",
        sshPassword: "",
        sshPrivateKey: "",
        sshKeyPassphrase: "",
        sshHostKeyFingerprint: existing.sshHostKeyFingerprint ?? "",
      };
    } else {
      const firstEngine = catalogue.engines[0];
      const firstMethod = catalogue.methods[0];
      next = {
        ...EMPTY,
        engine: firstEngine?.id ?? "",
        connectionMethod: firstMethod?.id ?? "",
        port: firstEngine ? String(firstEngine.defaultPort) : "",
      };
    }

    const draft = loadDatabaseDraft();
    if (draft && draftMatches(draft, editingId)) {
      // A draft only carries non-secret fields, so the secrets stay blank.
      const engineId = catalogue.engines.some(
        (item) => item.id === draft.fields.engine,
      )
        ? draft.fields.engine
        : next.engine;
      const engineSupportsTunnel = Boolean(
        catalogue.engines.find((item) => item.id === engineId)
          ?.supportsSshTunnel,
      );
      const methodOffered = catalogue.methods.some(
        (item) =>
          item.id === draft.fields.connectionMethod &&
          (item.id !== SSH_TUNNEL_METHOD || engineSupportsTunnel),
      );

      next = {
        ...next,
        ...draft.fields,
        engine: engineId,
        connectionMethod: methodOffered
          ? draft.fields.connectionMethod
          : next.connectionMethod,
        sshAuthMethod:
          draft.fields.sshAuthMethod === "private_key"
            ? "private_key"
            : "password",
        password: "",
        sshPassword: "",
        sshPrivateKey: "",
        sshKeyPassphrase: "",
      };
      setRestoredDraftAt(draft.savedAt);
    }

    initialForm.current = next;
    setForm(next);
  }, [open, existing, catalogue, editingId]);

  // If the selected method is no longer offered for this engine (for example
  // the engine changed to one without SSH tunneling), fall back to the first
  // offered method instead of submitting a combination the backend refuses.
  useEffect(() => {
    if (!open) return;
    if (methodOptions.some((item) => item.id === form.connectionMethod)) return;
    setForm((current) => ({
      ...current,
      connectionMethod: methodOptions[0]?.id ?? "",
    }));
  }, [open, methodOptions, form.connectionMethod]);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    if (key === "engine") {
      // Choosing an engine restores that engine's suggested port. Done here
      // rather than in an effect so an opened edit or a restored draft keeps
      // its own port.
      const chosen = catalogue.engines.find((item) => item.id === value);
      setForm((current) => ({
        ...current,
        engine: value,
        port: chosen ? String(chosen.defaultPort) : current.port,
      }));
    } else {
      setForm((current) => ({ ...current, [key]: value }));
    }
    // Any configuration change makes a previous test verdict stale.
    setTestResult(null);
  }

  const storageAvailable = catalogue.credentialStorageAvailable;
  const busy = saving || testing;
  const dirty = !formsEqual(form, initialForm.current);

  /** Every close path routes through here: edits are never discarded silently. */
  function requestClose() {
    // While a save is in flight the outcome decides everything; asking now
    // would only interrupt it.
    if (saving) return;
    if (!dirty) {
      exitDialog();
      return;
    }
    setConfirmingClose(true);
  }

  function exitDialog() {
    setConfirmingClose(false);
    onClose();
  }

  /** Keep the non-secret fields for later. Secrets are never written to a draft. */
  function keepDraft() {
    saveDatabaseDraft(toDraftFields(form), editingId);
    exitDialog();
  }

  /** Throw the form and any stored draft for this target away. */
  function discardChanges() {
    if (draftMatches(loadDatabaseDraft(), editingId)) clearDatabaseDraft();
    exitDialog();
  }

  /**
   * The SSH half of the payload, or null when the method is not a tunnel.
   *
   * `fingerprintOverride` carries a fingerprint that was just verified in the
   * trust prompt; otherwise the remembered value is used.
   */
  function buildSsh(
    fingerprintOverride?: string | null,
  ): SshTunnelInput | null {
    if (!form.sshHost.trim()) {
      setError("Enter the host of your SSH server.");
      return null;
    }

    const sshPortValue =
      form.sshPort.trim() === "" ? null : Number(form.sshPort);
    if (
      sshPortValue !== null &&
      (!Number.isInteger(sshPortValue) ||
        sshPortValue < 1 ||
        sshPortValue > 65535)
    ) {
      setError("SSH port must be between 1 and 65535.");
      return null;
    }

    if (!form.sshUsername.trim()) {
      setError("Enter the user name for the SSH server.");
      return null;
    }

    if (
      form.sshAuthMethod !== "password" &&
      form.sshAuthMethod !== "private_key"
    ) {
      setError("Choose how BackMeUp should sign in to the SSH server.");
      return null;
    }

    const fingerprint = (
      fingerprintOverride ??
      form.sshHostKeyFingerprint
    ).trim();

    return {
      sshHost: form.sshHost.trim(),
      sshPort: sshPortValue,
      sshUsername: form.sshUsername.trim(),
      sshAuthMethod: form.sshAuthMethod,
      sshPassword:
        form.sshAuthMethod === "password" && form.sshPassword
          ? form.sshPassword
          : null,
      sshPrivateKey:
        form.sshAuthMethod === "private_key" && form.sshPrivateKey
          ? form.sshPrivateKey
          : null,
      sshKeyPassphrase:
        form.sshAuthMethod === "private_key" && form.sshKeyPassphrase
          ? form.sshKeyPassphrase
          : null,
      sshHostKeyFingerprint: fingerprint || null,
    };
  }

  /** Shared validation, so Test and Save agree on what "valid" means. */
  function collect(
    fingerprintOverride?: string | null,
  ): Parameters<typeof api.testDatabaseConnection>[0] | null {
    if (!form.label.trim() || !form.databaseName.trim()) {
      setError("Enter a name for this connection and the database name.");
      return null;
    }
    if (!form.username.trim()) {
      setError("Enter the database user name.");
      return null;
    }
    if (requiresHost && !form.host.trim()) {
      setError("Enter the host this database runs on.");
      return null;
    }

    const portValue = form.port.trim() === "" ? null : Number(form.port);
    if (
      portValue !== null &&
      (!Number.isInteger(portValue) || portValue < 1 || portValue > 65535)
    ) {
      setError("Port must be between 1 and 65535.");
      return null;
    }

    let ssh: SshTunnelInput | null = null;
    if (isSshTunnel) {
      ssh = buildSsh(fingerprintOverride);
      if (!ssh) return null;
    }

    return {
      label: form.label.trim(),
      engine: form.engine,
      connectionMethod: form.connectionMethod,
      host: form.host.trim() || null,
      port: portValue,
      databaseName: form.databaseName.trim(),
      username: form.username.trim(),
      password: form.password,
      ssh,
    };
  }

  /** Whether the currently typed SSH config needs a secret in the form. */
  function sshSecretRequired(): boolean {
    if (!isSshTunnel) return false;
    if (!editing) return true;
    return (
      existing?.connectionMethod !== SSH_TUNNEL_METHOD ||
      !existing?.hasSshCredentials ||
      existing?.sshAuthMethod !== form.sshAuthMethod
    );
  }

  async function runTest(fingerprintOverride?: string | null) {
    setError(null);

    if (isSshTunnel) {
      if (form.sshAuthMethod === "password" && !form.sshPassword) {
        setError("Enter the SSH password before testing.");
        return;
      }
      if (form.sshAuthMethod === "private_key" && !form.sshPrivateKey) {
        setError("Paste the SSH private key before testing.");
        return;
      }
    }

    if (!form.password) {
      setError("Enter the database password before testing.");
      return;
    }

    const input = collect(fingerprintOverride);
    if (!input) return;

    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await api.testDatabaseConnection(input));
    } catch (testError) {
      setError(
        testError instanceof ApiError
          ? testError.message
          : "The connection test could not be run.",
      );
    } finally {
      setTesting(false);
    }
  }

  /**
   * The presented host key has been compared with the server. Remember
   * it and immediately re-test with the fingerprint pinned, so a succeeding
   * result is proof the pinned key was used.
   */
  function handleTrustHostKey() {
    const fingerprint = testResult?.hostKeyFingerprint;
    if (!fingerprint) return;

    setForm((current) => ({
      ...current,
      sshHostKeyFingerprint: fingerprint,
    }));
    void runTest(fingerprint);
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    // Saving is refused outright when the credential store is unreachable,
    // rather than falling back to weaker storage.
    if (!storageAvailable) {
      setError(catalogue.credentialStorageNote);
      return;
    }

    if (!editing && !form.password) {
      setError("Enter the database password.");
      return;
    }

    if (sshSecretRequired()) {
      if (form.sshAuthMethod === "password" && !form.sshPassword) {
        setError("Enter the SSH password.");
        return;
      }
      if (form.sshAuthMethod === "private_key" && !form.sshPrivateKey) {
        setError("Paste the SSH private key.");
        return;
      }
    }

    const collected = collect();
    if (!collected) return;

    const { password, ...input } = collected;

    setSaving(true);
    try {
      if (existing) {
        // Addressing first, then the secret. Two steps so a failure in one
        // cannot silently discard the other.
        const updated = await api.updateDatabase({ ...input, id: existing.id });
        if (password) {
          await api.updateDatabaseCredentials({
            id: existing.id,
            username: input.username,
            password,
          });
        }
        if (draftMatches(loadDatabaseDraft(), editingId)) clearDatabaseDraft();
        onSaved({ ...updated, hasCredentials: true });
      } else {
        const created = await api.createDatabase({ ...input, password });
        if (draftMatches(loadDatabaseDraft(), editingId)) clearDatabaseDraft();
        onSaved(created);
      }
      onClose();
    } catch (saveError) {
      setError(
        saveError instanceof ApiError
          ? saveError.message
          : "That connection could not be saved.",
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <Modal
        open={open}
        wide
        title={editing ? "Edit database" : "Add database"}
        description={
          editing
            ? "Change the connection details. Leave a secret blank to keep the stored one."
            : "Record where a database lives and test that BackMeUp can reach it."
        }
        onClose={requestClose}
        footer={
          <>
            <Button
              variant="outline"
              onClick={() => void runTest()}
              disabled={busy || !storageAvailable}
            >
              {testing ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <PlugZap className="size-4" aria-hidden="true" />
              )}
              Test Connection
            </Button>
            <Button variant="ghost" onClick={requestClose} disabled={busy}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="database-form"
              disabled={busy || !storageAvailable}
            >
              {saving ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : null}
              {editing ? "Save changes" : "Add database"}
            </Button>
          </>
        }
      >
        <form
          id="database-form"
          className="flex flex-col gap-6"
          onSubmit={handleSubmit}
          noValidate
        >
          {error ? (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          {restoredDraftAt !== null ? (
            <Alert>
              <AlertDescription>
                Draft restored
                {restoredDraftAt > 0
                  ? ` from ${formatDateTime(restoredDraftAt)}`
                  : ""}
                . Passwords and keys are never kept in a draft, so enter them
                again before saving.
              </AlertDescription>
            </Alert>
          ) : null}

          {/*
            A real result of a real attempt. Never a placeholder: this stays
            empty until the backend has actually dialled the server. An
            `unverified` outcome is the SSH host-key check awaiting a
            comparison.
          */}
          {testResult ? (
            <Alert
              variant={
                testResult.outcome === "success"
                  ? "success"
                  : testResult.outcome === "unverified"
                    ? "warning"
                    : "destructive"
              }
            >
              <AlertDescription className="space-y-2">
                <span className="block font-medium">{testResult.message}</span>
                {testResult.outcome === "success" ? (
                  <span className="block text-xs opacity-90">
                    {[
                      testResult.serverBanner,
                      typeof testResult.latencyMs === "number"
                        ? `${testResult.latencyMs} ms`
                        : null,
                      testResult.encrypted ? "encrypted" : null,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                ) : null}
                {testResult.outcome !== "success" &&
                testResult.hostKeyFingerprint ? (
                  <span className="block space-y-2">
                    <code className="block break-all font-mono text-xs">
                      {testResult.hostKeyFingerprint}
                      {testResult.hostKeyType
                        ? ` (${testResult.hostKeyType})`
                        : ""}
                    </code>
                    <span className="block text-xs opacity-90">
                      Only trust this after comparing it with your server
                      (hosting panel or a terminal).
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleTrustHostKey()}
                      disabled={busy}
                    >
                      Trust this key &amp; connect
                    </Button>
                  </span>
                ) : null}
              </AlertDescription>
            </Alert>
          ) : null}

          {!storageAvailable ? (
            <Alert>
              <AlertDescription>
                {catalogue.credentialStorageNote}
              </AlertDescription>
            </Alert>
          ) : null}

          <section className="space-y-3">
            <h3 className="text-sm font-semibold tracking-tight text-foreground">
              Connection
            </h3>

            {/* Two columns throughout, so every field lines up with its pair. */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field
                label="Name"
                hint="A label for you. Never sent to the database."
              >
                <Input
                  value={form.label}
                  onChange={(event) => update("label", event.target.value)}
                  placeholder="Production"
                  maxLength={100}
                  disabled={busy}
                  autoFocus
                />
              </Field>

              {/*
                Distinct from the friendly Name on purpose: this is the real
                schema the server will be asked for.
              */}
              <Field
                label="Database name"
                hint="Exactly as your host lists it."
              >
                <Input
                  value={form.databaseName}
                  onChange={(event) =>
                    update("databaseName", event.target.value)
                  }
                  placeholder="u912345678_shop"
                  maxLength={128}
                  disabled={busy}
                />
              </Field>

              <Field label="Engine">
                <Select
                  value={form.engine}
                  onValueChange={(value) => update("engine", value)}
                  disabled={busy}
                  options={catalogue.engines.map((item) => ({
                    value: item.id,
                    label: item.supported
                      ? item.label
                      : `${item.label} (unavailable)`,
                  }))}
                />
              </Field>

              <Field label="Connection">
                <Select
                  value={form.connectionMethod}
                  onValueChange={(value) => update("connectionMethod", value)}
                  disabled={busy}
                  options={methodOptions.map((item) => ({
                    value: item.id,
                    label: item.label,
                  }))}
                />
              </Field>

              {isSshTunnel ? (
                <>
                  <Field
                    label="Database host"
                    hint="As seen by the SSH server. Leave blank for the server itself."
                  >
                    <Input
                      value={form.host}
                      onChange={(event) => update("host", event.target.value)}
                      placeholder="127.0.0.1"
                      maxLength={253}
                      disabled={busy}
                    />
                  </Field>

                  <Field
                    label="Database port"
                    hint={`Suggested for ${engine?.label ?? "this engine"}. Change it if your server uses another port.`}
                  >
                    <Input
                      value={form.port}
                      onChange={(event) =>
                        update("port", event.target.value)
                      }
                      inputMode="numeric"
                      maxLength={5}
                      disabled={busy}
                    />
                  </Field>
                </>
              ) : requiresHost ? (
                <>
                  <Field
                    label="Host"
                    hint="Hostname or IP address. No hosting provider is assumed."
                  >
                    <Input
                      value={form.host}
                      onChange={(event) => update("host", event.target.value)}
                      placeholder="db.example.com"
                      maxLength={253}
                      disabled={busy}
                    />
                  </Field>

                  <Field
                    label="Port"
                    hint={`Suggested for ${engine?.label ?? "this engine"}. Change it if your server uses another port.`}
                  >
                    <Input
                      value={form.port}
                      onChange={(event) =>
                        update("port", event.target.value)
                      }
                      inputMode="numeric"
                      maxLength={5}
                      disabled={busy}
                    />
                  </Field>
                </>
              ) : null}
            </div>
          </section>

          {isSshTunnel ? (
            <section className="space-y-4 rounded-lg border border-border p-4">
              <div className="space-y-1">
                <h3 className="text-sm font-semibold tracking-tight text-foreground">
                  SSH tunnel
                </h3>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  BackMeUp signs in to your server over SSH and reaches the
                  database from there, so the database port never has to be
                  public.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field
                  label="SSH host"
                  hint="The server BackMeUp signs in to, not the database host."
                >
                  <Input
                    value={form.sshHost}
                    onChange={(event) => update("sshHost", event.target.value)}
                    placeholder="srv123.hosterlive.com"
                    maxLength={253}
                    disabled={busy}
                  />
                </Field>

                <Field label="SSH port" hint="Almost always 22.">
                  <Input
                    value={form.sshPort}
                    onChange={(event) => update("sshPort", event.target.value)}
                    inputMode="numeric"
                    maxLength={5}
                    disabled={busy}
                  />
                </Field>

                <Field label="SSH user name">
                  <Input
                    value={form.sshUsername}
                    onChange={(event) =>
                      update("sshUsername", event.target.value)
                    }
                    placeholder="u912345678"
                    maxLength={128}
                    disabled={busy}
                    autoComplete="off"
                  />
                </Field>

                <Field label="SSH sign-in method">
                  <Select
                    value={form.sshAuthMethod}
                    onValueChange={(value) => update("sshAuthMethod", value)}
                    disabled={busy}
                    options={SSH_AUTH_OPTIONS}
                  />
                </Field>

                {form.sshAuthMethod === "private_key" ? (
                  <>
                    <Field
                      className="sm:col-span-2"
                      label="SSH private key"
                      hint={
                        editing && !form.sshPrivateKey
                          ? "Leave blank to keep the stored key. Paste a new key to replace it."
                          : "Paste the full contents of the key file. It is stored encrypted for your Windows account only."
                      }
                    >
                      <textarea
                        value={form.sshPrivateKey}
                        onChange={(event) =>
                          update("sshPrivateKey", event.target.value)
                        }
                        placeholder={
                          "-----BEGIN OPENSSH PRIVATE KEY-----\n…"
                        }
                        rows={6}
                        spellCheck={false}
                        autoComplete="off"
                        disabled={busy}
                        className="min-h-28 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs leading-relaxed text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50"
                      />
                    </Field>

                    <Field
                      label="Key passphrase"
                      hint="Only if the key is protected by one. Re-enter it together with the key."
                    >
                      <PasswordField
                        id="ssh-key-passphrase"
                        name="ssh-key-passphrase"
                        autoComplete="new-password"
                        value={form.sshKeyPassphrase}
                        onChange={(event) =>
                          update("sshKeyPassphrase", event.target.value)
                        }
                        disabled={busy}
                      />
                    </Field>
                  </>
                ) : (
                  <Field
                    label="SSH password"
                    hint={
                      editing
                        ? "Leave blank to keep the stored SSH password."
                        : "Stored in the Windows Credential Manager, like the database password."
                    }
                  >
                    <PasswordField
                      id="ssh-password"
                      name="ssh-password"
                      autoComplete="new-password"
                      value={form.sshPassword}
                      onChange={(event) =>
                        update("sshPassword", event.target.value)
                      }
                      disabled={busy}
                    />
                  </Field>
                )}
              </div>

              {form.sshHostKeyFingerprint ? (
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Verified host key:{" "}
                  <span className="break-all font-mono text-foreground">
                    {form.sshHostKeyFingerprint}
                  </span>
                  {existing?.sshHostKeyType
                    ? ` (${existing.sshHostKeyType})`
                    : ""}
                </p>
              ) : (
                <p className="text-xs leading-relaxed text-muted-foreground">
                  The server&apos;s host key is shown the first time you test
                  this tunnel, so you can compare it with your server before
                  anything is trusted.
                </p>
              )}
            </section>
          ) : null}

          <section className="space-y-3">
            <h3 className="text-sm font-semibold tracking-tight text-foreground">
              Database credentials
            </h3>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label="User name">
                <Input
                  value={form.username}
                  onChange={(event) => update("username", event.target.value)}
                  placeholder="backup_reader"
                  maxLength={128}
                  disabled={busy}
                  autoComplete="off"
                />
              </Field>

              <Field
                label="Password"
                hint={
                  editing
                    ? "Leave blank to keep the password already stored in Windows Credential Manager."
                    : catalogue.credentialStorageNote
                }
              >
                <PasswordField
                  id="database-password"
                  name="database-password"
                  autoComplete="new-password"
                  value={form.password}
                  onChange={(event) => update("password", event.target.value)}
                  disabled={busy}
                />
              </Field>
            </div>
          </section>

          <p className="text-xs leading-relaxed text-muted-foreground">
            PostgreSQL and SQL Server connections always use an encrypted,
            certificate-verified transport, and a server whose certificate
            BackMeUp cannot verify is refused. A direct MySQL connection is
            not encrypted, so use the SSH tunnel method when the network to the
            database is not trusted.
          </p>
        </form>
      </Modal>

      {/*
        Shown when the form is closed with unsaved edits. Keep editing returns
        to the form; a draft stores only the non-secret fields; discarding
        removes any draft stored for this exact target.
      */}
      <Modal
        open={confirmingClose}
        title="Unsaved changes"
        description="This form was closed before it was saved."
        onClose={() => setConfirmingClose(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmingClose(false)}>
              Keep editing
            </Button>
            <Button variant="outline" onClick={discardChanges}>
              Discard
            </Button>
            <Button onClick={keepDraft}>Save as draft</Button>
          </>
        }
      >
        <p className="text-sm leading-relaxed text-muted-foreground">
          Keep editing to finish saving, store the non-secret fields as a draft
          and continue later, or discard this form. Passwords, keys and
          passphrases are never kept in a draft.
        </p>
      </Modal>
    </>
  );
}

function Field({
  label,
  hint,
  className,
  children,
}: {
  label: string;
  hint?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <label
      className={cn(
        "flex min-w-0 flex-col gap-1.5 text-sm font-medium text-foreground",
        className,
      )}
    >
      {label}
      {children}
      {hint ? (
        <span className="text-xs font-normal leading-relaxed text-muted-foreground">
          {hint}
        </span>
      ) : null}
    </label>
  );
}

const selectClass =
  "h-10 w-full rounded-md border border-input bg-background px-2.5 text-sm font-normal text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50";

function Select({
  value,
  onValueChange,
  options,
  disabled,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: { value: string; label: string }[];
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      onChange={(event) => onValueChange(event.target.value)}
      disabled={disabled}
      className={cn(selectClass)}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}
