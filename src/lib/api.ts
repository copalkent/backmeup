/**
 * Typed bindings for the Rust backend.
 *
 * The frontend never sees, sends or derives credential material: password
 * hashes, recovery-code hashes, salts and session state all stay inside Rust.
 * Every privileged decision (validation, throttling, authorisation, recovery)
 * is made server-side in `src-tauri/src/commands.rs`.
 */
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export interface OwnerProfile {
  fullName: string;
  email: string;
}

export interface BootstrapState {
  needsSetup: boolean;
  authenticated: boolean;
  setupConfirmed: boolean;
  owner: OwnerProfile | null;
  remainingRecoveryCodes: number | null;
}

export interface RecoveryCodesView {
  recoveryCodes: string[];
  codeCount: number;
}

export interface RecoveryCodeStatus {
  total: number;
  used: number;
  remaining: number;
}

export interface ExportResult {
  saved: boolean;
  fileName: string | null;
}

/**
 * The result of opening the native folder picker. `cancelled` means the owner
 * dismissed the dialog and nothing was changed.
 */
export interface FolderSelection {
  cancelled: boolean;
  location: string | null;
}

export interface EngineOption {
  id: string;
  label: string;
  defaultPort: number;
  supportsHost: boolean;
  /** Address BackMeUp uses for a "This machine" connection to this engine. */
  localHost: string;
  /** False when this build has no adapter, so the UI can say so plainly. */
  supported: boolean;
  /** True when this engine's adapter can run over an SSH tunnel. */
  supportsSshTunnel: boolean;
}

export interface ConnectionMethodOption {
  id: string;
  label: string;
  requiresHost: boolean;
}

/**
 * Everything the database form needs. Delivered by the backend so the engine
 * list and the credential-storage policy are never duplicated here.
 */
export interface EngineCatalogue {
  engines: EngineOption[];
  methods: ConnectionMethodOption[];
  /** False disables saving entirely - BackMeUp never falls back to weaker storage. */
  credentialStorageAvailable: boolean;
  credentialStorageNote: string;
}

/**
 * Result of the last connection test.
 *
 * `neverTested` is deliberately distinct from `failed`: a configuration that
 * has never been dialled must not look like a broken one, and a past success is
 * history rather than proof that a server is online right now.
 */
export type TestState = "neverTested" | "succeeded" | "failed";

/**
 * A saved database connection.
 *
 * There is no password field: the secret lives in the Windows Credential
 * Manager and is never returned to the frontend.
 */
export interface DatabaseConnection {
  id: string;
  label: string;
  engine: string;
  engineLabel: string;
  connectionMethod: string;
  connectionMethodLabel: string;
  host: string | null;
  port: number | null;
  databaseName: string;
  username: string | null;
  createdAt: number;
  testState: TestState;
  lastTestedAt: number | null;
  hasCredentials: boolean;
  /** SSH tunnel settings. Present only for `ssh-tunnel` records. */
  sshHost: string | null;
  sshPort: number | null;
  sshUsername: string | null;
  /** `password` | `private_key`. */
  sshAuthMethod: string | null;
  /** Whether the SSH secret (password or key blob) is stored. Never the secret itself. */
  hasSshCredentials: boolean;
  /** Verified fingerprint in display form (`SHA256:<base64>`), or null before verification. */
  sshHostKeyFingerprint: string | null;
  sshHostKeyType: string | null;
}

/** Sanitised outcome of a real connection attempt. */
export interface ConnectionTestResult {
  /**
   * `unverified` means the SSH server's host key was read and nothing was
   * authenticated yet; the owner must confirm the fingerprint before a real
   * attempt is made.
   */
  outcome: "success" | "failed" | "unverified";
  /** Server banner, only present on success. Control characters are stripped. */
  serverBanner: string | null;
  latencyMs: number | null;
  encrypted: boolean;
  /** Actionable sentence. Never contains a host, user, password or SQL. */
  message: string;
  /** Display-form fingerprint (`SHA256:<base64>`), for `unverified` or a changed key. */
  hostKeyFingerprint: string | null;
  hostKeyType: string | null;
}

/**
 * SSH tunnel settings, shared by add, edit and test.
 *
 * Secrets are only ever sent towards Rust; they are stored in the Windows
 * Credential Manager (or a DPAPI blob for the private key) and are never
 * returned to this layer.
 */
export type SshTunnelInput = {
  sshHost: string;
  sshPort?: number | null;
  sshUsername: string;
  /** `password` | `private_key`. */
  sshAuthMethod: string;
  sshPassword?: string | null;
  sshPrivateKey?: string | null;
  sshKeyPassphrase?: string | null;
  /** `SHA256:<base64>` or the bare digest; normalised in Rust. */
  sshHostKeyFingerprint?: string | null;
};

/**
 * Connection addressing, shared by add, edit and test.
 *
 * Declared as a type alias rather than an interface so it satisfies the
 * `Record<string, unknown>` parameter shape used for IPC payloads.
 */
export type DatabaseInput = {
  label: string;
  engine: string;
  connectionMethod: string;
  host?: string | null;
  port?: number | null;
  databaseName: string;
  username: string;
  /** Required for the `ssh-tunnel` method; ignored otherwise. */
  ssh?: SshTunnelInput | null;
};

/** Event carrying the Google sign-in URL, sent as soon as it exists. */
export const DRIVE_SIGNIN_URL_EVENT = "drive-signin-url";

/**
 * Subscribe to the Google sign-in URL.
 *
 * Sent before the browser is asked to open, so an owner whose browser did not
 * launch still has a link to follow. Returns an unsubscribe function.
 */
export function onDriveSigninUrl(handler: (url: string) => void): () => void {
  let unlisten: (() => void) | undefined;
  let disposed = false;

  void listen<string>(DRIVE_SIGNIN_URL_EVENT, (event) => {
    handler(event.payload);
  }).then((fn) => {
    if (disposed) {
      fn();
    } else {
      unlisten = fn;
    }
  });

  return () => {
    disposed = true;
    unlisten?.();
  };
}
export interface GoogleDriveStatus {
  connected: boolean;
  /** Folder BackMeUp creates in Drive. */
  rootFolder: string;
  /** Per-database folders BackMeUp created inside `rootFolder`. */
  folders: string[];
  /** Shown whenever Drive is connected: storage is shared with the account. */
  storageWarning: string;
  /** The single scope requested, so it can be checked against the consent screen. */
  scope: string;
}

export interface BackupDestination {
  id: string;
  kind: string;
  label: string;
  description: string;
  /** False until a real, verified integration exists. */
  available: boolean;
  unavailableReason: string;
  /** `configured` | `not_configured` | `unavailable`. */
  status: string;
  location: string | null;
  updatedAt: number | null;
}

export interface BackupRun {
  id: string;
  databaseLabel: string | null;
  databaseName: string | null;
  engineLabel: string | null;
  destinationLabel: string | null;
  /** The local folder a copy was written to, when that destination is local. */
  destinationLocation: string | null;
  status: string;
  startedAt: number | null;
  finishedAt: number | null;
  sizeBytes: number | null;
  failureReason: string | null;
  /** `uploaded` | `failed` | `skipped`, or null for older runs. */
  driveStatus: string | null;
  /** Why the Drive copy was not stored, kept apart from `failureReason`. */
  driveError: string | null;
  /** Path relative to the chosen backup folder, when one was kept. */
  fileName: string | null;
  /** `BackMeUp/<database>/<day>/<file>` when the copy reached Drive. */
  drivePath: string | null;
  /**
   * SHA-256 of the finished file. Hash the file again and the value must
   * match; any other value means the file is not the one this run produced.
   */
  sha256: string | null;
}

export interface BackupSummary {
  status: string;
  at: number;
}

export interface BackupOverview {
  databaseCount: number;
  backupCount: number;
  lastBackup: BackupSummary | null;
  destinationCount: number;
  hasLocalFolder: boolean;
  /** True while a Google Drive sign-in is stored. */
  hasDrive: boolean;
}

/** Error surface returned by the Rust commands. */
export class ApiError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
  }
}

function toApiError(raw: unknown): ApiError {
  if (raw && typeof raw === "object") {
    const candidate = raw as { code?: unknown; message?: unknown };
    if (typeof candidate.message === "string" && candidate.message.length > 0) {
      return new ApiError(
        typeof candidate.code === "string" ? candidate.code : "unknown",
        candidate.message,
      );
    }
  }
  if (typeof raw === "string" && raw.length > 0) {
    return new ApiError("unknown", raw);
  }
  return new ApiError("unknown", "BackMeUp could not complete that request.");
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (raw) {
    throw toApiError(raw);
  }
}

export const api = {
  bootstrapState: () => call<BootstrapState>("app_bootstrap_state"),

  setupOwner: (input: {
    fullName: string;
    email: string;
    password: string;
    confirmPassword: string;
  }) => call<RecoveryCodesView>("setup_owner", input),

  confirmSetupCodesSaved: () => call<BootstrapState>("confirm_setup_codes_saved"),

  login: (input: { email: string; password: string }) =>
    call<BootstrapState>("login", input),

  logout: () => call<BootstrapState>("logout"),

  currentAccount: () => call<OwnerProfile>("current_account"),

  recoverPassword: (input: {
    email: string;
    recoveryCode: string;
    newPassword: string;
    confirmPassword: string;
  }) => call<void>("recover_password", input),

  recoveryCodeStatus: () => call<RecoveryCodeStatus>("recovery_code_status"),

  beginRecoveryCodeRegeneration: (currentPassword: string) =>
    call<RecoveryCodesView>("begin_recovery_code_regeneration", {
      currentPassword,
    }),

  commitRecoveryCodeRegeneration: () =>
    call<RecoveryCodeStatus>("commit_recovery_code_regeneration"),

  cancelRecoveryCodeRegeneration: () =>
    call<void>("cancel_recovery_code_regeneration"),

  /**
   * The destination is chosen in the native Windows save dialog inside Rust,
   * so no file path is ever accepted from the webview.
   */
  exportRecoveryCodes: () => call<ExportResult>("export_recovery_codes"),

  // -------------------------------------------------------------------------
  // Database connections
  //
  // Records plus real connection tests. No command here accepts a statement,
  // a file path or a shell command, so a connection test cannot be turned into
  // arbitrary SQL or code execution. `dbconn/` in Rust is the only place that
  // opens a socket or reads a stored password.
  // -------------------------------------------------------------------------

  databaseEngines: () => call<EngineCatalogue>("database_engines"),

  listDatabases: () => call<DatabaseConnection[]>("list_databases"),

  createDatabase: (input: DatabaseInput & { password: string }) =>
    call<DatabaseConnection>("create_database", input),

  /** Addressing only. Leaves the stored password untouched. */
  updateDatabase: (input: DatabaseInput & { id: string }) =>
    call<DatabaseConnection>("update_database", input),

  /** Replaces the stored secret. The password is never read back afterwards. */
  updateDatabaseCredentials: (input: {
    id: string;
    username: string;
    password: string;
  }) => call<void>("update_database_credentials", input),

  /** Tests the values currently in the form, before anything is saved. */
  testDatabaseConnection: (input: DatabaseInput & { password: string }) =>
    call<ConnectionTestResult>("test_database_connection", input),

  /**
   * Tests a saved connection using its stored credentials.
   *
   * For an SSH tunnel the first call returns `unverified` with the server's
   * fingerprint; repeat the call with `hostKeyFingerprint` set to the
   * fingerprint the owner verified out of band.
   */
  testSavedDatabase: (id: string, hostKeyFingerprint?: string | null) =>
    call<ConnectionTestResult>("test_saved_database", {
      id,
      hostKeyFingerprint,
    }),

  deleteDatabase: (id: string) => call<void>("delete_database", { id }),

  // -------------------------------------------------------------------------
  // Backup destinations
  //
  // Folder selection happens in Rust through the native dialog, so the webview
  // is never given a filesystem capability or a path it can act on.
  // -------------------------------------------------------------------------

  listDestinations: () => call<BackupDestination[]>("list_backup_destinations"),

  chooseLocalBackupFolder: () =>
    call<FolderSelection>("choose_local_backup_folder"),

  clearLocalBackupFolder: () => call<void>("clear_local_backup_folder"),

  // -------------------------------------------------------------------------
  // Backup records
  // -------------------------------------------------------------------------

  listBackupRuns: (limit?: number) =>
    call<BackupRun[]>("list_backup_runs", { limit }),

  backupOverview: () => call<BackupOverview>("backup_overview"),

  /**
   * Forgets every recorded run. History only: backup *files* in the chosen
   * folder are never touched. Returns how many rows were removed.
   */
  clearBackupHistory: () => call<number>("clear_backup_history"),

  // -------------------------------------------------------------------------
  // Google Drive
  //
  // Sign-in happens in the owner's browser. No Google password is ever sent
  // here. The client secret embedded in the backend is a public identifier for
  // a desktop OAuth client; PKCE is what protects the flow.
  // -------------------------------------------------------------------------

  googleDriveStatus: () => call<GoogleDriveStatus>("google_drive_status"),

  /**
   * Opens the browser at Google's consent screen and waits for the redirect.
   * Rejects if the owner declines, cancels, or the window times out.
   */
  connectGoogleDrive: () => call<GoogleDriveStatus>("connect_google_drive"),

  /** Stops an in-flight sign-in. The pending connect call rejects. */
  cancelGoogleDriveConnect: () =>
    call<void>("cancel_google_drive_connect"),

  /** Forgets the stored sign-in. Files already in Drive are left alone. */
  disconnectGoogleDrive: () => call<GoogleDriveStatus>("disconnect_google_drive"),

  /** Proves the stored token still works; returns remaining Drive bytes. */
  testGoogleDrive: () => call<number | null>("test_google_drive"),

  /** Re-creates the per-database folders, e.g. after adding a connection. */
  syncGoogleDriveFolders: () =>
    call<GoogleDriveStatus>("sync_google_drive_folders"),

  // -------------------------------------------------------------------------
  // Running a backup
  //
  // A run reads the source through the saved connection and writes one file to
  // the chosen folder. No statement, path or command comes from the webview.
  // -------------------------------------------------------------------------

  /**
   * Starts a run and resolves when it finishes, so the UI follows
   * `onBackupProgress` for live status rather than awaiting this for updates.
   * Rejects only when the run was refused (no folder chosen, no credential,
   * unsupported engine, or another run already going); a run that started and
   * then failed comes back as `stage: "failed"` with a reason.
   */
  startBackupRun: (databaseId: string) =>
    call<BackupRunFinished>("start_backup_run", { id: databaseId }),

  /** Asks the running backup to stop. Its incomplete file is deleted. */
  cancelBackupRun: (runId: string) =>
    call<void>("cancel_backup_run", { runId }),

  /** The run in flight, if any. Lets the UI recover after a reload. */
  activeBackupRun: () => call<ActiveBackupRun | null>("active_backup_run"),
};

/** A run that has been accepted and has now finished. */
export interface BackupRunFinished {
  runId: string;
  databaseLabel: string;
  destinationLabel: string;
  /** `succeeded` | `cancelled` | `failed`. */
  stage: string;
  /** Base name of the file, present only when the run succeeded. */
  fileStem: string | null;
  /** Path relative to the chosen backup folder, when one was kept. */
  fileName: string | null;
  /** `BackMeUp/<database>/<day>/<file>` when the copy reached Drive. */
  drivePath: string | null;
  /** SHA-256 of the finished file, when the run produced one. */
  sha256: string | null;
  /** Safe sentence, present only when the run did not succeed. */
  reason: string | null;
  sizeBytes: number | null;
  rows: number | null;
}

export interface ActiveBackupRun {
  runId: string;
  /** True once a cancel has been accepted and the dump is winding down. */
  cancelling: boolean;
}

/**
 * Live progress for a run.
 *
 * `stage` is `preparing` | `reading` | `uploading` | `succeeded` | `failed` |
 * `cancelled`. Counts are cumulative for the run; `reason` is a safe sentence
 * and is only present when it ended badly.
 */
export interface BackupProgress {
  runId: string;
  databaseLabel: string;
  stage: string;
  objectsDone: number;
  rows: number;
  bytesWritten: number;
  reason: string | null;
}

/** Event name the backend emits progress on. */
export const BACKUP_PROGRESS_EVENT = "backup-run-progress";

/**
 * Subscribe to run progress.
 *
 * Returns an unsubscribe function synchronously, so a caller can dispose it
 * directly from an effect. Events are throttled by the backend, so a database
 * with thousands of tables cannot flood this listener.
 */
export function onBackupProgress(
  handler: (progress: BackupProgress) => void,
): () => void {
  let unlisten: (() => void) | undefined;
  let disposed = false;

  void listen<BackupProgress>(BACKUP_PROGRESS_EVENT, (event) => {
    handler(event.payload);
  }).then((fn) => {
    // The component may unmount before the listener is registered.
    if (disposed) {
      fn();
    } else {
      unlisten = fn;
    }
  });

  return () => {
    disposed = true;
    unlisten?.();
  };
}