/**
 * Draft persistence for the Add/Edit database form.
 *
 * A draft lives in `localStorage`, which is not a secret store, so it only
 * ever holds the non-secret fields. Passwords, SSH passwords, private keys
 * and passphrases are stripped before writing and shown blank when a draft is
 * restored - those secrets stay in the Windows Credential Manager, as they do
 * everywhere else in BackMeUp.
 */

/** The form fields a draft may hold. Secrets are deliberately absent. */
export interface DatabaseDraftFields {
  label: string;
  engine: string;
  connectionMethod: string;
  host: string;
  port: string;
  databaseName: string;
  username: string;
  sshHost: string;
  sshPort: string;
  sshUsername: string;
  sshAuthMethod: string;
  sshHostKeyFingerprint: string;
}

export interface DatabaseDraft {
  fields: DatabaseDraftFields;
  /** `null` for the unsaved "add" form, otherwise the id being edited. */
  editingId: string | null;
  /** Epoch seconds, so it formats with the other timestamps in the app. */
  savedAt: number;
}

const STORAGE_KEY = "backmeup.database-draft.v1";

const FIELD_KEYS: (keyof DatabaseDraftFields)[] = [
  "label",
  "engine",
  "connectionMethod",
  "host",
  "port",
  "databaseName",
  "username",
  "sshHost",
  "sshPort",
  "sshUsername",
  "sshAuthMethod",
  "sshHostKeyFingerprint",
];

/** Every draftable field is short by design; anything longer was not written by this app. */
const MAX_FIELD_LENGTH = 512;

/**
 * Read the stored draft, or null when there is none or it cannot be trusted.
 *
 * The contents are treated as untrusted input: unknown keys are dropped, every
 * value must already be a string and is length-capped, so a tampered store can
 * never inject more than a long form value.
 */
export function loadDatabaseDraft(): DatabaseDraft | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw) as {
      fields?: unknown;
      editingId?: unknown;
      savedAt?: unknown;
    };
    if (!parsed || typeof parsed !== "object") return null;

    const source = parsed.fields;
    if (!source || typeof source !== "object") return null;

    const record = source as Record<string, unknown>;
    const fields = {} as DatabaseDraftFields;
    for (const key of FIELD_KEYS) {
      const value = record[key];
      if (value !== undefined && typeof value !== "string") return null;
      fields[key] =
        typeof value === "string" ? value.slice(0, MAX_FIELD_LENGTH) : "";
    }

    return {
      fields,
      editingId: typeof parsed.editingId === "string" ? parsed.editingId : null,
      savedAt: typeof parsed.savedAt === "number" ? parsed.savedAt : 0,
    };
  } catch {
    return null;
  }
}

/** Store a draft. A draft is a convenience, so a storage failure is silent. */
export function saveDatabaseDraft(
  fields: DatabaseDraftFields,
  editingId: string | null,
): void {
  try {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        fields,
        editingId,
        savedAt: Math.floor(Date.now() / 1000),
      }),
    );
  } catch {
    // Nothing to do: the form can still be saved the normal way.
  }
}

export function clearDatabaseDraft(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do: an unreadable draft is ignored anyway.
  }
}

/** Whether a draft belongs to the same target (the "add" slot or one row id). */
export function draftMatches(
  draft: DatabaseDraft | null,
  editingId: string | null,
): boolean {
  return draft !== null && draft.editingId === editingId;
}
