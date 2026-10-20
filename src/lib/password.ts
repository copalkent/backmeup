export interface PasswordRequirement {
  id: string;
  label: string;
  met: boolean;
}

const MIN_LENGTH = 12;

/**
 * Frontend password checklist. Purely a usability aid - the identical policy is
 * enforced authoritatively in `src-tauri/src/validate.rs`.
 */
export function describePassword(password: string): PasswordRequirement[] {
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9\s]/.test(password);

  return [
    { id: "length", label: `At least ${MIN_LENGTH} characters`, met: password.length >= MIN_LENGTH },
    { id: "lower", label: "A lowercase letter", met: hasLower },
    { id: "upper", label: "An uppercase letter", met: hasUpper },
    { id: "digit", label: "A number", met: hasDigit },
    { id: "symbol", label: "A symbol", met: hasSymbol },
  ];
}

export const PASSWORD_MIN_LENGTH = MIN_LENGTH;

export type PasswordStrengthLevel = 0 | 1 | 2 | 3 | 4;

/** Wording for each level of `scorePassword`. */
export const PASSWORD_STRENGTH_LABELS: Record<PasswordStrengthLevel, string> = {
  0: "Too short",
  1: "Weak",
  2: "Fair",
  3: "Strong",
  4: "Very strong",
};

/**
 * Maps a password onto a 0-4 strength level for the progress meter.
 *
 * The level is derived purely from how many of the real requirements are met,
 * so the meter can never imply a stronger password than `describePassword`
 * will actually accept. It is presentation only - the backend policy in
 * `src-tauri/src/validate.rs` remains authoritative.
 */
export function scorePassword(password: string): PasswordStrengthLevel {
  const met = describePassword(password).filter(
    (requirement) => requirement.met,
  ).length;

  if (met <= 0) return 0;
  if (met <= 2) return 1;
  if (met === 3) return 2;
  if (met === 4) return 3;
  return 4;
}

/** Group a recovery code for display: `ABCDE-FGHJK-...` -> `ABCDE FGHJK ...` */
export function formatRecoveryCode(code: string): string {
  return code.replace(/-/g, " ");
}