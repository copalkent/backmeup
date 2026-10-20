import { useState } from "react";
import { ArrowLeft, Loader2, RotateCcw } from "lucide-react";

import { PasswordField } from "@/components/PasswordField";
import { PasswordStrength } from "@/components/PasswordStrength";
import { Field, ScreenShell } from "@/components/ScreenShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError, api } from "@/lib/api";
import { describePassword } from "@/lib/password";

interface ForgotPasswordScreenProps {
  onBack: () => void;
  onRecovered: () => void;
}

export function ForgotPasswordScreen({
  onBack,
  onRecovered,
}: ForgotPasswordScreenProps) {
  const [email, setEmail] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  const requirements = describePassword(newPassword);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);

    const errors: Record<string, string> = {};
    if (!email.trim()) errors.email = "Enter the email you registered with.";
    if (!recoveryCode.trim()) {
      errors.recoveryCode = "Enter one of your recovery codes.";
    }
    if (requirements.some((requirement) => !requirement.met)) {
      errors.newPassword = "Your new password does not meet the requirements.";
    }
    if (newPassword !== confirmPassword) {
      errors.confirmPassword = "Passwords do not match.";
    }
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      return;
    }

    setSubmitting(true);
    try {
      await api.recoverPassword({
        email: email.trim(),
        recoveryCode: recoveryCode.trim(),
        newPassword,
        confirmPassword,
      });
      setNotice(
        "Password updated. Your recovery code has been used and can no longer be used again. Please sign in with your new password.",
      );
      window.setTimeout(() => {
        setNewPassword("");
        setConfirmPassword("");
        setRecoveryCode("");
        onRecovered();
      }, 2200);
    } catch (recoveryError) {
      // The backend deliberately returns a generic message so it cannot be
      // used to discover whether an email or a code exists.
      setError(
        recoveryError instanceof ApiError
          ? recoveryError.message
          : "Recovery failed. Please try again.",
      );
      setRecoveryCode("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <ScreenShell
      wide
      icon={<RotateCcw aria-hidden="true" />}
      title="Recover your account"
      description="Use one of your 10 recovery codes to set a new password. Each code works only once."
    >
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {notice ? (
        <Alert variant="success">
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}

      <form className="flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
        <Field id="recovery-email" label="Registered email address" error={fieldErrors.email}>
          <Input
            id="recovery-email"
            type="email"
            inputMode="email"
            autoComplete="username"
            placeholder="you@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            aria-invalid={Boolean(fieldErrors.email)}
            disabled={submitting}
          />
        </Field>

        <Field
          id="recovery-code"
          label="Recovery code"
          error={fieldErrors.recoveryCode}
          hint="Enter one unused code exactly as it was saved."
        >
          <Input
            id="recovery-code"
            className="font-mono tracking-[0.18em] uppercase"
            placeholder="XXXXX-XXXXX-XXXXX-XXXXX"
            value={recoveryCode}
            onChange={(event) => setRecoveryCode(event.target.value.toUpperCase())}
            aria-invalid={Boolean(fieldErrors.recoveryCode)}
            autoComplete="one-time-code"
            spellCheck={false}
            disabled={submitting}
          />
        </Field>

        <Field
          id="recovery-password"
          label="New password"
          error={fieldErrors.newPassword}
          hint={<PasswordStrength password={newPassword} />}
        >
          <PasswordField
            id="recovery-password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            aria-invalid={Boolean(fieldErrors.newPassword)}
            aria-describedby={
              fieldErrors.newPassword
                ? "recovery-password-error"
                : "recovery-password-hint"
            }
            disabled={submitting}
          />
        </Field>

        <Field
          id="recovery-confirm"
          label="Confirm new password"
          error={fieldErrors.confirmPassword}
        >
          <PasswordField
            id="recovery-confirm"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            aria-invalid={Boolean(fieldErrors.confirmPassword)}
            disabled={submitting}
          />
        </Field>

        <div className="flex flex-col gap-2">
          <Button type="submit" size="lg" disabled={submitting || Boolean(notice)}>
            {submitting ? (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            ) : null}
            Reset password
          </Button>
          <Button type="button" variant="ghost" onClick={onBack} disabled={submitting}>
            <ArrowLeft className="size-4" aria-hidden="true" />
            Back to sign in
          </Button>
        </div>
      </form>
    </ScreenShell>
  );
}