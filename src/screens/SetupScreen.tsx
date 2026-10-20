import { useState } from "react";
import { Loader2, UserPlus } from "lucide-react";

import { Brand } from "@/components/Brand";
import { PasswordField } from "@/components/PasswordField";
import { PasswordStrength } from "@/components/PasswordStrength";
import { Field, ScreenShell } from "@/components/ScreenShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError, type RecoveryCodesView, api } from "@/lib/api";
import { describePassword } from "@/lib/password";

interface SetupScreenProps {
  onSetupComplete: (result: RecoveryCodesView) => void;
}

interface FieldErrors {
  fullName?: string;
  email?: string;
  password?: string;
  confirmPassword?: string;
}

export function SetupScreen({ onSetupComplete }: SetupScreenProps) {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const requirements = describePassword(password);

  function validateClient(): FieldErrors {
    const errors: FieldErrors = {};

    if (fullName.trim().length < 2) {
      errors.fullName = "Enter your full name.";
    }
    if (!/^[^\s@]+@[^\s@]+\.[A-Za-z]{2,}$/.test(email.trim())) {
      errors.email = "Enter a valid email address.";
    }
    if (requirements.some((requirement) => !requirement.met)) {
      errors.password = "Your password does not meet the requirements.";
    }
    if (password !== confirmPassword) {
      errors.confirmPassword = "Passwords do not match.";
    }

    return errors;
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setFormError(null);

    const errors = validateClient();
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) {
      return;
    }

    setSubmitting(true);
    try {
      const result = await api.setupOwner({
        fullName: fullName.trim(),
        email: email.trim(),
        password,
        confirmPassword,
      });
      onSetupComplete(result);
    } catch (error) {
      setFormError(
        error instanceof ApiError ? error.message : "Setup could not be completed.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <ScreenShell
      center
      icon={<Brand />}
      title="Set up BackMeUp"
      description="Create the owner account for this device. It is stored locally and never leaves this computer."
    >
      {formError ? (
        <Alert variant="destructive">
          <AlertDescription>{formError}</AlertDescription>
        </Alert>
      ) : null}

      <form className="flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
        <Field id="full-name" label="Full name" error={fieldErrors.fullName}>
          <Input
            id="full-name"
            name="name"
            autoComplete="name"
            placeholder="Kent Louise"
            value={fullName}
            onChange={(event) => setFullName(event.target.value)}
            aria-invalid={Boolean(fieldErrors.fullName)}
            aria-describedby={fieldErrors.fullName ? "full-name-error" : undefined}
            disabled={submitting}
          />
        </Field>

        <Field id="email" label="Email address" error={fieldErrors.email}>
          <Input
            id="email"
            name="email"
            type="email"
            inputMode="email"
            autoComplete="username"
            placeholder="you@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            aria-invalid={Boolean(fieldErrors.email)}
            aria-describedby={fieldErrors.email ? "email-error" : undefined}
            disabled={submitting}
          />
        </Field>

<Field
          id="password"
          label="Password"
          error={fieldErrors.password}
          hint={<PasswordStrength password={password} />}
        >
          <PasswordField
            id="password"
            name="new-password"
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            aria-invalid={Boolean(fieldErrors.password)}
            aria-describedby={
              fieldErrors.password ? "password-error" : "password-hint"
            }
            disabled={submitting}
          />
        </Field>

        <Field
          id="confirm-password"
          label="Confirm password"
          error={fieldErrors.confirmPassword}
        >
          <PasswordField
            id="confirm-password"
            name="confirm-password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            aria-invalid={Boolean(fieldErrors.confirmPassword)}
            aria-describedby={
              fieldErrors.confirmPassword ? "confirm-password-error" : undefined
            }
            disabled={submitting}
          />
        </Field>

        <Button type="submit" size="lg" disabled={submitting}>
          {submitting ? (
            <Loader2 className="size-4 animate-spin" aria-hidden="true" />
          ) : (
            <UserPlus className="size-4" aria-hidden="true" />
          )}
          Create account
        </Button>
      </form>
    </ScreenShell>
  );
}