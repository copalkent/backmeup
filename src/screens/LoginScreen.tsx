import { useState } from "react";
import { Loader2, LogIn } from "lucide-react";

import { Brand } from "@/components/Brand";
import { PasswordField } from "@/components/PasswordField";
import { Field, ScreenShell } from "@/components/ScreenShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError, api } from "@/lib/api";

interface LoginScreenProps {
  onLogin: () => void;
  onForgotPassword: () => void;
}

export function LoginScreen({ onLogin, onForgotPassword }: LoginScreenProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    if (!email.trim() || !password) {
      setError("Enter your email address and password.");
      return;
    }

    setSubmitting(true);
    try {
      await api.login({ email: email.trim(), password });
      setPassword("");
      onLogin();
    } catch (loginError) {
      setError(
        loginError instanceof ApiError
          ? loginError.message
          : "Sign in failed. Please try again.",
      );
      setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <ScreenShell
      center
      icon={<Brand />}
      title="Sign in to BackMeUp"
      description="Your account is stored on this device only."
    >
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <form className="flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
        <Field id="login-email" label="Email address">
          <Input
            id="login-email"
            name="email"
            type="email"
            inputMode="email"
            autoComplete="username"
            placeholder="you@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={submitting}
          />
        </Field>

        <Field id="login-password" label="Password">
          <PasswordField
            id="login-password"
            name="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={submitting}
          />
        </Field>

        <Button type="submit" size="lg" disabled={submitting}>
          {submitting ? (
            <Loader2 className="size-4 animate-spin" aria-hidden="true" />
          ) : (
            <LogIn className="size-4" aria-hidden="true" />
          )}
          Sign in
        </Button>
      </form>

      <div className="text-sm">
        <button
          type="button"
          onClick={onForgotPassword}
          disabled={submitting}
          className="text-primary underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          Forgot password?
        </button>
      </div>
    </ScreenShell>
  );
}