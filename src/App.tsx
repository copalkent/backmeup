import { useCallback, useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

import { AppShell, type AppSection } from "@/components/AppShell";
import { ThemeProvider } from "@/components/ThemeProvider";
import { TitleBar } from "@/components/TitleBar";
import { ToastProvider } from "@/components/Toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { BackupHistoryScreen } from "@/screens/BackupHistoryScreen";
import { DashboardScreen } from "@/screens/DashboardScreen";
import { DatabasesScreen } from "@/screens/DatabasesScreen";
import { ForgotPasswordScreen } from "@/screens/ForgotPasswordScreen";
import { LoginScreen } from "@/screens/LoginScreen";
import { RecoveryCodesScreen } from "@/screens/RecoveryCodesScreen";
import { SecurityScreen } from "@/screens/SecurityScreen";
import { SettingsScreen } from "@/screens/SettingsScreen";
import { SetupScreen } from "@/screens/SetupScreen";
import {
  ApiError,
  type BootstrapState,
  type RecoveryCodesView,
  api,
} from "@/lib/api";

type View =
  | "loading"
  | "setup"
  | "codes"
  | "login"
  | "forgot-password"
  | "app"
  | "security";

interface CodesState {
  codes: string[];
  context: "setup" | "regenerate";
}

export default function App() {
  const [view, setView] = useState<View>("loading");
  const [boot, setBoot] = useState<BootstrapState | null>(null);
  const [codesState, setCodesState] = useState<CodesState | null>(null);
  const [fatalError, setFatalError] = useState<string | null>(null);

  /**
   * Signed-in navigation. Lives here rather than in a store because the app is
   * a flat list of four sections.
   */
  const [section, setSection] = useState<AppSection>("dashboard");

  /**
   * Ask the backend which screen to show. The routing decision is derived from
   * Rust state on every transition, so hiding a screen in the UI is never what
   * keeps an unauthenticated user out of a privileged operation.
   */
  const refresh = useCallback(async (fallback?: View) => {
    try {
      const next = await api.bootstrapState();
      setBoot(next);
      setFatalError(null);

      if (next.needsSetup) {
        setView("setup");
      } else if (next.authenticated) {
        if (!next.setupConfirmed) {
          setView("security");
        } else {
          setView(fallback ?? "app");
        }
      } else {
        setView(fallback ?? "login");
      }
    } catch (error) {
      setFatalError(
        error instanceof ApiError
          ? error.message
          : "BackMeUp could not open its local database.",
      );
      setView("login");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleSignOut = useCallback(async () => {
    // Return to a known section so the next sign-in never lands on a stale view.
    setSection("dashboard");
    await api.logout().then(() => refresh("login"));
  }, [refresh]);

  function handleSetupComplete(result: RecoveryCodesView) {
    setCodesState({ codes: result.recoveryCodes, context: "setup" });
    setView("codes");
  }

  async function handleCodesDone() {
    setCodesState(null);
    await refresh("app");
  }

  const signedIn = view === "app";

  return (
    <ThemeProvider>
      <TooltipProvider delayDuration={350}>
        <ToastProvider>
          <div className="flex h-full flex-col overflow-hidden bg-background">
            <TitleBar
              signedIn={signedIn}
              owner={boot?.owner ?? null}
              onOpenSettings={() => setSection("settings")}
            />

            <main className="relative min-h-0 flex-1 overflow-hidden">
              {view === "loading" ? (
                <div className="flex h-full items-center justify-center">
                  <Loader2
                    className="size-5 animate-spin text-muted-foreground"
                    aria-label="Loading"
                  />
                </div>
              ) : null}

              {view === "setup" ? (
                <SetupScreen onSetupComplete={handleSetupComplete} />
              ) : null}

              {view === "codes" && codesState ? (
                <RecoveryCodesScreen
                  codes={codesState.codes}
                  context={codesState.context}
                  onDone={() => void handleCodesDone()}
                  onCancel={() => void refresh("app")}
                />
              ) : null}

              {view === "login" ? (
                <LoginScreen
                  onLogin={() => void refresh("app")}
                  onForgotPassword={() => setView("forgot-password")}
                />
              ) : null}

              {view === "forgot-password" ? (
                <ForgotPasswordScreen
                  onBack={() => setView("login")}
                  onRecovered={() => void refresh("login")}
                />
              ) : null}

              {signedIn ? (
                <AppShell section={section} onNavigate={setSection}>
                  {section === "dashboard" ? (
                    <DashboardScreen
                      fullName={boot?.owner?.fullName ?? ""}
                      remainingRecoveryCodes={
                        boot?.remainingRecoveryCodes ?? null
                      }
                      onOpenSecurity={() => setView("security")}
                      onAddDatabase={() => setSection("databases")}
                      onOpenBackups={() => setSection("history")}
                    />
                  ) : null}

                  {section === "databases" ? <DatabasesScreen /> : null}

                  {section === "history" ? <BackupHistoryScreen /> : null}

                  {section === "settings" ? (
                    <SettingsScreen
                      fullName={boot?.owner?.fullName ?? ""}
                      email={boot?.owner?.email ?? ""}
                      onOpenSecurity={() => setView("security")}
                      onSignOut={() => void handleSignOut()}
                    />
                  ) : null}
                </AppShell>
              ) : null}

              {view === "security" ? (
                <SecurityScreen
                  setupIncomplete={boot?.setupConfirmed === false}
                  onBack={() =>
                    boot?.setupConfirmed === false
                      ? void refresh("app")
                      : setView("app")
                  }
                />
              ) : null}

              {fatalError && view !== "loading" ? (
                <div className="pointer-events-none absolute inset-x-0 top-0 flex justify-center px-6 pt-4">
                  <p
                    role="status"
                    className="pointer-events-auto rounded-md border border-foreground bg-background px-3 py-1.5 text-xs font-medium text-foreground"
                  >
                    {fatalError}
                  </p>
                </div>
              ) : null}
            </main>
          </div>
        </ToastProvider>
      </TooltipProvider>
    </ThemeProvider>
  );
}
