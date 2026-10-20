/**
 * Light/dark theme state.
 *
 * The choice is a local UI preference only: it never gates a privileged action
 * and the backend re-derives every authorization decision from Rust state. The
 * stored value is untrusted input, so it is validated against a strict
 * allowlist before it is written to the DOM or handed to Tauri.
 */

export type Theme = "light" | "dark";

/** Keep in sync with `public/theme-boot.js`, which runs before first paint. */
export const THEME_STORAGE_KEY = "backmeup.theme";

/** Must exceed the 200ms cross-fade defined by `.theme-fade` in index.css. */
export const THEME_FADE_MS = 240;

export const THEME_FADE_CLASS = "theme-fade";

/** Native window colours, kept in step with the CSS tokens. */
export const WINDOW_BACKGROUND: Record<Theme, string> = {
  light: "#ffffff",
  dark: "#000000",
};

/**
 * Only ever returns a usable theme. A missing, malformed or oversized stored
 * value falls back to the Windows colour preference instead of being trusted.
 */
function parseStoredTheme(raw: string | null): Theme | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 16) {
    return null;
  }
  return raw === "light" || raw === "dark" ? raw : null;
}

export function readStoredTheme(): Theme | null {
  try {
    return parseStoredTheme(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    // Storage can be unavailable or blocked; the system preference is enough.
    return null;
  }
}

export function persistTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    /* Losing the preference must never break the toggle. */
  }
}

export function systemTheme(): Theme {
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  } catch {
    return "dark";
  }
}

/** Mirrors what `public/theme-boot.js` already applied, so nothing shifts. */
export function initialTheme(): Theme {
  return readStoredTheme() ?? systemTheme();
}