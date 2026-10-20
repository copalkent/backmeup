import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

import {
  THEME_FADE_CLASS,
  THEME_FADE_MS,
  WINDOW_BACKGROUND,
  initialTheme,
  persistTheme,
  type Theme,
} from "@/lib/theme";

const appWindow = getCurrentWindow();

interface ThemeContextValue {
  theme: Theme;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const isFirstPaint = useRef(true);

  useLayoutEffect(() => {
    const root = document.documentElement;

    root.classList.toggle("dark", theme === "dark");
    root.style.colorScheme = theme;

    // `public/theme-boot.js` has already applied this exact theme before first
    // paint, so the initial pass must neither animate nor re-write storage.
    if (isFirstPaint.current) {
      isFirstPaint.current = false;
      return;
    }

    persistTheme(theme);

    // Added in the same pre-paint frame as the class swap so the change
    // cross-fades, then dropped so it never affects later transitions.
    root.classList.add(THEME_FADE_CLASS);
    const fade = window.setTimeout(() => {
      root.classList.remove(THEME_FADE_CLASS);
    }, THEME_FADE_MS);

    return () => window.clearTimeout(fade);
  }, [theme]);

  useLayoutEffect(() => {
    // Keep the native window and the native save dialog (recovery-code export)
    // in step with the in-app palette so there is no white flash while
    // resizing or while the file dialog is open.
    void (async () => {
      try {
        await appWindow.setTheme(theme);
        await appWindow.setBackgroundColor(WINDOW_BACKGROUND[theme]);
      } catch {
        /* The window API is unavailable outside the desktop shell. */
      }
    })();
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((current) => (current === "dark" ? "light" : "dark"));
  }, []);

  const value = useMemo(
    () => ({ theme, toggleTheme }),
    [theme, toggleTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used inside ThemeProvider.");
  }
  return context;
}