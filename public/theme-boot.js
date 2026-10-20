/*
 * Applies the saved theme before the first paint.
 *
 * This lives in `public/` as a separate file rather than an inline <script> so
 * the `script-src 'self'` CSP stays intact. It must stay in sync with
 * src/lib/theme.ts.
 */
(function () {
  var root = document.documentElement;
  var theme = null;

  try {
    var stored = window.localStorage.getItem("backmeup.theme");
    // The stored value is untrusted input: accept only the exact allowlist.
    if (stored === "light" || stored === "dark") {
      theme = stored;
    }
  } catch (error) {
    theme = null;
  }

  if (theme === null) {
    try {
      theme = window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    } catch (error) {
      theme = "dark";
    }
  }

  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme;
})();