/**
 * Presentation helpers for the backup records.
 *
 * Every input here comes from the backend, and every branch falls back to a
 * neutral placeholder rather than a guess, so a missing or unexpected value can
 * never render as a plausible-looking date or size.
 */

import type { TestState } from "@/lib/api";

const dateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

const dateOnly = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

/** Seconds since the epoch -> a local date and time, or `-` when absent. */
export function formatDateTime(epochSeconds: number | null | undefined): string {
  if (typeof epochSeconds !== "number" || !Number.isFinite(epochSeconds) || epochSeconds <= 0) {
    return "-";
  }
  return dateTime.format(new Date(epochSeconds * 1000));
}

/** Seconds since the epoch -> a local date, or `-` when absent. */
export function formatDate(epochSeconds: number | null | undefined): string {
  if (typeof epochSeconds !== "number" || !Number.isFinite(epochSeconds) || epochSeconds <= 0) {
    return "-";
  }
  return dateOnly.format(new Date(epochSeconds * 1000));
}

/** Bytes -> a short human size, or `-` when the size was not recorded. */
export function formatBytes(bytes: number | null | undefined): string {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) {
    return "-";
  }
  if (bytes < 1024) return `${bytes} B`;

  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

const RUN_STATUS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
};

/** Raw backend status -> display wording, defaulting to the raw value. */
export function formatRunStatus(status: string): string {
  return RUN_STATUS[status] ?? status;
}

/** Whether a recorded run reached a successful finish. */
export function isSuccessful(status: string): boolean {
  return status === "succeeded";
}

/**
 * Wording for a connection's last test.
 *
 * Deliberately never says "online": a stored result describes a moment in the
 * past, not the server's current state.
 */
export function describeTestState(
  state: TestState,
  lastTestedAt: number | null,
  hasCredentials: boolean,
): string {
  if (!hasCredentials) return "Password not stored";

  switch (state) {
    case "succeeded":
      return `Last test succeeded${
        lastTestedAt ? ` ${formatDateTime(lastTestedAt)}` : ""
      }`;
    case "failed":
      return `Last test failed${
        lastTestedAt ? ` ${formatDateTime(lastTestedAt)}` : ""
      }`;
    default:
      return "Not tested yet";
  }
}