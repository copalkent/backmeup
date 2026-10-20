import {
  PASSWORD_STRENGTH_LABELS,
  scorePassword,
} from "@/lib/password";
import { cn } from "@/lib/utils";

const SEGMENTS = [1, 2, 3, 4] as const;

/**
 * Compact replacement for the per-requirement checklist.
 *
 * A single segmented bar plus one word conveys the same information without a
 * column of icons. The level comes straight from `scorePassword`, so the bar
 * and the validation the backend performs can never disagree.
 */
export function PasswordStrength({ password }: { password: string }) {
  const score = scorePassword(password);
  const label = PASSWORD_STRENGTH_LABELS[score];

  return (
    <div className="flex items-center gap-2">
      <div
        role="progressbar"
        aria-label="Password strength"
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={score}
        aria-valuetext={password ? label : "No password entered"}
        className="flex flex-1 gap-1"
      >
        {SEGMENTS.map((segment) => (
          <span
            key={segment}
            className={cn(
              "h-1 flex-1 rounded-full transition-colors",
              segment <= score ? "bg-foreground" : "bg-border",
            )}
          />
        ))}
      </div>
      {password ? (
        <span
          aria-hidden="true"
          className="shrink-0 text-xs font-medium text-muted-foreground"
        >
          {label}
        </span>
      ) : null}
    </div>
  );
}