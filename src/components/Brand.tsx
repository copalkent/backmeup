import { cn } from "@/lib/utils";

interface BrandProps {
  className?: string;
}

/**
 * Official BackMeUp mark, used on the authentication screens.
 *
 * The supplied artwork is black, so a white recolour of the exact same alpha
 * channel ships alongside it for Dark Mode. Both variants are rendered at once
 * and swapped with the `dark` variant, so they are already in the HTTP cache
 * when the theme flips and no flash of the wrong colour is possible. The logo
 * sits on the window background directly - no container, border or backing
 * plate.
 */
export function Brand({ className }: BrandProps) {
  return (
    <span
      role="img"
      aria-label="BackMeUp"
      className={cn("relative block h-20 w-16", className)}
    >
      <img
        src="/brand/backmeup-logo-black.png"
        alt=""
        aria-hidden="true"
        className="absolute inset-0 h-full w-full object-contain dark:hidden"
      />
      <img
        src="/brand/backmeup-logo-white.png"
        alt=""
        aria-hidden="true"
        className="absolute inset-0 hidden h-full w-full object-contain dark:block"
      />
    </span>
  );
}