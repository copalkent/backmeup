/**
 * Tiny app-wide signals.
 *
 * The title bar shows destination status and the destination controls live in
 * a different subtree, so a change made in one place has to reach the other.
 * A DOM event is enough for this: there is exactly one listener, no payload,
 * and no store to keep in sync.
 */

const DESTINATIONS_CHANGED = "backmeup:destinations-changed";

/** Tell anything listening that a backup destination changed. */
export function notifyDestinationsChanged(): void {
  window.dispatchEvent(new Event(DESTINATIONS_CHANGED));
}

/** Subscribe to destination changes. Returns the unsubscribe function. */
export function onDestinationsChanged(handler: () => void): () => void {
  window.addEventListener(DESTINATIONS_CHANGED, handler);
  return () => window.removeEventListener(DESTINATIONS_CHANGED, handler);
}
