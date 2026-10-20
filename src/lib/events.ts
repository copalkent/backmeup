/**
 * Tiny app-wide signals.
 *
 * The title bar shows destination status and the destination controls live in
 * a different subtree, so a change made in one place has to reach the other.
 * A DOM event is enough for this: there is exactly one listener, no payload,
 * and no store to keep in sync.
 */

const DESTINATIONS_CHANGED = "backmeup:destinations-changed";
const NOTICES_CHANGED = "backmeup:notices-changed";

/** Tell anything listening that a backup destination changed. */
export function notifyDestinationsChanged(): void {
  window.dispatchEvent(new Event(DESTINATIONS_CHANGED));
}

/** Subscribe to destination changes. Returns the unsubscribe function. */
export function onDestinationsChanged(handler: () => void): () => void {
  window.addEventListener(DESTINATIONS_CHANGED, handler);
  return () => window.removeEventListener(DESTINATIONS_CHANGED, handler);
}

/**
 * Tell anything listening that the notices changed.
 *
 * A finished backup, a tested connection and a dismissed update all change
 * what the bell has to say, and each of them happens somewhere else.
 */
export function notifyNoticesChanged(): void {
  window.dispatchEvent(new Event(NOTICES_CHANGED));
}

/** Subscribe to notice changes. Returns the unsubscribe function. */
export function onNoticesChanged(handler: () => void): () => void {
  window.addEventListener(NOTICES_CHANGED, handler);
  return () => window.removeEventListener(NOTICES_CHANGED, handler);
}
