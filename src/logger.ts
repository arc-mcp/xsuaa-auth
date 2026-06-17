/**
 * Structural logger contract — injected everywhere, optional, defaults to no-op.
 *
 * Argument order is `(message, data)` to match the source consumers (arc-1, LISA).
 * Consumers using a different shape (e.g. pino's `(obj, msg)`) pass a thin adapter.
 * `emitAudit` is optional and is always invoked null-safely (`logger.emitAudit?.(…)`).
 */
export interface Logger {
  debug(message: string, data?: Record<string, unknown>): void;
  info(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
  emitAudit?(event: Record<string, unknown>): void;
}

const noop = (): void => {};

/** Default logger used when a consumer injects none. Silent. */
export const noopLogger: Logger = {
  debug: noop,
  info: noop,
  warn: noop,
  error: noop,
};
