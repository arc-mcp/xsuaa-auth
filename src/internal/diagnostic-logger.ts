import { types } from 'node:util';
import { type Logger, noopLogger } from '../logger.js';

type DiagnosticData = Record<string, unknown> | (() => Record<string, unknown>);
type DiagnosticLogger = Record<'debug' | 'info' | 'warn', (message: string, data?: DiagnosticData) => void>;

/** Do not coerce arbitrary exceptions or execute message/prototype getters. */
export function diagnosticError(error: unknown): Record<string, unknown> {
  if (typeof error === 'string') return { error };
  if (typeof error === 'object' && error !== null && !types.isProxy(error)) {
    const message = Object.getOwnPropertyDescriptor(error, 'message');
    if (message && Object.hasOwn(message, 'value') && typeof message.value === 'string') {
      return { error: message.value };
    }
  }
  return { error: 'Unknown verifier error' };
}

/** Diagnostics must not replace a verification result or select a weaker verifier. */
export function diagnosticLogger(logger: Logger = noopLogger): DiagnosticLogger {
  function log(level: keyof DiagnosticLogger, message: string, data?: DiagnosticData): void {
    try {
      const fields = typeof data === 'function' ? data() : data;
      const result: unknown = fields === undefined ? logger[level](message) : logger[level](message, fields);
      // A void-typed sink can still return a Promise/thenable. Consume failures
      // without awaiting delivery or delaying the authentication decision.
      if (result !== undefined) void Promise.resolve(result).catch(() => {});
    } catch {
      // Best-effort diagnostic sink only. This does not wrap or suppress audits.
    }
  }
  return {
    debug: (message, data) => log('debug', message, data),
    info: (message, data) => log('info', message, data),
    warn: (message, data) => log('warn', message, data),
  };
}
