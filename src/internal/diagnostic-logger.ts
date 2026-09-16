import { type Logger, noopLogger } from '../logger.js';

type DiagnosticLogger = Pick<Logger, 'debug' | 'info' | 'warn'>;

/** Diagnostics must not replace a verification result or select a weaker verifier. */
export function diagnosticLogger(logger: Logger = noopLogger): DiagnosticLogger {
  function log(level: keyof DiagnosticLogger, message: string, data?: Record<string, unknown>): void {
    try {
      logger[level](message, data);
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
