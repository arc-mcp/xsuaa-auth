/**
 * Test helper: a capturing {@link Logger} that records every call into per-level
 * arrays plus an `audit` array fed by `emitAudit`.
 *
 * The package logger is INJECTED (no global logger to spy on, unlike arc-1's
 * module-level `logger`). So instead of `vi.spyOn(logger, 'warn')`, tests build a
 * `CapturingLogger`, pass it into the unit under test, and assert against its
 * recorded entries.
 */

import type { Logger } from '../../src/logger.js';

export interface LogEntry {
  message: string;
  data?: Record<string, unknown>;
}

export interface CapturingLogger extends Logger {
  debugs: LogEntry[];
  infos: LogEntry[];
  warns: LogEntry[];
  errors: LogEntry[];
  /** Events passed to `emitAudit`. */
  audit: Record<string, unknown>[];
  /** True if any level recorded a message matching `re`. */
  has(level: 'debug' | 'info' | 'warn' | 'error', re: RegExp): boolean;
}

/** Build a fresh capturing logger. */
export function makeCapturingLogger(): CapturingLogger {
  const debugs: LogEntry[] = [];
  const infos: LogEntry[] = [];
  const warns: LogEntry[] = [];
  const errors: LogEntry[] = [];
  const audit: Record<string, unknown>[] = [];

  const bucketFor = (level: 'debug' | 'info' | 'warn' | 'error'): LogEntry[] =>
    level === 'debug' ? debugs : level === 'info' ? infos : level === 'warn' ? warns : errors;

  return {
    debugs,
    infos,
    warns,
    errors,
    audit,
    debug: (message, data) => {
      debugs.push({ message, data });
    },
    info: (message, data) => {
      infos.push({ message, data });
    },
    warn: (message, data) => {
      warns.push({ message, data });
    },
    error: (message, data) => {
      errors.push({ message, data });
    },
    emitAudit: (event) => {
      audit.push(event);
    },
    has: (level, re) => bucketFor(level).some((e) => re.test(e.message)),
  };
}
