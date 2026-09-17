import type { Logger } from '../logger.js';
import type { AuthInfo } from './sdk.js';

const malformedResults = new WeakSet<object>();

/** Internal integration failures must survive the built-in verifier catch blocks. */
export function isMalformedAuthInfoError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && malformedResults.has(error);
}

/** Validate only core result fields; optional SAP identity metadata is not an auth gate. */
export function assertAuthInfo(result: AuthInfo, logger: Pick<Logger, 'warn'>, method: string): void {
  try {
    if (typeof result === 'object' && result !== null && typeof result.token === 'string') {
      const scopes = result.scopes;
      if (Array.isArray(scopes)) {
        let valid = true;
        for (let index = 0; index < scopes.length; index++) {
          if (typeof scopes[index] !== 'string') {
            valid = false;
            break;
          }
        }
        if (valid) return;
      }
    }
  } catch {
    // Transparent result wrappers are valid; throwing core reads are not.
  }
  logger.warn('Verifier integration failure', { method, reason: 'malformed_auth_info' });
  const error = new Error('Verifier returned malformed AuthInfo');
  malformedResults.add(error);
  throw error;
}
