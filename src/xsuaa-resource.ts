import { types } from 'node:util';
import { InvalidTokenError } from './internal/sdk.js';

const CODE = 'XSUAA_RESOURCE_MISMATCH';
const localErrors = new WeakSet<object>();

/** A verified XSUAA token lacks the configured MCP resource audience. */
export class XsuaaResourceMismatchError extends InvalidTokenError {
  readonly code: typeof CODE = CODE;

  constructor() {
    super('Token was not issued for this resource');
    this.name = 'XsuaaResourceMismatchError';
    localErrors.add(this);
  }
}

/** A verified-token denial must not fall through to another verifier. */
export function resourceRejection(error: unknown): XsuaaResourceMismatchError | undefined {
  const seen = new Set<object>();
  let current = error;
  while (typeof current === 'object' && current !== null && !seen.has(current)) {
    if (types.isProxy(current)) throw new Error('Verifier returned an unsupported error representation');
    seen.add(current);
    if (localErrors.has(current)) return current as XsuaaResourceMismatchError;
    const code = Object.getOwnPropertyDescriptor(current, 'code');
    if (code && Object.hasOwn(code, 'value') && code.value === CODE) return new XsuaaResourceMismatchError();
    const cause = Object.getOwnPropertyDescriptor(current, 'cause');
    current = cause && Object.hasOwn(cause, 'value') ? cause.value : undefined;
  }
  return undefined;
}

/** Keep the comparison exact: a different path is a different MCP resource. */
export function validateExpectedResource(value: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError('expectedResource must be an absolute URL');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('expectedResource must be an absolute URL');
  }
  if (
    !['https:', 'http:'].includes(url.protocol) ||
    (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.href !== value
  ) {
    throw new TypeError('expectedResource must be a canonical HTTPS URL (or HTTP loopback) without query or fragment');
  }
  return value;
}

export function hasResourceAudience(payload: Record<string, unknown>, expectedResource: string): boolean {
  if (!Object.hasOwn(payload, 'aud')) return false;
  const audience = payload.aud;
  if (typeof audience === 'string') return audience === expectedResource;
  return (
    Array.isArray(audience) &&
    audience.every((value) => typeof value === 'string') &&
    audience.includes(expectedResource)
  );
}
