import type { XsuaaUserAttributeStatuses, XsuaaUserAttributes } from '../../src/index.js';

// Compiled by npm run typecheck; never executed. An unused expect-error fails CI.
export function checkSparseReadonlyRecords(values: XsuaaUserAttributes, statuses: XsuaaUserAttributeStatuses) {
  // @ts-expect-error arbitrary keys may be absent
  values.unrequested.includes('grant');
  // @ts-expect-error status is absent for names outside the configured allowlist
  const alwaysPresent: string = statuses.unrequested;
  // @ts-expect-error null-prototype records do not expose Object methods
  // biome-ignore lint/suspicious/noPrototypeBuiltins: negative compile-time API contract
  values.hasOwnProperty('target');
  // @ts-expect-error the statuses record has no inherited methods either
  statuses.toString();
  // @ts-expect-error records cannot be changed
  values.target = ['grant'];
  // @ts-expect-error extracted arrays cannot be changed
  values.target?.push('grant');
  const present: boolean = values.target?.includes('grant') ?? false;
  const owns: boolean = Object.hasOwn(values, 'target');
  return { present, owns, alwaysPresent };
}
