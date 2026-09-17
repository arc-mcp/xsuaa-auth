import type { XsuaaUserAttributeStatus, XsuaaUserAttributeStatuses, XsuaaUserAttributes } from '../../src/index.js';
import { XsuaaUserTokenRequiredError } from '../../src/index.js';

export const rejectionCode: 'XSUAA_USER_TOKEN_REQUIRED' = new XsuaaUserTokenRequiredError().code;

// Consumers can build fixtures and accept sparse dictionary inputs without casts.
export const emptyValues: XsuaaUserAttributes = {};
export const literalValues: XsuaaUserAttributes = { target: ['A4H/100'] };
export const emptyStatuses: XsuaaUserAttributeStatuses = {};
export const literalStatuses: XsuaaUserAttributeStatuses = { target: 'valid' };
const dictionary: Readonly<Record<string, readonly string[] | undefined>> = { target: ['A4H/100'] };
export const dictionaryValues: XsuaaUserAttributes = dictionary;

// Iteration must retain the value type, without casts or accidentally widening to any.
export function iterateRecords(values: XsuaaUserAttributes, statuses: XsuaaUserAttributeStatuses) {
  const valueEntries: [string, readonly string[] | undefined][] = Object.entries(values);
  const valueList: (readonly string[] | undefined)[] = Object.values(values);
  const statusEntries: [string, XsuaaUserAttributeStatus | undefined][] = Object.entries(statuses);
  const statusList: (XsuaaUserAttributeStatus | undefined)[] = Object.values(statuses);
  for (const [, value] of Object.entries(values)) {
    value?.includes('grant');
    // @ts-expect-error iteration must not erase readonly arrays
    value?.push('grant');
    // @ts-expect-error iteration must not widen values to any
    const invalid: number = value;
    void invalid;
  }
  for (const status of Object.values(statuses)) {
    // @ts-expect-error statuses do not become arbitrary numbers or any
    const invalid: number = status;
    void invalid;
  }
  return { valueEntries, valueList, statusEntries, statusList };
}

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
