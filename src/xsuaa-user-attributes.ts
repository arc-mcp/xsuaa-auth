/** Bounded extraction from an already validated SAP XSUAA security context. */

export type XsuaaUserAttributeStatus = 'valid' | 'missing' | 'invalid' | 'limit_exceeded';
/** Sparse dictionaries have no Object.prototype methods. Use Object.hasOwn(). */
type NullPrototypeRecord<Value> = {
  [name: string]: Value | undefined;
  hasOwnProperty?: never;
  isPrototypeOf?: never;
  propertyIsEnumerable?: never;
  toLocaleString?: never;
  toString?: never;
  valueOf?: never;
  constructor?: never;
};
export type XsuaaUserAttributes = Readonly<NullPrototypeRecord<readonly string[]>>;
export type XsuaaUserAttributeStatuses = Readonly<NullPrototypeRecord<XsuaaUserAttributeStatus>>;

export interface XsuaaUserAttributeInfo {
  readonly xsuaaUserAttributes: XsuaaUserAttributes;
  readonly xsuaaUserAttributeStatus: XsuaaUserAttributeStatuses;
}

const MAX_ATTRIBUTE_NAMES = 16;
const MAX_VALUES_PER_ATTRIBUTE = 1_024;
const MAX_VALUE_BYTES = 1_024;
const MAX_TOTAL_BYTES = 64 * 1_024;
const RESERVED_NAMES = new Set(Object.getOwnPropertyNames(Object.prototype));
RESERVED_NAMES.add('prototype');

export function validateUserAttributeNames(names: readonly string[] | undefined): readonly string[] | undefined {
  if (names === undefined) return undefined;
  if (!Array.isArray(names)) throw new TypeError('userAttributeNames must be an array of attribute names');
  const unique = new Set<string>();
  for (const name of names) {
    if (typeof name !== 'string' || !/^[\x21-\x7e]{1,64}$/.test(name) || RESERVED_NAMES.has(name)) {
      throw new TypeError('userAttributeNames contains an invalid attribute name');
    }
    unique.add(name);
    if (unique.size > MAX_ATTRIBUTE_NAMES) throw new TypeError('userAttributeNames exceeds 16 distinct names');
  }
  return Object.freeze([...unique]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Read only own fields of the SDK-verified payload, never decode an unverified JWT. */
function verifiedAttributeContainer(payload: unknown): Record<string, unknown> | 'missing' | 'invalid' {
  if (!isRecord(payload)) return 'invalid';
  let raw: unknown;
  if (Object.hasOwn(payload, 'ext_cxt') && payload.ext_cxt != null) {
    if (!isRecord(payload.ext_cxt)) return 'invalid';
    if (Object.hasOwn(payload.ext_cxt, 'xs.user.attributes')) raw = payload.ext_cxt['xs.user.attributes'];
  }
  // Preserve the SDK's nullish ext_cxt precedence, without prototype lookup.
  if (raw == null && Object.hasOwn(payload, 'xs.user.attributes')) raw = payload['xs.user.attributes'];
  if (raw == null) return 'missing';
  return isRecord(raw) ? raw : 'invalid';
}

/**
 * Only call on a context returned by XsuaaService.createSecurityContext().
 * Oversized arrays are not traversed or copied. The aggregate byte budget applies
 * to bounded candidate values; a per-name rejected array is not extracted.
 */
export function extractXsuaaUserAttributes(
  context: { token: { payload: unknown } },
  names: readonly string[],
  isUserPrincipal: boolean,
): XsuaaUserAttributeInfo {
  const attributes: NullPrototypeRecord<readonly string[]> = Object.create(null);
  const statuses: NullPrototypeRecord<XsuaaUserAttributeStatus> = Object.create(null);
  const candidates = new Map<string, readonly string[]>();
  const container = isUserPrincipal ? verifiedAttributeContainer(context.token.payload) : 'missing';
  let totalBytes = 0;
  for (const name of names) {
    statuses[name] = 'missing';
    if (typeof container === 'string') {
      statuses[name] = container;
      continue;
    }
    // Keep SAP getAttribute()'s falsy-to-null compatibility, but only for own fields.
    const raw = Object.hasOwn(container, name) ? container[name] || null : undefined;
    if (raw == null) continue;
    const values: readonly unknown[] = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : [];
    if (typeof raw !== 'string' && !Array.isArray(raw)) {
      statuses[name] = 'invalid';
      continue;
    }
    if (values.length > MAX_VALUES_PER_ATTRIBUTE) {
      statuses[name] = 'limit_exceeded';
      continue;
    }
    let invalid = false;
    let tooLarge = false;
    let candidateBytes = 0;
    for (const value of values) {
      if (typeof value !== 'string') {
        invalid = true;
        continue;
      }
      const bytes = Buffer.byteLength(value, 'utf8');
      candidateBytes += bytes;
      if (bytes > MAX_VALUE_BYTES) tooLarge = true;
      if (value.trim().length === 0) invalid = true;
    }
    statuses[name] = tooLarge ? 'limit_exceeded' : invalid ? 'invalid' : 'valid';
    if (statuses[name] === 'valid') {
      totalBytes += candidateBytes;
      candidates.set(name, values as readonly string[]);
    }
  }

  if (totalBytes > MAX_TOTAL_BYTES) {
    // A global limit has one deterministic outcome, independent of name order.
    for (const name of names) statuses[name] = 'limit_exceeded';
  } else {
    for (const [name, values] of candidates) attributes[name] = Object.freeze([...values]);
  }
  return Object.freeze({
    xsuaaUserAttributes: Object.freeze(attributes),
    xsuaaUserAttributeStatus: Object.freeze(statuses),
  });
}
