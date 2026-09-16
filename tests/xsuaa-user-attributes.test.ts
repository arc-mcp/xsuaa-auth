import { describe, expect, it, vi } from 'vitest';
import { extractXsuaaUserAttributes, validateUserAttributeNames } from '../src/xsuaa-user-attributes.js';
import { hasSupportedXsuaaUserPrincipal } from '../src/xsuaa-user-principal.js';

const contextFor = (attributes: Record<string, unknown>) => ({
  token: { payload: { 'xs.user.attributes': attributes } },
});

function extract(raw: unknown, names = ['target']) {
  return extractXsuaaUserAttributes(contextFor(Object.fromEntries(names.map((name) => [name, raw]))), names, true);
}

describe('verified XSUAA user attribute extraction', () => {
  it.each([
    ['one', ['one']],
    [
      ['one', 'two'],
      ['one', 'two'],
    ],
    [[], []],
    [
      ['same', 'same'],
      ['same', 'same'],
    ],
  ])('normalizes %j without transforming or deduplicating values', (raw, expected) => {
    const info = extract(raw);
    expect(info.xsuaaUserAttributes.target).toEqual(expected);
    expect(info.xsuaaUserAttributeStatus.target).toBe('valid');
  });

  it.each([undefined, null, 0, false, ''])('preserves missing/falsy SDK compatibility for %j', (raw) => {
    const info = extract(raw);
    expect(info.xsuaaUserAttributeStatus.target).toBe('missing');
    expect(info.xsuaaUserAttributes).not.toHaveProperty('target');
  });

  it.each([{}, ['one', 0], ['one', {}], ' ', ['one', '\t']].map((raw) => ({ raw })))(
    'rejects invalid values $raw without partly accepted arrays',
    ({ raw }) => {
      const info = extract(raw);
      expect(info.xsuaaUserAttributeStatus.target).toBe('invalid');
      expect(info.xsuaaUserAttributes).not.toHaveProperty('target');
    },
  );

  it('does not read attributes on a machine or unknown principal', () => {
    const getPayload = vi.fn(() => ({ 'xs.user.attributes': { target: ['*'] } }));
    const info = extractXsuaaUserAttributes(
      {
        token: {
          get payload() {
            return getPayload();
          },
        },
      },
      ['target', 'other'],
      false,
    );
    expect(getPayload).not.toHaveBeenCalled();
    expect(info.xsuaaUserAttributes).toEqual({});
    expect(info.xsuaaUserAttributeStatus).toEqual({ target: 'missing', other: 'missing' });
  });

  it('reads only allowlisted names', () => {
    const unrelated = vi.fn(() => {
      throw new Error('unrequested attribute read');
    });
    const attributes = Object.defineProperty({ target: 'one' }, 'unrelated', { get: unrelated });
    expect(extractXsuaaUserAttributes(contextFor(attributes), ['target'], true).xsuaaUserAttributes.target).toEqual([
      'one',
    ]);
    expect(unrelated).not.toHaveBeenCalled();
  });

  it('copies and freezes the result, records and arrays', () => {
    const raw = ['one'];
    const info = extract(raw);
    raw.push('two');
    expect(info.xsuaaUserAttributes.target).toEqual(['one']);
    expect(Object.isFrozen(info)).toBe(true);
    expect(Object.isFrozen(info.xsuaaUserAttributes)).toBe(true);
    expect(Object.isFrozen(info.xsuaaUserAttributeStatus)).toBe(true);
    expect(Object.isFrozen(info.xsuaaUserAttributes.target)).toBe(true);
    expect(Object.getPrototypeOf(info.xsuaaUserAttributes)).toBe(null);
    expect(Object.getPrototypeOf(info.xsuaaUserAttributeStatus)).toBe(null);
  });

  it('caps raw entries before any deduplication, without traversing an oversized array', () => {
    const raw = Array(1_025).fill('same');
    Object.defineProperty(raw, '0', {
      get: () => {
        throw new Error('oversized array was traversed');
      },
    });
    const info = extract(raw);
    expect(info.xsuaaUserAttributeStatus.target).toBe('limit_exceeded');
    expect(info.xsuaaUserAttributes).toEqual({});
    expect(extract(Array(1_024).fill('same')).xsuaaUserAttributes.target).toHaveLength(1_024);
  });

  it('enforces UTF-8 byte lengths, not JS character counts', () => {
    expect(extract('é'.repeat(512)).xsuaaUserAttributeStatus.target).toBe('valid');
    expect(extract(`${'é'.repeat(512)}x`).xsuaaUserAttributeStatus.target).toBe('limit_exceeded');
    expect(extract('é'.repeat(513)).xsuaaUserAttributeStatus.target).toBe('limit_exceeded');
  });

  it('retains unrelated valid names after a per-name limit failure', () => {
    const info = extractXsuaaUserAttributes(
      contextFor({ bad: ['x'.repeat(1_025)], good: ['one'] }),
      ['bad', 'good'],
      true,
    );
    expect(info.xsuaaUserAttributeStatus).toEqual({ bad: 'limit_exceeded', good: 'valid' });
    expect(info.xsuaaUserAttributes).toEqual({ good: ['one'] });
  });

  it('accepts exactly 64 KiB combined before copying', () => {
    const info = extractXsuaaUserAttributes(
      contextFor({ one: Array(32).fill('x'.repeat(1_024)), two: Array(32).fill('x'.repeat(1_024)) }),
      ['one', 'two'],
      true,
    );
    expect(info.xsuaaUserAttributeStatus).toEqual({ one: 'valid', two: 'valid' });
    expect(info.xsuaaUserAttributes).toEqual({
      one: Array(32).fill('x'.repeat(1_024)),
      two: Array(32).fill('x'.repeat(1_024)),
    });
    expect(Object.isFrozen(info.xsuaaUserAttributes.one)).toBe(true);
    expect(Object.isFrozen(info.xsuaaUserAttributes.two)).toBe(true);
  });

  it.each([65_535, 65_536, 65_537])('pins the combined byte boundary at %i bytes', (bytes) => {
    const raw = [
      ...Array(Math.floor(bytes / 1_024)).fill('x'.repeat(1_024)),
      ...(bytes % 1_024 ? ['x'.repeat(bytes % 1_024)] : []),
    ];
    const info = extract(raw);
    expect(info.xsuaaUserAttributeStatus.target).toBe(bytes <= 65_536 ? 'valid' : 'limit_exceeded');
    expect(info.xsuaaUserAttributes).toEqual(bytes <= 65_536 ? { target: raw } : {});
  });

  it.each(['x'.repeat(65_537), [...Array(64).fill('x'.repeat(1_024)), false]].map((bad) => ({ bad })))(
    'does not charge rejected candidates to unrelated valid attributes',
    ({ bad }) => {
      for (const names of [
        ['bad', 'good'],
        ['good', 'bad'],
      ]) {
        const info = extractXsuaaUserAttributes(contextFor({ bad, good: ['one'] }), names, true);
        expect(info.xsuaaUserAttributes).toEqual({ good: ['one'] });
        expect(info.xsuaaUserAttributeStatus.good).toBe('valid');
      }
    },
  );

  it.each([1_023, 1_024, 1_025])('pins ASCII value-byte and raw-entry limits at %i', (size) => {
    const expected = size <= 1_024 ? 'valid' : 'limit_exceeded';
    expect(extract('x'.repeat(size)).xsuaaUserAttributeStatus.target).toBe(expected);
    expect(extract(Array(size).fill('x')).xsuaaUserAttributeStatus.target).toBe(expected);
  });

  it('rejects every requested name on aggregate overflow, independent of allowlist order', () => {
    const context = contextFor({ one: Array(33).fill('x'.repeat(1_024)), two: Array(33).fill('x'.repeat(1_024)) });
    for (const names of [
      ['one', 'two', 'missing'],
      ['missing', 'two', 'one'],
    ]) {
      const info = extractXsuaaUserAttributes(context, names, true);
      expect(info.xsuaaUserAttributes).toEqual({});
      expect(info.xsuaaUserAttributeStatus).toEqual({
        one: 'limit_exceeded',
        two: 'limit_exceeded',
        missing: 'limit_exceeded',
      });
    }
  });
});

describe('attribute-name allowlist validation', () => {
  it('omission stays omitted; copies, deduplicates and freezes configured names', () => {
    expect(validateUserAttributeNames(undefined)).toBeUndefined();
    const original = ['one', 'one', 'two'];
    const result = validateUserAttributeNames(original);
    original.push('three');
    expect(result).toEqual(['one', 'two']);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it.each([
    '__proto__',
    'constructor',
    'prototype',
    'toString',
    '__defineGetter__',
    '',
    ' ',
    'one two',
    'a'.repeat(65),
    'tärgét',
  ])('rejects reserved or invalid name %s', (name) => {
    expect(() => validateUserAttributeNames([name])).toThrow(TypeError);
  });

  it('caps distinct names and checks runtime option types', () => {
    expect(validateUserAttributeNames(['a'.repeat(64)])).toEqual(['a'.repeat(64)]);
    expect(validateUserAttributeNames(Array.from({ length: 16 }, (_, i) => `a${i}`))).toHaveLength(16);
    expect(() => validateUserAttributeNames(Array.from({ length: 17 }, (_, i) => `a${i}`))).toThrow(TypeError);
    expect(() => validateUserAttributeNames('target' as unknown as string[])).toThrow(TypeError);
    expect(() => validateUserAttributeNames([42] as unknown as string[])).toThrow(TypeError);
  });
});

describe('verified user-principal classification', () => {
  const context = (grant: unknown, origin: unknown = 'ias', logon: unknown = 'alice') => ({
    token: { payload: { grant_type: grant, origin, user_name: logon } },
    getGrantType: () => grant,
    getOrigin: () => origin,
    getLogonName: () => logon,
  });

  it.each(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'])(
    'accepts supported grant %s with SAP user evidence',
    (grant) => {
      expect(hasSupportedXsuaaUserPrincipal(context(grant))).toBe(true);
    },
  );

  it.each(['client_credentials', 'unknown', 'password', 'user_token', '', undefined, {}])(
    'rejects machine or unsupported grant %j',
    (grant) => {
      expect(hasSupportedXsuaaUserPrincipal(context(grant))).toBe(false);
    },
  );

  it.each([
    [null, 'alice'],
    ['ias', ''],
    ['bad/origin', 'alice'],
    [42, 'alice'],
    ['ias', []],
    [' ', 'alice'],
    ['ias', '\t'],
  ])('rejects malformed SAP user fields', (origin, logon) => {
    expect(hasSupportedXsuaaUserPrincipal(context('authorization_code', origin, logon))).toBe(false);
  });
});
