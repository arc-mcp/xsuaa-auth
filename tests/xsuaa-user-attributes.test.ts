import { describe, expect, it, vi } from 'vitest';
import { extractXsuaaUserAttributes, validateUserAttributeNames } from '../src/xsuaa-user-attributes.js';
import { hasSupportedXsuaaUserPrincipal } from '../src/xsuaa-user-principal.js';

function extract(raw: unknown, names = ['target']) {
  return extractXsuaaUserAttributes({ getAttribute: () => raw }, names, true);
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

  it.each([undefined, null])('omits missing values %j', (raw) => {
    const info = extract(raw);
    expect(info.xsuaaUserAttributeStatus.target).toBe('missing');
    expect(info.xsuaaUserAttributes).not.toHaveProperty('target');
  });

  it.each([0, false, {}, ['one', 0], ['one', {}], '', ' ', ['one', '\t']])(
    'rejects invalid values %j without partly accepted arrays',
    (raw) => {
      const info = extract(raw);
      expect(info.xsuaaUserAttributeStatus.target).toBe('invalid');
      expect(info.xsuaaUserAttributes).not.toHaveProperty('target');
    },
  );

  it('does not read attributes on a machine or unknown principal', () => {
    const getAttribute = vi.fn(() => ['*']);
    const info = extractXsuaaUserAttributes({ getAttribute }, ['target', 'other'], false);
    expect(getAttribute).not.toHaveBeenCalled();
    expect(info.xsuaaUserAttributes).toEqual({});
    expect(info.xsuaaUserAttributeStatus).toEqual({ target: 'missing', other: 'missing' });
  });

  it('reads only allowlisted names', () => {
    const getAttribute = vi.fn(() => 'one');
    extractXsuaaUserAttributes({ getAttribute }, ['target'], true);
    expect(getAttribute.mock.calls).toEqual([['target']]);
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
    expect(extract('é'.repeat(513)).xsuaaUserAttributeStatus.target).toBe('limit_exceeded');
  });

  it('retains unrelated valid names after a per-name limit failure', () => {
    const info = extractXsuaaUserAttributes(
      { getAttribute: (name) => (name === 'bad' ? ['x'.repeat(1_025)] : ['one']) },
      ['bad', 'good'],
      true,
    );
    expect(info.xsuaaUserAttributeStatus).toEqual({ bad: 'limit_exceeded', good: 'valid' });
    expect(info.xsuaaUserAttributes).toEqual({ good: ['one'] });
  });

  it('accepts exactly 64 KiB combined before copying', () => {
    const info = extractXsuaaUserAttributes(
      { getAttribute: () => Array(32).fill('x'.repeat(1_024)) },
      ['one', 'two'],
      true,
    );
    expect(info.xsuaaUserAttributeStatus).toEqual({ one: 'valid', two: 'valid' });
  });

  it('rejects every requested name on aggregate overflow, independent of allowlist order', () => {
    const getAttribute = (name: string) => (name === 'missing' ? null : Array(33).fill('x'.repeat(1_024)));
    for (const names of [
      ['one', 'two', 'missing'],
      ['missing', 'two', 'one'],
    ]) {
      const info = extractXsuaaUserAttributes({ getAttribute }, names, true);
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
    expect(validateUserAttributeNames(Array.from({ length: 16 }, (_, i) => `a${i}`))).toHaveLength(16);
    expect(() => validateUserAttributeNames(Array.from({ length: 17 }, (_, i) => `a${i}`))).toThrow(TypeError);
    expect(() => validateUserAttributeNames('target' as unknown as string[])).toThrow(TypeError);
    expect(() => validateUserAttributeNames([42] as unknown as string[])).toThrow(TypeError);
  });
});

describe('verified user-principal classification', () => {
  const context = (
    grant: unknown,
    origin: unknown = 'ias',
    logon: unknown = 'alice',
    principal: unknown = `user/${origin}/${logon}`,
  ) => ({
    getGrantType: () => grant,
    getOrigin: () => origin,
    getLogonName: () => logon,
    getUserName: () => principal,
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
    [null, 'alice', 'user/ias/alice'],
    ['ias', '', 'user/ias/'],
    ['bad/origin', 'alice', 'user/bad/origin/alice'],
    ['ias', 'alice', 'client/sb-machine'],
    [42, 'alice', 'user/42/alice'],
    ['ias', [], 'user/ias/'],
  ])('rejects malformed or inconsistent SAP user evidence', (origin, logon, principal) => {
    expect(hasSupportedXsuaaUserPrincipal(context('authorization_code', origin, logon, principal))).toBe(false);
  });
});
