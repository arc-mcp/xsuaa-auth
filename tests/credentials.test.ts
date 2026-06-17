/**
 * Layer-0 config helpers (SPEC §6): loadXsuaaCredentials + resolveAppUrl.
 *
 * Both accept an explicit `env` arg, so the tests pass fixture env objects rather
 * than mutating `process.env`. The `resolveAppUrl` precedence cases are the package
 * analogue of arc-1's `getAppUrl` tests in `xsuaa.test.ts`.
 */

import { describe, expect, it } from 'vitest';
import { loadXsuaaCredentials, resolveAppUrl } from '../src/index.js';

function vcapWithXsuaa(creds: Record<string, unknown>): NodeJS.ProcessEnv {
  return {
    VCAP_SERVICES: JSON.stringify({ xsuaa: [{ name: 'arc1-xsuaa', credentials: creds }] }),
  } as NodeJS.ProcessEnv;
}

const FULL_CREDS = {
  url: 'https://sub.authentication.eu10.hana.ondemand.com',
  clientid: 'sb-arc1!t1',
  clientsecret: 'the-secret',
  xsappname: 'arc1!t1',
  uaadomain: 'authentication.eu10.hana.ondemand.com',
  verificationkey: '-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----',
};

describe('loadXsuaaCredentials', () => {
  it('parses a VCAP_SERVICES xsuaa binding into XsuaaCredentials', () => {
    const creds = loadXsuaaCredentials(vcapWithXsuaa(FULL_CREDS));
    expect(creds).toEqual({
      url: FULL_CREDS.url,
      clientid: FULL_CREDS.clientid,
      clientsecret: FULL_CREDS.clientsecret,
      xsappname: FULL_CREDS.xsappname,
      uaadomain: FULL_CREDS.uaadomain,
      verificationkey: FULL_CREDS.verificationkey,
    });
  });

  it('leaves verificationkey undefined when absent (it is optional)', () => {
    const { verificationkey, ...rest } = FULL_CREDS;
    void verificationkey;
    const creds = loadXsuaaCredentials(vcapWithXsuaa(rest));
    expect(creds.verificationkey).toBeUndefined();
    expect(creds.clientid).toBe(FULL_CREDS.clientid);
  });

  it('throws when VCAP_SERVICES is not set', () => {
    expect(() => loadXsuaaCredentials({} as NodeJS.ProcessEnv)).toThrow(/VCAP_SERVICES is not set/);
  });

  it('throws when VCAP_SERVICES is not valid JSON', () => {
    expect(() => loadXsuaaCredentials({ VCAP_SERVICES: 'not-json' } as NodeJS.ProcessEnv)).toThrow(/not valid JSON/);
  });

  it('throws when there is no xsuaa binding', () => {
    const env = {
      VCAP_SERVICES: JSON.stringify({ destination: [{ name: 'd', credentials: {} }] }),
    } as NodeJS.ProcessEnv;
    expect(() => loadXsuaaCredentials(env)).toThrow(/no `xsuaa` binding/);
  });

  it('throws listing the missing required field(s)', () => {
    const env = vcapWithXsuaa({ url: 'https://x', clientid: 'c' }); // missing clientsecret/xsappname/uaadomain
    expect(() => loadXsuaaCredentials(env)).toThrow(/missing required field\(s\): clientsecret, xsappname, uaadomain/);
  });

  it('treats an empty-string required field as missing', () => {
    const env = vcapWithXsuaa({ ...FULL_CREDS, clientsecret: '' });
    expect(() => loadXsuaaCredentials(env)).toThrow(/missing required field\(s\): clientsecret/);
  });
});

describe('resolveAppUrl', () => {
  it('prefers the publicUrlEnvVar override (stripping a trailing slash)', () => {
    const env = {
      ARC1_PUBLIC_URL: 'https://reverse-proxy.example.com/base/',
      VCAP_APPLICATION: JSON.stringify({ application_uris: ['route.cfapps.eu10.hana.ondemand.com'] }),
    } as NodeJS.ProcessEnv;
    expect(resolveAppUrl(env, { publicUrlEnvVar: 'ARC1_PUBLIC_URL' })).toBe('https://reverse-proxy.example.com/base');
  });

  it('ignores an empty/whitespace publicUrlEnvVar value and falls through to the VCAP route', () => {
    const env = {
      ARC1_PUBLIC_URL: '   ',
      VCAP_APPLICATION: JSON.stringify({ application_uris: ['route.cfapps.eu10.hana.ondemand.com'] }),
    } as NodeJS.ProcessEnv;
    expect(resolveAppUrl(env, { publicUrlEnvVar: 'ARC1_PUBLIC_URL' })).toBe(
      'https://route.cfapps.eu10.hana.ondemand.com',
    );
  });

  it('uses the first https URI from VCAP_APPLICATION.application_uris (adds https:// to a bare host)', () => {
    const env = {
      VCAP_APPLICATION: JSON.stringify({ application_uris: ['arc1-mcp-server.cfapps.us10-001.hana.ondemand.com'] }),
    } as NodeJS.ProcessEnv;
    expect(resolveAppUrl(env)).toBe('https://arc1-mcp-server.cfapps.us10-001.hana.ondemand.com');
  });

  it('falls back to the uris field when application_uris is absent', () => {
    const env = {
      VCAP_APPLICATION: JSON.stringify({ uris: ['my-app.cfapps.eu10.hana.ondemand.com'] }),
    } as NodeJS.ProcessEnv;
    expect(resolveAppUrl(env)).toBe('https://my-app.cfapps.eu10.hana.ondemand.com');
  });

  it('falls back to localhost:<port> when VCAP_APPLICATION is absent', () => {
    expect(resolveAppUrl({} as NodeJS.ProcessEnv, { port: 9090 })).toBe('http://localhost:9090');
  });

  it('falls back to localhost:8080 by default (no port option)', () => {
    expect(resolveAppUrl({} as NodeJS.ProcessEnv)).toBe('http://localhost:8080');
  });

  it('falls back to localhost when VCAP_APPLICATION is invalid JSON', () => {
    const env = { VCAP_APPLICATION: 'not-json' } as NodeJS.ProcessEnv;
    expect(resolveAppUrl(env, { port: 7070 })).toBe('http://localhost:7070');
  });
});
