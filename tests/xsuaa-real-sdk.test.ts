/** Real SAP signature/expiry/audience validation; only remote JWKS retrieval is stubbed. */
import xssec from '@sap/xssec';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createXsuaaTokenVerifier, XsuaaUserTokenRequiredError } from '../src/index.js';
import { InvalidTokenError } from '../src/internal/sdk.js';

const CREDS = {
  clientid: 'sb-first-app!t123',
  clientsecret: 'test-only-secret',
  xsappname: 'first-app!t123',
  url: 'https://tenant.authentication.example.invalid',
  uaadomain: 'authentication.example.invalid',
};

describe('new verifier options with real @sap/xssec 4.x validation', () => {
  let key: CryptoKey;
  let unrelatedKey: CryptoKey;
  const fetchJwks = vi.spyOn(xssec.XsuaaService.prototype, 'fetchJwks');

  beforeAll(async () => {
    const pair = await generateKeyPair('RS256');
    key = pair.privateKey;
    unrelatedKey = (await generateKeyPair('RS256')).privateKey;
    const jwk = { ...(await exportJWK(pair.publicKey)), kid: 'pr677-verification-test', alg: 'RS256', use: 'sig' };
    fetchJwks.mockResolvedValue({ keys: [jwk] });
  });

  afterAll(() => fetchJwks.mockRestore());

  async function token(payload: Record<string, unknown> = {}, signingKey?: CryptoKey) {
    return new SignJWT({
      grant_type: 'authorization_code',
      origin: 'ias-test',
      user_name: 'test-user',
      user_id: 'synthetic-test-user-id',
      cid: CREDS.clientid,
      client_id: CREDS.clientid,
      zid: 'pr677-local-verification-zone',
      scope: [`${CREDS.xsappname}.read`],
      'xs.user.attributes': { arc1_targets: ['A4H/001'] },
      ...payload,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'pr677-verification-test' })
      .setIssuer(`${CREDS.url}/oauth/token`)
      .setAudience(CREDS.xsappname)
      .setIssuedAt()
      .setExpirationTime(typeof payload.exp === 'number' ? payload.exp : '5m')
      .sign(signingKey ?? key);
  }

  const verifier = () =>
    createXsuaaTokenVerifier(CREDS, { userAttributeNames: ['arc1_targets'], requireUserToken: true });

  it.each(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'])(
    'validates signed user fixture with %s grant',
    async (grant_type) => {
      const result = await verifier()(await token({ grant_type }));
      expect(result.scopes).toEqual(['read']);
      expect(result.extra?.xsuaaUserAttributes).toEqual({ arc1_targets: ['A4H/001'] });
      expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: 'valid' });
    },
  );

  it('uses the SDK verified ext_cxt accessor precedence', async () => {
    const result = await verifier()(await token({ ext_cxt: { 'xs.user.attributes': { arc1_targets: ['A4H/100'] } } }));
    expect(result.extra?.xsuaaUserAttributes).toEqual({ arc1_targets: ['A4H/100'] });
  });

  it('records missing for a falsy scalar collapsed by SAP getAttribute()', async () => {
    const result = await verifier()(await token({ 'xs.user.attributes': { arc1_targets: '' } }));
    expect(result.extra?.xsuaaUserAttributeStatus).toEqual({ arc1_targets: 'missing' });
  });

  it('rejects a wrong signature before reading its user grants', async () => {
    await expect(verifier()(await token({}, unrelatedKey))).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects an expired signed token before extracting attributes', async () => {
    await expect(verifier()(await token({ exp: Math.floor(Date.now() / 1_000) - 3_600 }))).rejects.toBeInstanceOf(
      InvalidTokenError,
    );
  });

  it('rejects a valid signed token issued only for another app', async () => {
    const other = { ...CREDS, clientid: 'sb-other-app!t456', xsappname: 'other-app!t456' };
    const otherVerifier = createXsuaaTokenVerifier(other, {
      userAttributeNames: ['arc1_targets'],
      requireUserToken: true,
    });
    await expect(otherVerifier(await token())).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('does not treat another app local scopes as this app scopes', async () => {
    const result = await verifier()(await token({ scope: ['other-app!t456.admin', 'other-app!t456.read'] }));
    expect(result.scopes).toEqual([]);
  });

  it('rejects a validated client-credentials token even with forged-looking user hints and admin', async () => {
    await expect(
      verifier()(
        await token({
          grant_type: 'client_credentials',
          scope: [`${CREDS.xsappname}.admin`],
          email: 'user@example.invalid',
        }),
      ),
    ).rejects.toBeInstanceOf(XsuaaUserTokenRequiredError);
  });

  it('rejects a validated unknown-grant token as a principal failure, not an invalid signature', async () => {
    await expect(verifier()(await token({ grant_type: 'unknown' }))).rejects.toBeInstanceOf(
      XsuaaUserTokenRequiredError,
    );
  });
});
