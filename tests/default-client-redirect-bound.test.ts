import { createHash } from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setupHttpAuth } from '../src/index.js';
import { consentFields, responseCookies } from './helpers/oauth-consent.js';
import { makeCapturingLogger } from './helpers/test-logger.js';

const credentials = {
  clientid: 'sb-redirect-bound!t1',
  clientsecret: 'synthetic-redirect-bound-test-secret',
  url: 'https://identity.example',
  xsappname: 'test!t1',
  uaadomain: 'identity.example',
};
const appUrl = 'https://proxy.example';
const redirectUri = 'https://tenant.hana.ondemand.com/cb?original=1';
const verifier = 'v'.repeat(64);

function buildApp() {
  const app = express();
  const logger = makeCapturingLogger();
  setupHttpAuth(app, { xsuaa: { credentials, appUrl } }, logger);
  return { app, logger };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('default-client redirect eviction through the facade', () => {
  it.each([
    { phase: 'before approval', method: 'GET', otherInstance: false },
    { phase: 'after approval', method: 'POST body', otherInstance: false },
    { phase: 'after approval', method: 'POST query', otherInstance: true },
  ])(
    'completes sign-in after eviction $phase via $method (other instance: $otherInstance)',
    async ({ phase, method, otherInstance }) => {
      const { app, logger } = buildApp();
      const exchange = vi.fn(async (_url: string, init: RequestInit) => {
        const fields = new URLSearchParams(init.body as string);
        expect(fields.get('code')).toBe('upstream-code');
        expect(fields.get('client_id')).toBe(credentials.clientid);
        expect(fields.get('client_secret')).toBe(credentials.clientsecret);
        expect(fields.get('code_verifier')).toBe(verifier);
        expect(fields.get('redirect_uri')).toBe(`${appUrl}/oauth/callback`);
        return Response.json({ access_token: 'synthetic-access' });
      });
      vi.stubGlobal('fetch', exchange);
      const page = await request(app)
        .get('/authorize')
        .query({
          client_id: credentials.clientid,
          redirect_uri: redirectUri,
          response_type: 'code',
          code_challenge: createHash('sha256').update(verifier).digest('base64url'),
          code_challenge_method: 'S256',
          state: 'original-client-state',
        });
      expect(page.status).toBe(200);
      const approve = () =>
        request(app)
          .post('/authorize')
          .set('Origin', appUrl)
          .set('Cookie', responseCookies(page))
          .type('form')
          .send({ ...consentFields(page.text), consent_action: 'approve' });
      const churn = async () => {
        // These invalid authorization attempts still reach the real registration
        // shim before the SDK rejects their missing OAuth fields.
        for (let index = 0; index < 64; index++) {
          const fields = {
            client_id: credentials.clientid,
            redirect_uri: `https://tenant.hana.ondemand.com/cb?slot=${index}`,
          };
          const response =
            method === 'GET'
              ? await request(app).get('/authorize').query(fields)
              : method === 'POST body'
                ? await request(app).post('/authorize').type('form').send(fields)
                : await request(app).post('/authorize').query(fields);
          expect(response.status).toBe(302);
          expect(new URL(response.headers.location).searchParams.get('error')).toBe('invalid_request');
        }
        expect(logger.audit).toEqual(
          expect.arrayContaining([expect.objectContaining({ event: 'oauth_redirect_uri_evicted', redirectUri })]),
        );
      };
      if (phase === 'before approval') await churn();
      const approved = await approve();
      expect(approved.status).toBe(302);
      const upstream = new URL(approved.headers.location);
      expect(upstream.origin).toBe(credentials.url);
      if (phase === 'after approval') await churn();
      expect(exchange).not.toHaveBeenCalled();

      const callbackApp = otherInstance ? buildApp().app : app;
      const callback = await request(callbackApp)
        .get('/oauth/callback')
        .set('Cookie', responseCookies(approved))
        .query({ state: upstream.searchParams.get('state'), code: 'upstream-code' });
      expect(callback.status).toBe(302);
      const target = new URL(callback.headers.location);
      expect(target.origin + target.pathname).toBe('https://tenant.hana.ondemand.com/cb');
      expect(target.searchParams.get('original')).toBe('1');
      expect(target.searchParams.get('state')).toBe('original-client-state');
      expect(target.searchParams.get('error')).toBeNull();
      expect(target.searchParams.get('code')).toMatch(/^mcp-code-/);
      const token = await request(callbackApp)
        .post('/token')
        .type('form')
        .send({
          client_id: credentials.clientid,
          client_secret: credentials.clientsecret,
          grant_type: 'authorization_code',
          redirect_uri: redirectUri,
          code: target.searchParams.get('code'),
          code_verifier: verifier,
        });
      expect(token.status).toBe(200);
      expect(token.body.access_token).toBe('synthetic-access');
      expect(exchange).toHaveBeenCalledTimes(1);
    },
  );
});
