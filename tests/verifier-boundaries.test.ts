import express from 'express';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import type { AuthInfo } from '../src/internal/sdk.js';
import { requireBearerAuth } from '../src/internal/sdk.js';
import { createChainedTokenVerifier } from '../src/verifiers.js';
import { XsuaaUserTokenRequiredError } from '../src/xsuaa-user-principal.js';

const accepted: AuthInfo = { token: 'token', clientId: 'first', scopes: ['read'] };

describe.each(['XSUAA', 'OIDC'])('verifier integration boundaries in %s slot', (slot) => {
  function chain(verifier: (token: string) => Promise<AuthInfo>) {
    const fallback = vi.fn().mockResolvedValue({ ...accepted, scopes: ['admin'] });
    return {
      fallback,
      verify: createChainedTokenVerifier(
        { apiKeys: [{ key: 'token', scopes: ['admin'] }] },
        slot === 'XSUAA' ? verifier : undefined,
        slot === 'OIDC' ? verifier : fallback,
      ),
    };
  }

  it('does not select fallback when optional diagnostic metadata throws', async () => {
    const result = {
      ...accepted,
      get extra(): Record<string, unknown> {
        throw new Error('optional metadata unavailable');
      },
    };
    const { verify, fallback } = chain(vi.fn().mockResolvedValue(result));
    expect(await verify('token')).toBe(result);
    expect(fallback).not.toHaveBeenCalled();
  });

  it.each([undefined, null, 'invalid', { ...accepted, scopes: undefined }, { ...accepted, scopes: [42] }])(
    'rejects malformed core AuthInfo terminally: %j',
    async (result) => {
      const { verify, fallback } = chain(vi.fn().mockResolvedValue(result));
      await expect(verify('token')).rejects.toThrow('Verifier returned malformed AuthInfo');
      expect(fallback).not.toHaveBeenCalled();
    },
  );

  it.each(['plain null-prototype', 'throwing message', 'proxy prototype'])(
    'preserves ordinary fallback without unsafe error coercion: %s',
    async (form) => {
      const trap = vi.fn(() => {
        throw new Error('must not execute');
      });
      const error =
        form === 'plain null-prototype'
          ? Object.create(null)
          : form === 'throwing message'
            ? Object.defineProperty(new Error(), 'message', { get: trap })
            : Object.create(new Proxy({}, { get: trap, getPrototypeOf: trap }));
      const { verify } = chain(vi.fn().mockRejectedValue(error));
      expect((await verify('token')).scopes).toEqual(['admin']);
      expect(trap).not.toHaveBeenCalled();
    },
  );

  it.each(['direct', 'cause', 'callable cause', 'fresh causes'])(
    'rejects an opaque Proxy error terminally without inspecting traps: %s',
    async (form) => {
      const trap = vi.fn(() => {
        throw new Error('proxy trap executed');
      });
      const revoked = Proxy.revocable(form === 'callable cause' ? () => {} : {}, {});
      revoked.revoke();
      let reads = 0;
      const freshCause = (): object =>
        new Proxy(
          {},
          {
            getOwnPropertyDescriptor: (_target, key) => {
              // Bound the pre-fix reproducer itself instead of hanging the test runner.
              reads++;
              if (reads > 4) throw new Error('unbounded cause traversal');
              if (key === 'cause') return { configurable: true, value: freshCause() };
              return undefined;
            },
            getPrototypeOf: trap,
          },
        );
      const proxy = form === 'fresh causes' ? freshCause() : revoked.proxy;
      const error = form === 'direct' ? proxy : new Error('wrapper', { cause: proxy });
      const { verify, fallback } = chain(vi.fn().mockRejectedValue(error));
      await expect(verify('token')).rejects.toThrow('Verifier returned an unsupported error representation');
      expect(fallback).not.toHaveBeenCalled();
      expect(trap).not.toHaveBeenCalled();
      expect(reads).toBe(0);
    },
  );

  it('normalizes own denial code without traversing a Proxy prototype', async () => {
    const trap = vi.fn(() => {
      throw new Error('prototype trap executed');
    });
    const error = Object.assign(Object.create(new Proxy({}, { getPrototypeOf: trap, get: trap })), {
      code: 'XSUAA_USER_TOKEN_REQUIRED',
    });
    const { verify, fallback } = chain(vi.fn().mockRejectedValue(error));
    await expect(verify('token')).rejects.toBeInstanceOf(XsuaaUserTokenRequiredError);
    expect(trap).not.toHaveBeenCalled();
    expect(fallback).not.toHaveBeenCalled();
  });

  it.each(['malformed result', 'opaque cause'])(
    'returns a controlled HTTP 500 for %s, never fallback access',
    async (form) => {
      const broken =
        form === 'malformed result'
          ? vi.fn().mockResolvedValue({ ...accepted, scopes: undefined, expiresAt: Date.now() / 1000 + 60 })
          : vi.fn().mockRejectedValue(new Error('private-provider-detail', { cause: new Proxy({}, {}) }));
      const { verify, fallback } = chain(broken);
      const app = express();
      app.get('/mcp', requireBearerAuth({ verifier: { verifyAccessToken: verify } }), (_req, res) =>
        res.json({ ok: true }),
      );
      const response = await request(app).get('/mcp').set('Authorization', 'Bearer token');
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('server_error');
      expect(JSON.stringify(response.body)).not.toContain('private-provider-detail');
      expect(fallback).not.toHaveBeenCalled();
    },
  );
});
