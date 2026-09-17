import express from 'express';
import request from 'supertest';
import { expect, vi } from 'vitest';
import { requireBearerAuth } from '../../src/internal/sdk.js';
import type { Verifier } from '../../src/types.js';

// Object rows prevent it.each from spreading malformed array values into test arguments.
export const malformedScopes = [
  { label: 'undefined', scopes: undefined },
  { label: 'null', scopes: null },
  { label: 'mixed array', scopes: ['read', undefined] },
  { label: 'sparse array', scopes: new Array(1) },
];

/** Exercise both the direct library result and the real middleware mapping. */
export async function expectMalformedVerifier(verify: Verifier, token: string): Promise<void> {
  await expect(verify(token)).rejects.toThrow('Verifier returned malformed AuthInfo');
  const reached = vi.fn();
  const app = express();
  app.get('/mcp', requireBearerAuth({ verifier: { verifyAccessToken: verify } }), (_req, res) => {
    reached();
    res.send('must not authenticate');
  });
  const response = await request(app).get('/mcp').set('Authorization', `Bearer ${token}`);
  expect(response.status, JSON.stringify(response.body)).toBe(500);
  expect(response.body.error).toBe('server_error');
  expect(reached).not.toHaveBeenCalled();
}
