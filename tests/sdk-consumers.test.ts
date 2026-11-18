/**
 * The package carries its own copy of the SDK auth code (server-legacy), so it must
 * work behind an MCP server built on either SDK line. Each case mounts the bearer
 * middleware from `setupHttpAuth` in front of a real server of that line and checks
 * that the verified `AuthInfo` reaches the tool handler and a bad token gets a 401.
 */

import type { AddressInfo } from 'node:net';
import { StreamableHTTPClientTransport as ClientTransportV2, Client as ClientV2 } from '@modelcontextprotocol/client';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { Client as ClientV1 } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport as ClientTransportV1 } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Server as ServerV1 } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createMcpHandler, Server as ServerV2 } from '@modelcontextprotocol/server';
import express, { type RequestHandler } from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import { setupHttpAuth } from '../src/index.js';

const KEY = 'consumer-test-key';
const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  // Clients first: a v1 client holds an SSE stream open that would stall server.close().
  for (const close of closers.splice(0).reverse()) await close();
});

async function listen(mcp: RequestHandler): Promise<URL> {
  const app = express();
  const bearer = setupHttpAuth(app, { apiKeys: [{ key: KEY, scopes: ['read'] }], required: true });
  if (!bearer) throw new Error('auth not configured');
  app.all('/mcp', express.json(), bearer, mcp);
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
  closers.push(
    () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  );
  return new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`);
}

const whoami = (scopes: string[] | undefined) => ({ content: [{ type: 'text' as const, text: String(scopes) }] });
const requestInit = { headers: { authorization: `Bearer ${KEY}` } };

async function expectBadTokenRejected(url: URL) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { authorization: 'Bearer wrong', 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  expect(res.status).toBe(401);
  expect(res.headers.get('www-authenticate')).toContain('invalid_token');
}

describe('behind an MCP SDK v1 server', () => {
  it('passes AuthInfo to the handler and rejects a bad token with 401', async () => {
    const url = await listen(async (req, res) => {
      const server = new ServerV1({ name: 'v1', version: '0' }, { capabilities: { tools: {} } });
      server.setRequestHandler(CallToolRequestSchema, async (_request, extra) => whoami(extra.authInfo?.scopes));
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    });
    const client = new ClientV1({ name: 'test', version: '0' });
    await client.connect(new ClientTransportV1(url, { requestInit }));
    closers.push(() => client.close());
    expect(await client.callTool({ name: 'whoami' })).toMatchObject(whoami(['read']));
    await expectBadTokenRejected(url);
  });
});

describe('behind an MCP SDK v2 server', () => {
  it.each([
    ['legacy', '2025-11-25'],
    ['auto', '2026-07-28'],
  ] as const)('client mode %s negotiates %s and the handler sees AuthInfo', async (mode, version) => {
    const mcp = toNodeHandler(
      createMcpHandler(() => {
        const server = new ServerV2({ name: 'v2', version: '0' }, { capabilities: { tools: {} } });
        server.setRequestHandler('tools/call', async (_request, ctx) => whoami(ctx.http?.authInfo?.scopes));
        return server;
      }),
    );
    // express.json() drained the stream; hand the parsed body over explicitly.
    const url = await listen((req, res) => void mcp(req, res, req.body));
    const client = new ClientV2({ name: 'test', version: '0' }, { versionNegotiation: { mode } });
    await client.connect(new ClientTransportV2(url, { requestInit }));
    closers.push(() => client.close());
    expect(client.getNegotiatedProtocolVersion()).toBe(version);
    expect(await client.callTool({ name: 'whoami' })).toMatchObject(whoami(['read']));
    await expectBadTokenRejected(url);
  });
});
