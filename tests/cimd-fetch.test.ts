/**
 * SSRF-hardened CIMD document fetcher (T1).
 *
 * ── How this is tested, and why it is split ──
 * A local test server necessarily listens on 127.0.0.1, which the fetcher is supposed to
 * refuse. So the suite is deliberately in two halves:
 *
 *  1. **Policy** — `isBlockedAddress`, `validateClientIdUrl`, `hostAllowed`, and
 *     `fetchClientIdMetadataDocument`'s DNS/address gate, driven through the real entry
 *     point with `node:dns` mocked. This proves loopback and friends ARE refused.
 *  2. **Transport** — the response state machine (status, content type, compression,
 *     the streaming size cap, both deadlines, and the pin), driven through
 *     `performPinnedRequest` against a real local HTTP server with the request
 *     implementation injected.
 *
 * The injection is a test seam, not a bypass: `https:`-only lives in
 * `validateClientIdUrl` and the address gate lives in `fetchClientIdMetadataDocument`,
 * both of which are exercised in half 1 and neither of which the seam can reach past.
 *
 * The blocked-range vectors are shared with arc-1's `abapgit.test.ts`
 * (`getExternalInfo` unsafe-literal cases), so the two SSRF guards cannot drift apart.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';

const mockLookup = vi.hoisted(() => vi.fn());
vi.mock('node:dns', () => ({ lookup: mockLookup }));

const { fetchClientIdMetadataDocument, hostAllowed, isBlockedAddress, performPinnedRequest, validateClientIdUrl } =
  await import('../src/cimd-fetch.js');

type LookupEntry = { address: string; family: number };
type LookupCallback = (err: NodeJS.ErrnoException | null, addresses?: LookupEntry[]) => void;

/** Make the mocked `dns.lookup` answer with the given addresses. */
function resolvesTo(...addresses: LookupEntry[]): void {
  mockLookup.mockImplementation((_host: string, _opts: unknown, cb: LookupCallback) => {
    cb(null, addresses);
  });
}

describe('isBlockedAddress — RFC 6890 special-use ranges', () => {
  it('blocks every IPv4 special-use range', () => {
    const blocked = [
      '0.0.0.0',
      '10.0.0.1',
      '10.255.255.254',
      '100.64.0.1', // CGNAT
      '100.127.255.255',
      '127.0.0.1', // loopback
      '127.1.2.3',
      '169.254.1.1', // link-local
      '169.254.169.254', // the cloud metadata service
      '172.16.0.1', // private
      '172.31.255.254',
      '192.0.0.1', // IETF protocol assignments
      '192.0.2.5', // TEST-NET-1
      '192.88.99.1', // 6to4 relay anycast
      '192.168.1.1', // private
      '198.18.0.1', // benchmarking
      '198.51.100.7', // TEST-NET-2
      '203.0.113.9', // TEST-NET-3
      '224.0.0.1', // multicast
      '239.255.255.255',
      '240.0.0.1', // reserved
      '255.255.255.255', // broadcast
    ];
    for (const ip of blocked) expect(isBlockedAddress(ip), ip).toBe(true);
  });

  it('allows ordinary public IPv4', () => {
    for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '172.15.0.1', '172.32.0.1', '100.63.255.255']) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });

  it('blocks the IPv4 ranges immediately adjacent to allowed space (boundary check)', () => {
    // 172.16/12 spans 172.16 – 172.31 only; 100.64/10 spans 100.64 – 100.127 only.
    expect(isBlockedAddress('172.16.0.0')).toBe(true);
    expect(isBlockedAddress('172.31.255.255')).toBe(true);
    expect(isBlockedAddress('100.64.0.0')).toBe(true);
    expect(isBlockedAddress('100.127.255.255')).toBe(true);
  });

  it('blocks every IPv6 special-use range', () => {
    const blocked = [
      '::', // unspecified
      '::1', // loopback
      'fe80::1', // link-local
      'febf::1',
      'fc00::1', // unique local
      'fd12:3456::1',
      'ff02::1', // multicast
      '2001:db8::1', // documentation
      '2002::1', // 6to4 (embeds v4)
      '2001::1', // Teredo (embeds v4)
      '2001:2::1', // benchmarking
      '100::1', // discard-only
    ];
    for (const ip of blocked) expect(isBlockedAddress(ip), ip).toBe(true);
  });

  it('blocks site-local and local-use NAT64 IPv6', () => {
    for (const address of ['fec0::1', '64:ff9b:1::a00:1']) expect(isBlockedAddress(address), address).toBe(true);
  });

  it('allows ordinary public IPv6', () => {
    for (const ip of ['2606:4700:4700::1111', '2a00:1450:4001:80e::200e', '2001:4860:4860::8888']) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });

  it('blocks IPv4-mapped IPv6 in BOTH textual forms', () => {
    // The WHATWG URL parser canonicalizes a dotted mapped literal into hex hextets, so a
    // guard that only knows one spelling is bypassable by writing the other.
    expect(isBlockedAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedAddress('::ffff:7f00:1')).toBe(true);
    expect(isBlockedAddress('::ffff:10.0.0.1')).toBe(true);
    expect(isBlockedAddress('::ffff:a00:1')).toBe(true);
    expect(isBlockedAddress('::ffff:169.254.169.254')).toBe(true);
    expect(isBlockedAddress('::ffff:a9fe:a9fe')).toBe(true);
    // A mapped PUBLIC address is still fine.
    expect(isBlockedAddress('::ffff:8.8.8.8')).toBe(false);
    expect(isBlockedAddress('::ffff:808:808')).toBe(false);
  });

  it('blocks v4-embedding transition prefixes that could tunnel inward', () => {
    expect(isBlockedAddress('64:ff9b::127.0.0.1')).toBe(true); // NAT64 → loopback
    expect(isBlockedAddress('64:ff9b::10.0.0.1')).toBe(true); // NAT64 → private
    expect(isBlockedAddress('2002:7f00:1::1')).toBe(true); // 6to4 wrapping 127.0.0.1
  });

  it('blocks anything that does not parse as an IP — unknown is not safe', () => {
    for (const bad of ['', 'not-an-ip', '999.1.1.1', '1.2.3', '010.0.0.1', '::gggg', '1:2:3:4:5:6:7:8:9']) {
      expect(isBlockedAddress(bad), bad).toBe(true);
    }
  });
});

describe('validateClientIdUrl — Client Identifier URL shape', () => {
  it('accepts a well-formed https URL with a path', () => {
    const result = validateClientIdUrl('https://client.example.com/mcp/metadata.json');
    expect(result.ok).toBe(true);
  });

  it('refuses a client_id URL longer than 2048 characters', () => {
    const result = validateClientIdUrl(`https://client.example.com/${'a'.repeat(2048)}`);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('shape');
  });

  it('refuses non-https schemes, including plain http', () => {
    for (const raw of ['http://client.example.com/m.json', 'ftp://x.example.com/m', 'file:///etc/passwd']) {
      const r = validateClientIdUrl(raw);
      expect(r.ok, raw).toBe(false);
      if (!r.ok) expect(['scheme', 'shape']).toContain(r.reason);
    }
    // http is specifically a scheme refusal, not a generic shape one.
    const http = validateClientIdUrl('http://client.example.com/m.json');
    expect(http.ok).toBe(false);
    if (!http.ok) expect(http.reason).toBe('scheme');
  });

  it('refuses userinfo', () => {
    const r = validateClientIdUrl('https://user:secret@client.example.com/m.json');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('userinfo');
  });

  it('refuses a fragment, a missing path, and dot segments', () => {
    for (const raw of [
      'https://client.example.com/m.json#frag',
      'https://client.example.com',
      'https://client.example.com/',
      'https://client.example.com/a/../../etc/passwd',
      'https://client.example.com/./m.json',
      'https://client.example.com/..',
      // Percent-encoded spellings — the parser resolves the plain form away, so a check
      // against the parsed path would miss both of these.
      'https://client.example.com/a/%2e%2e/b.json',
      'https://client.example.com/a/%2E./b.json',
    ]) {
      const r = validateClientIdUrl(raw);
      expect(r.ok, raw).toBe(false);
      if (!r.ok) expect(r.reason, raw).toBe('shape');
    }
  });

  it('refuses internal-only hostnames before any DNS is attempted', () => {
    for (const raw of [
      'https://localhost/m.json',
      'https://localhost./m.json',
      'https://foo.localhost/m.json',
      'https://foo.localhost./m.json',
      'https://svc.internal/m.json',
      'https://printer.local/m.json',
      'https://api.svc.cluster.local/m.json',
    ]) {
      const r = validateClientIdUrl(raw);
      expect(r.ok, raw).toBe(false);
      if (!r.ok) expect(r.reason, raw).toBe('blocked_host');
    }
  });

  it('refuses an IP-literal target in a special-use range, before any lookup', () => {
    for (const raw of [
      'https://127.0.0.1/m.json',
      'https://[::1]/m.json',
      'https://[::ffff:127.0.0.1]/m.json',
      'https://169.254.169.254/latest/meta-data',
      'https://10.0.0.1/m.json',
      'https://[fd00::1]/m.json',
    ]) {
      const r = validateClientIdUrl(raw);
      expect(r.ok, raw).toBe(false);
      if (!r.ok) expect(r.reason, raw).toBe('blocked_host');
    }
  });

  it('applies the host allowlist when one is configured', () => {
    const list = ['claude.ai', '*.vscode.dev'];
    expect(validateClientIdUrl('https://claude.ai/m.json', list).ok).toBe(true);
    expect(validateClientIdUrl('https://a.vscode.dev/m.json', list).ok).toBe(true);
    const denied = validateClientIdUrl('https://evil.example.com/m.json', list);
    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.reason).toBe('host_not_allowed');
  });
});

describe('hostAllowed', () => {
  it('treats an empty or omitted list as open', () => {
    expect(hostAllowed('anything.example.com')).toBe(true);
    expect(hostAllowed('anything.example.com', [])).toBe(true);
  });

  it('matches exact hosts case-insensitively and ignores the root label', () => {
    expect(hostAllowed('claude.ai', ['claude.ai'])).toBe(true);
    expect(hostAllowed('CLAUDE.AI', ['claude.ai'])).toBe(true);
    expect(hostAllowed('claude.ai.', ['claude.ai'])).toBe(true);
  });

  it('never matches on a substring — the classic allowlist bypass', () => {
    expect(hostAllowed('evil-claude.ai', ['claude.ai'])).toBe(false);
    expect(hostAllowed('claude.ai.evil.com', ['claude.ai'])).toBe(false);
    expect(hostAllowed('notclaude.ai', ['claude.ai'])).toBe(false);
  });

  it('expands a wildcard by exactly one label', () => {
    expect(hostAllowed('a.vscode.dev', ['*.vscode.dev'])).toBe(true);
    expect(hostAllowed('a.b.vscode.dev', ['*.vscode.dev'])).toBe(false); // two labels
    expect(hostAllowed('vscode.dev', ['*.vscode.dev'])).toBe(false); // bare apex
    expect(hostAllowed('evilvscode.dev', ['*.vscode.dev'])).toBe(false);
  });
});

describe('fetchClientIdMetadataDocument — DNS and address policy', () => {
  afterEach(() => {
    mockLookup.mockReset();
  });

  it('refuses a loopback target end to end, without resolving', async () => {
    const result = await fetchClientIdMetadataDocument('https://localhost/m.json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('blocked_host');
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('refuses when a host allowlist excludes the target, with zero DNS traffic', async () => {
    const result = await fetchClientIdMetadataDocument('https://evil.example.com/m.json', {
      allowedHosts: ['claude.ai'],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('host_not_allowed');
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it('refuses a name that resolves into a special-use range', async () => {
    resolvesTo({ address: '169.254.169.254', family: 4 });
    const result = await fetchClientIdMetadataDocument('https://metadata.example.com/m.json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('blocked_address');
  });

  it('refuses a DNS-rebinding answer that mixes a public and a private address', async () => {
    // The defence is "refuse if ANY answer is blocked", not "pick an acceptable one" —
    // cherry-picking would reward the attack.
    resolvesTo({ address: '93.184.216.34', family: 4 }, { address: '127.0.0.1', family: 4 });
    const result = await fetchClientIdMetadataDocument('https://rebind.example.com/m.json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('blocked_address');
  });

  it('refuses a mapped-IPv6 private answer', async () => {
    resolvesTo({ address: '::ffff:10.0.0.5', family: 6 });
    const result = await fetchClientIdMetadataDocument('https://mapped.example.com/m.json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('blocked_address');
  });

  it('reports a resolution failure as dns_failure', async () => {
    mockLookup.mockImplementation((_h: string, _o: unknown, cb: LookupCallback) => cb(new Error('ENOTFOUND')));
    const result = await fetchClientIdMetadataDocument('https://nope.example.com/m.json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('dns_failure');
  });

  it('reports an empty answer as dns_failure', async () => {
    resolvesTo();
    const result = await fetchClientIdMetadataDocument('https://empty.example.com/m.json');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('dns_failure');
  });

  it('never returns anything but a reason code on failure — no message, no address', async () => {
    resolvesTo({ address: '10.1.2.3', family: 4 });
    const result = await fetchClientIdMetadataDocument('https://internal.example.com/m.json');
    expect(result).toEqual({ ok: false, reason: 'blocked_address' });
    expect(Object.keys(result)).toEqual(['ok', 'reason']);
  });
});

// ─── Transport state machine ──────────────────────────────────────────

const LIMITS = { connectTimeoutMs: 2_000, globalTimeoutMs: 5_000, maxBytes: 5_120 };

let server: Server | undefined;

afterEach(async () => {
  if (server) {
    await new Promise<void>((r) => server?.close(() => r()));
    server = undefined;
  }
});

/** Start a local HTTP server and return the URL + pinned loopback address to dial it. */
async function startServer(
  handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void,
): Promise<{ url: URL; pinned: { address: string; family: number } }> {
  server = createServer(handler);
  await new Promise<void>((r) => server?.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as AddressInfo).port;
  return {
    // An `http:` dial target, because the injected `http.request` refuses `https:` URLs.
    // The scheme gate is not weakened by this: `https:`-only is enforced in
    // `validateClientIdUrl`, which this half never calls and which half 1 covers.
    url: new URL(`http://pinned.example.com:${port}/metadata.json`),
    pinned: { address: '127.0.0.1', family: 4 },
  };
}

/** Inject `http.request` so the state machine can be driven against the local server. */
const httpImpl = (await import('node:http')).request as unknown as Parameters<typeof performPinnedRequest>[3];

describe('performPinnedRequest — response handling', () => {
  it('returns the body and the cache headers on a clean 200', async () => {
    const { url, pinned } = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=600' });
      res.end('{"client_id":"x"}');
    });
    const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.body).toBe('{"client_id":"x"}');
      expect(result.cacheControl).toBe('max-age=600');
      expect(result.resolvedAddress).toBe('127.0.0.1');
    }
  });

  it('accepts an application/<sub>+json content type', async () => {
    const { url, pinned } = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/client-metadata+json; charset=utf-8' });
      res.end('{}');
    });
    const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
    expect(result.ok).toBe(true);
  });

  it('refuses a redirect instead of following it', async () => {
    // The classic SSRF bypass: a public URL that 302s to an internal address.
    const { url, pinned } = await startServer((_req, res) => {
      res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    });
    const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('redirect_refused');
  });

  it('refuses every status other than 200', async () => {
    for (const status of [201, 204, 400, 401, 403, 404, 500]) {
      const { url, pinned } = await startServer((_req, res) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end('{}');
      });
      const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
      expect(result.ok, `status ${status}`).toBe(false);
      if (!result.ok) expect(result.reason, `status ${status}`).toBe('bad_status');
      await new Promise<void>((r) => server?.close(() => r()));
      server = undefined;
    }
  });

  it('refuses a missing or non-JSON content type', async () => {
    for (const headers of [{}, { 'content-type': 'text/html' }, { 'content-type': 'application/xml' }]) {
      const { url, pinned } = await startServer((_req, res) => {
        res.writeHead(200, headers);
        res.end('{}');
      });
      const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe('bad_content_type');
      await new Promise<void>((r) => server?.close(() => r()));
      server = undefined;
    }
  });

  it('refuses a compressed response rather than risk a decompression bomb', async () => {
    const { url, pinned } = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' });
      res.end('{}');
    });
    const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('content_encoding_refused');
  });

  it('refuses an oversized body declared up front via Content-Length', async () => {
    const big = 'x'.repeat(10_000);
    const { url, pinned } = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(big.length) });
      res.end(big);
    });
    const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('too_large');
  });

  it('refuses an oversized body while streaming, even when Content-Length lies', async () => {
    // Chunked transfer with no declared length: only the streaming cap can catch this,
    // which is exactly why the cap must not be applied after buffering.
    const { url, pinned } = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      const chunk = 'x'.repeat(1_024);
      let sent = 0;
      const pump = (): void => {
        if (sent >= 64 * 1024) {
          res.end();
          return;
        }
        sent += chunk.length;
        if (res.write(chunk)) setImmediate(pump);
        else res.once('drain', pump);
      };
      pump();
    });
    const result = await performPinnedRequest(url, pinned, LIMITS, httpImpl);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('too_large');
  });

  it('gives up on a server that connects and then dribbles forever', async () => {
    const { url, pinned } = await startServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.write('{');
      // Never ends. The global deadline is the only thing that can stop this.
    });
    const result = await performPinnedRequest(url, pinned, { ...LIMITS, globalTimeoutMs: 250 }, httpImpl);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('timeout');
  });

  it('sends no credentials and asks for no compression', async () => {
    let seen: import('node:http').IncomingHttpHeaders | undefined;
    const { url, pinned } = await startServer((req, res) => {
      seen = req.headers;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
    await performPinnedRequest(url, pinned, LIMITS, httpImpl);
    expect(seen?.cookie).toBeUndefined();
    expect(seen?.authorization).toBeUndefined();
    expect(seen?.['proxy-authorization']).toBeUndefined();
    expect(seen?.['accept-encoding']).toBe('identity');
  });
});

describe('performPinnedRequest — the pin itself', () => {
  it('answers every lookup with the validated address, whatever hostname is asked for', async () => {
    // This is the DNS-rebinding defence: once validated, the stack never gets a second
    // resolution, so the answer cannot change between the check and the connect.
    let captured: import('node:https').RequestOptions | undefined;
    const capturingImpl = ((_url: URL, opts: import('node:https').RequestOptions) => {
      captured = opts;
      return { on: () => {}, end: () => {}, destroy: () => {} } as never;
    }) as unknown as Parameters<typeof performPinnedRequest>[3];

    const pending = performPinnedRequest(
      new URL('https://client.example.com/m.json'),
      { address: '93.184.216.34', family: 4 },
      { ...LIMITS, globalTimeoutMs: 60 },
      capturingImpl,
    );

    const lookup = captured?.lookup;
    expect(lookup).toBeTypeOf('function');

    // Classic callback form.
    const single = await new Promise<unknown[]>((r) => {
      lookup?.('totally-different.evil.com', {}, (...args: unknown[]) => r(args));
    });
    expect(single[1]).toBe('93.184.216.34');
    expect(single[2]).toBe(4);

    // `all: true` form, which some Node versions use internally.
    const all = await new Promise<unknown[]>((r) => {
      lookup?.('totally-different.evil.com', { all: true }, (...args: unknown[]) => r(args));
    });
    expect(all[1]).toEqual([{ address: '93.184.216.34', family: 4 }]);

    await pending; // settles via the global deadline
  });

  it('keeps SNI bound to the real hostname and disables socket reuse', async () => {
    let captured: import('node:https').RequestOptions | undefined;
    const capturingImpl = ((_url: URL, opts: import('node:https').RequestOptions) => {
      captured = opts;
      return { on: () => {}, end: () => {}, destroy: () => {} } as never;
    }) as unknown as Parameters<typeof performPinnedRequest>[3];

    const pending = performPinnedRequest(
      new URL('https://client.example.com/m.json'),
      { address: '93.184.216.34', family: 4 },
      { ...LIMITS, globalTimeoutMs: 60 },
      capturingImpl,
    );
    // Pinning changes which address is dialled, never whether the certificate must match.
    expect(captured?.servername).toBe('client.example.com');
    // A pooled keep-alive socket would outlive the validation that authorised it.
    expect(captured?.agent).toBe(false);
    await pending;
  });
});
