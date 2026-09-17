import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { diagnosticError, diagnosticLogger } from '../src/internal/diagnostic-logger.js';
import { noopLogger } from '../src/logger.js';

describe('best-effort verifier diagnostics', () => {
  let compiledDir: string;
  beforeAll(() => {
    // Compile the actual sources, not a reimplementation or stale dist. Encoded
    // path characters exercise the child import; no Node TS-stripping API needed.
    compiledDir = mkdtempSync(join(tmpdir(), 'xsuaa logger % ü '));
    const compiler = fileURLToPath(new URL('./bin/tsc', import.meta.resolve('typescript/package.json')));
    execFileSync(
      process.execPath,
      [
        compiler,
        '--ignoreConfig',
        '--module',
        'commonjs',
        '--target',
        'ES2023',
        '--types',
        'node',
        '--skipLibCheck',
        '--rootDir',
        fileURLToPath(new URL('../src/', import.meta.url)),
        '--outDir',
        compiledDir,
        fileURLToPath(new URL('../src/internal/diagnostic-logger.ts', import.meta.url)),
      ],
      { cwd: fileURLToPath(new URL('../', import.meta.url)), timeout: 20_000, stdio: 'pipe' },
    );
  }, 25_000);
  afterAll(() => {
    if (compiledDir) rmSync(compiledDir, { recursive: true, force: true });
  });
  it.each(['TimeoutError', 'AbortError'])('retains native %s messages', (name) => {
    expect(diagnosticError(new DOMException('operation interrupted', name))).toEqual({
      error: 'operation interrupted',
    });
  });

  it('does not execute arbitrary message getters or accept a spoofed DOMException', () => {
    const getter = vi.fn(() => {
      throw new Error('must not execute');
    });
    const error = Object.defineProperty(new Error(), 'message', { get: getter });
    expect(diagnosticError(error)).toEqual({ error: 'Unknown verifier error' });
    expect(diagnosticError(Object.create(DOMException.prototype))).toEqual({ error: 'Unknown verifier error' });
    expect(diagnosticError(new Proxy(new DOMException('private'), { get: getter }))).toEqual({
      error: 'Unknown verifier error',
    });
    expect(getter).not.toHaveBeenCalled();
  });
  it.each(['debug', 'info', 'warn'] as const)('preserves argument count and receiver for %s', (level) => {
    const method = vi.fn();
    const sink = { ...noopLogger, [level]: method };
    const logger = diagnosticLogger(sink);
    logger[level]('message only');
    logger[level]('with data', { count: 1 });
    expect(method.mock.calls).toEqual([['message only'], ['with data', { count: 1 }]]);
    expect(method.mock.contexts).toEqual([sink, sink]);
  });

  it.each(['debug', 'info', 'warn'] as const)(
    'absorbs rejected promises and thenables from %s without an unhandled rejection',
    (level) => {
      // Run outside Vitest's rejection handler with Node's explicit strict policy.
      const script = `
        const { runInNewContext } = require('node:vm');
        const { diagnosticLogger } = require(${JSON.stringify(join(compiledDir, 'internal/diagnostic-logger.js'))});
        const sinks = [
          () => Promise.reject(new Error('native rejection')),
          () => runInNewContext("Promise.reject(new Error('foreign rejection'))"),
          () => ({ then(_resolve, reject) { reject(new Error('thenable rejection')); } }),
          () => ({ get then() { throw new Error('then getter'); } }),
        ];
        for (const sink of sinks) diagnosticLogger({ ${level}: sink }).${level}('verification diagnostic');
        setTimeout(() => process.stdout.write('survived'), 20);
      `;
      expect(
        execFileSync(process.execPath, ['--unhandled-rejections=strict', '--eval', script], {
          encoding: 'utf8',
          timeout: 10_000,
          stdio: ['ignore', 'pipe', 'pipe'],
        }),
      ).toBe('survived');
    },
  );

  it('does not await a pending sink or intercept its audit hook', () => {
    const emitAudit = vi.fn(() => {
      throw new Error('audit delivery failure');
    });
    const sink = { ...noopLogger, debug: () => new Promise<void>(() => {}), emitAudit };
    expect(diagnosticLogger(sink).debug('message')).toBeUndefined();
    expect(() => sink.emitAudit()).toThrow('audit delivery failure');
  });
});
