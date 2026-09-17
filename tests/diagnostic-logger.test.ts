import { execFileSync } from 'node:child_process';
import { describe, expect, it, vi } from 'vitest';
import { diagnosticLogger } from '../src/internal/diagnostic-logger.js';
import { noopLogger } from '../src/logger.js';

describe('best-effort verifier diagnostics', () => {
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
      // Strip the actual two source modules in memory; no stale dist or generated src files.
      const script = `
        import { readFileSync } from 'node:fs';
        import { stripTypeScriptTypes } from 'node:module';
        import { runInNewContext } from 'node:vm';
        const url = source => 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
        const loggerUrl = url(stripTypeScriptTypes(readFileSync(${JSON.stringify(new URL('../src/logger.ts', import.meta.url).pathname)}, 'utf8')));
        const source = stripTypeScriptTypes(readFileSync(${JSON.stringify(new URL('../src/internal/diagnostic-logger.ts', import.meta.url).pathname)}, 'utf8'))
          .replace("'../logger.js'", JSON.stringify(loggerUrl));
        const { diagnosticLogger } = await import(url(source));
        const sinks = [
          () => Promise.reject(new Error('native rejection')),
          () => runInNewContext("Promise.reject(new Error('foreign rejection'))"),
          () => ({ then(_resolve, reject) { reject(new Error('thenable rejection')); } }),
          () => ({ get then() { throw new Error('then getter'); } }),
        ];
        for (const sink of sinks) diagnosticLogger({ ${level}: sink }).${level}('verification diagnostic');
        await new Promise(resolve => setTimeout(resolve, 20));
        process.stdout.write('survived');
      `;
      expect(
        execFileSync(process.execPath, ['--unhandled-rejections=strict', '--input-type=module', '--eval', script], {
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
