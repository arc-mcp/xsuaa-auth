/** SPEC §8: only `src/internal/sdk.ts` may import an MCP SDK package (type imports included). */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';

it('imports MCP SDK packages only in src/internal/sdk.ts', () => {
  const offenders = readdirSync('src', { recursive: true, encoding: 'utf8' })
    .filter((file) => file.endsWith('.ts') && file !== join('internal', 'sdk.ts'))
    .filter((file) => /['"]@modelcontextprotocol\//.test(readFileSync(join('src', file), 'utf8')));
  expect(offenders).toEqual([]);
});
