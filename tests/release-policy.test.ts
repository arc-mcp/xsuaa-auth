import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = join(import.meta.dirname, '..');
const selector = join(root, 'scripts/select-publish-tag.mjs');

function select(version: string, prerelease: boolean) {
  const directory = mkdtempSync(join(tmpdir(), 'xsuaa-release-'));
  try {
    writeFileSync(join(directory, 'package.json'), JSON.stringify({ version }));
    writeFileSync(join(directory, 'release-please-config.json'), JSON.stringify({ packages: { '.': { prerelease } } }));
    return spawnSync(process.execPath, [selector], { cwd: directory, encoding: 'utf8' });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe('beta publish gate', () => {
  it('configures release-please to produce beta versions', () => {
    const config = JSON.parse(readFileSync(join(root, 'release-please-config.json'), 'utf8'));
    expect(config.packages['.']).toMatchObject({
      prerelease: true,
      'prerelease-type': 'beta',
      versioning: 'prerelease',
    });
  });

  it('routes betas to next and refuses an unsuffixed version in beta mode', () => {
    expect(select('2.0.0-beta.0', true)).toMatchObject({ status: 0, stdout: 'next' });
    expect(select('2.0.0', true)).toMatchObject({ status: 1, stdout: '' });
  });

  it('allows an intentional stable release after prerelease mode is disabled', () => {
    expect(select('2.0.0', false)).toMatchObject({ status: 0, stdout: 'latest' });
  });
});
