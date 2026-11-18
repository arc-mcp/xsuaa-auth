import { readFileSync } from 'node:fs';

try {
  const version = JSON.parse(readFileSync('package.json', 'utf8')).version;
  const prerelease = JSON.parse(readFileSync('release-please-config.json', 'utf8')).packages?.['.']?.prerelease;
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error('Invalid package version for npm publish');
  }
  if (prerelease !== true && prerelease !== false) {
    throw new Error('Missing release-please prerelease setting');
  }
  if (prerelease && !version.includes('-')) {
    throw new Error('Refusing to publish an unsuffixed version while prerelease mode is enabled');
  }
  process.stdout.write(version.includes('-') ? 'next' : 'latest');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Invalid release configuration');
  process.exitCode = 1;
}
