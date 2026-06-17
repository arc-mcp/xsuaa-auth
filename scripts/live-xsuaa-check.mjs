// P7 live XSUAA check — validates the module's createXsuaaTokenVerifier against
// the real arc1-xsuaa-test service (live JWKS fetch + signature + audience).
// Reads creds from a temp service-key file; prints only non-secret results.
import { readFileSync } from 'node:fs';
import { createXsuaaTokenVerifier } from '../dist/index.js';

const raw = JSON.parse(readFileSync('/tmp/authmod-xsuaa-key.json', 'utf8'));
const c = raw.credentials || raw;

// 1) Mint a real token from the live XSUAA tenant (client-credentials grant).
const res = await fetch(`${c.url}/oauth/token`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${Buffer.from(`${c.clientid}:${c.clientsecret}`).toString('base64')}`,
  },
  body: 'grant_type=client_credentials',
});
if (!res.ok) {
  console.log('TOKEN MINT FAILED:', res.status, (await res.text()).slice(0, 200));
  process.exit(1);
}
const { access_token } = await res.json();
console.log('token minted: segments=', access_token.split('.').length, 'len=', access_token.length);

const verify = createXsuaaTokenVerifier(c);

// 2) Positive: a real, live-issued token must validate.
try {
  const info = await verify(access_token);
  console.log(
    'POSITIVE ✓ live token validated:',
    JSON.stringify({ clientId: info.clientId, scopes: info.scopes, expiresAt: info.expiresAt }),
  );
} catch (e) {
  console.log('POSITIVE ✗ live token REJECTED (unexpected):', e?.constructor?.name, e?.message);
  process.exit(2);
}

// 3) Negative: garbage must be rejected.
try {
  await verify('not.a.jwt');
  console.log('NEGATIVE ✗ garbage ACCEPTED (bug!)');
  process.exit(3);
} catch (e) {
  console.log('NEGATIVE ✓ garbage rejected:', e?.constructor?.name);
}

// 4) Tamper: flip the signature of the real token — must be rejected (proves sig check).
const tampered = `${access_token.slice(0, -4)}${access_token.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA'}`;
try {
  await verify(tampered);
  console.log('TAMPER ✗ tampered-signature ACCEPTED (bug!)');
  process.exit(4);
} catch (e) {
  console.log('TAMPER ✓ tampered signature rejected:', e?.constructor?.name);
}

console.log('\nLIVE XSUAA VALIDATION: all checks passed.');
