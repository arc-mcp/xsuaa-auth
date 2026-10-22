import type { Response } from 'supertest';

export function consentFields(html: string): Record<string, string> {
  const entities: Record<string, string> = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'" };
  return Object.fromEntries(
    [...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)].map((match) => [
      match[1],
      (match[2] ?? '').replace(/&amp;|&lt;|&gt;|&quot;|&#39;/g, (entity) => entities[entity] ?? entity),
    ]),
  );
}

export function responseCookies(response: Response): string[] {
  const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
  return (cookies ?? [])
    .filter((cookie) => !cookie.includes('Expires=Thu, 01 Jan 1970'))
    .map((cookie) => cookie.split(';')[0] ?? '');
}
