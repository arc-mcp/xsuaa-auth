/** A validated token does not carry a supported XSUAA user principal. */
export class XsuaaUserTokenRequiredError extends Error {
  readonly code = 'XSUAA_USER_TOKEN_REQUIRED';

  constructor() {
    super('A supported user principal is required');
    this.name = 'XsuaaUserTokenRequiredError';
  }
}

const USER_GRANTS = new Set(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);

interface VerifiedXsuaaContext {
  getGrantType(): unknown;
  getOrigin(): unknown;
  getLogonName(): unknown;
  getUserName(): unknown;
}

/**
 * Call only AFTER SAP validation. Grant type alone is insufficient; the SAP
 * context must also identify an origin-qualified user principal. Neither email
 * nor subject is proof of a user (machine tokens can contain both).
 *
 * Supported grant/claim combinations require live evidence before release. In
 * particular a refreshed token can retain its original authorization-code grant.
 */
export function hasSupportedXsuaaUserPrincipal(context: VerifiedXsuaaContext): boolean {
  const grant = context.getGrantType();
  if (typeof grant !== 'string' || !USER_GRANTS.has(grant)) return false;
  const origin = context.getOrigin();
  const logonName = context.getLogonName();
  if (typeof origin !== 'string' || !origin.trim() || origin.includes('/')) return false;
  if (typeof logonName !== 'string' || !logonName.trim()) return false;
  return context.getUserName() === `user/${origin}/${logonName}`;
}
